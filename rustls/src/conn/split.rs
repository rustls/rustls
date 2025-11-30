//! A split reader-writer interface.
//!
//! This module offers an alternative API for TLS connections with completed
//! handshakes.  It separates the read and write halves of the connection into
//! [`Reader`] and [`Writer`] respectively.  These halves can be used fairly
//! independently, making it easier to pipeline and maximize throughput.

use std::{
    boxed::Box,
    io, mem,
    ops::Deref,
    sync::{Arc, Mutex},
    vec::Vec,
};

use crate::{
    CommonState, ConnectionCommon, Error,
    client::{ClientConnection, ClientConnectionData},
    common_state::State,
    conn::{
        ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX, ConnectionCore, InboundUnborrowedMessage,
        connection::PlaintextSink,
    },
    crypto::cipher::{Decrypted, InboundPlainMessage, OutboundChunks},
    enums::{ContentType, ProtocolVersion},
    error::{AlertDescription, PeerMisbehaved},
    msgs::deframer::{
        BufferProgress, DeframerIter, DeframerVecBuffer, Delocator, HandshakeDeframer, Locator,
    },
    vecbuf::ChunkVecBuffer,
};

//----------- split ----------------------------------------------------------

/// Split a [`ClientConnection`] into reader-writer halves.
///
/// # Panics
///
/// Panics if `conn.is_handshaking()`.
pub fn split_client(conn: ClientConnection) -> (ClientReader, ClientWriter) {
    assert!(
        !conn.is_handshaking(),
        "the connection must be post-handshake"
    );

    let ClientConnection { inner } = conn;
    let ConnectionCommon {
        core,
        deframer_buffer,
        sendable_plaintext,
    } = inner;
    let ConnectionCore {
        state,
        side: side_data,
        common_state,
        hs_deframer,
        seen_consecutive_empty_fragments,
    } = core;

    let state = Arc::new(Mutex::new(state));
    let common_state = Arc::new(Mutex::new(common_state));

    (
        ClientReader {
            state: state.clone(),
            common_state: common_state.clone(),

            side_data,
            deframer_buffer,
            hs_deframer,
            seen_consecutive_empty_fragments,
        },
        ClientWriter {
            state: state.clone(),
            common_state: common_state.clone(),

            sendable_plaintext,
        },
    )
}

//----------- Reader ---------------------------------------------------------

/// The reading half of a client-side TLS connection.
pub struct ClientReader {
    state: Arc<Mutex<Result<Box<dyn State<ClientConnectionData>>, Error>>>,
    common_state: Arc<Mutex<CommonState>>,

    /// Side-specific data about the connection.
    side_data: ClientConnectionData,

    /// A buffer of received TLS frames to coalesce.
    deframer_buffer: DeframerVecBuffer,

    /// De-framing state specific to handshake messages.
    hs_deframer: HandshakeDeframer,

    /// The number of consecutive empty fragments we've received.
    ///
    /// We limit consecutive empty fragments to avoid a route for the peer to
    /// send us significant but fruitless traffic.
    seen_consecutive_empty_fragments: u8,
}

impl ClientReader {
    /// A reader for plaintext data.
    pub fn reader(&mut self) -> PlaintextReader<'_> {
        PlaintextReader { reader: self }
    }

    /// Receive TLS messages from the network.
    pub fn recv_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<Received> {
        let mut state = self.state.lock().unwrap();
        let mut common_state = self.common_state.lock().unwrap();

        let mut total = 0;
        let mut eof = false;

        while !eof && common_state.wants_read() {
            match Self::read_tls(
                &mut common_state,
                &mut self.hs_deframer,
                &mut self.deframer_buffer,
                rd,
            ) {
                Ok(0) => eof = true,
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        break;
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }

            Self::process_new_packets(
                &mut state,
                &mut common_state,
                &mut self.side_data,
                &mut self.hs_deframer,
                &mut self.seen_consecutive_empty_fragments,
                &mut self.deframer_buffer,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }

        let writer_action = WriterAction {};

        Ok(Received {
            bytes_read: total,
            writer_action: Some(writer_action).filter(|a| !a.is_empty()),
        })
    }

    // ConnectionCommon::read_tls()
    fn read_tls(
        common_state: &mut CommonState,
        hs_deframer: &mut HandshakeDeframer,
        deframer_buffer: &mut DeframerVecBuffer,
        rd: &mut dyn io::Read,
    ) -> io::Result<usize> {
        if common_state
            .received_plaintext
            .is_full()
        {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if common_state.has_received_close_notify {
            return Ok(0);
        }

        let res = deframer_buffer.read(rd, hs_deframer.is_active());
        if let Ok(0) = res {
            common_state.has_seen_eof = true;
        }
        res
    }

    // ConnectionCore::process_new_packets()
    fn process_new_packets(
        state_: &mut Result<Box<dyn State<ClientConnectionData>>, Error>,
        common_state: &mut CommonState,
        side_data: &mut ClientConnectionData,
        hs_deframer: &mut HandshakeDeframer,
        seen_consecutive_empty_fragments: &mut u8,
        deframer_buffer: &mut DeframerVecBuffer,
    ) -> Result<(), Error> {
        let mut state = match mem::replace(state_, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                *state_ = Err(e.clone());
                return Err(e);
            }
        };

        // Should `InboundPlainMessage` resolve to plaintext application
        // data it will be allocated within `plaintext` and written to
        // `CommonState.received_plaintext` buffer.
        //
        // TODO `CommonState.received_plaintext` should be hoisted into
        // `ConnectionCommon`
        let mut plaintext = None;
        let mut buffer_progress = hs_deframer.progress();

        loop {
            let buffer = deframer_buffer.filled_mut();
            let locator = Locator::new(buffer);
            let res = Self::deframe(
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
                Some(&*state),
                buffer,
                &mut buffer_progress,
            );

            let opt_msg = match res {
                Ok(opt_msg) => opt_msg,
                Err(e) => {
                    *state_ = Err(e.clone());
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            };

            let Some(msg) = opt_msg else {
                break;
            };

            match common_state.process_main_protocol(
                msg,
                state,
                side_data,
                &locator,
                &mut plaintext,
                // Unused after handshake states.
                None,
            ) {
                Ok(new) => state = new,
                Err(e) => {
                    *state_ = Err(e.clone());
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            }

            if common_state.has_received_close_notify {
                // "Any data received after a closure alert has been received MUST be ignored."
                // -- <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
                // This is data that has already been accepted in `read_tls`.
                buffer_progress.add_discard(deframer_buffer.filled().len());
                break;
            }

            if let Some(payload) = plaintext.take() {
                let payload = payload.reborrow(&Delocator::new(buffer));
                common_state
                    .received_plaintext
                    .append(payload.into_vec());
            }

            deframer_buffer.discard(buffer_progress.take_discard());
        }

        deframer_buffer.discard(buffer_progress.take_discard());
        *state_ = Ok(state);
        Ok(())
    }

    // ConnectionCore::deframe()
    fn deframe<'b>(
        common_state: &mut CommonState,
        hs_deframer: &mut HandshakeDeframer,
        seen_consecutive_empty_fragments: &mut u8,
        state: Option<&dyn State<ClientConnectionData>>,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<InboundPlainMessage<'b>>, Error> {
        // before processing any more of `buffer`, return any extant messages from `hs_deframer`
        if hs_deframer.has_message_ready() {
            Ok(Self::take_handshake_message(
                hs_deframer,
                buffer,
                buffer_progress,
            ))
        } else {
            Self::process_more_input(
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
                state,
                buffer,
                buffer_progress,
            )
        }
    }

    // ConnectionCore::take_handshake_message()
    fn take_handshake_message<'b>(
        hs_deframer: &mut HandshakeDeframer,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Option<InboundPlainMessage<'b>> {
        hs_deframer
            .iter(buffer)
            .next()
            .map(|(message, discard)| {
                buffer_progress.add_discard(discard);
                message
            })
    }

    // ConnectionCore::process_more_input()
    fn process_more_input<'b>(
        common_state: &mut CommonState,
        hs_deframer: &mut HandshakeDeframer,
        seen_consecutive_empty_fragments: &mut u8,
        state: Option<&dyn State<ClientConnectionData>>,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<InboundPlainMessage<'b>>, Error> {
        let version_is_tls13 = matches!(
            common_state.negotiated_version,
            Some(ProtocolVersion::TLSv1_3)
        );

        let locator = Locator::new(buffer);

        loop {
            let mut iter = DeframerIter::new(&mut buffer[buffer_progress.processed()..]);

            let (message, processed) = loop {
                let message = match iter.next().transpose() {
                    Ok(Some(message)) => message,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(Self::handle_deframe_error(common_state, err, state)),
                };

                let allowed_plaintext = match message.typ {
                    // CCS messages are always plaintext.
                    ContentType::ChangeCipherSpec => true,
                    // Alerts are allowed to be plaintext if-and-only-if:
                    // * The negotiated protocol version is TLS 1.3. - In TLS 1.2 it is unambiguous when
                    //   keying changes based on the CCS message. Only TLS 1.3 requires these heuristics.
                    // * We have not yet decrypted any messages from the peer - if we have we don't
                    //   expect any plaintext.
                    // * The payload size is indicative of a plaintext alert message.
                    ContentType::Alert
                        if version_is_tls13
                            && !common_state
                                .record_layer
                                .has_decrypted()
                            && message.payload.len() <= 2 =>
                    {
                        true
                    }
                    // In other circumstances, we expect all messages to be encrypted.
                    _ => false,
                };

                if allowed_plaintext && !hs_deframer.is_active() {
                    break (message.into_plain_message(), iter.bytes_consumed());
                }

                let message = match common_state
                    .record_layer
                    .decrypt_incoming(message)
                {
                    // failed decryption during trial decryption is not allowed to be
                    // interleaved with partial handshake data.
                    Ok(None) if hs_deframer.aligned().is_none() => {
                        return Err(
                            PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage.into(),
                        );
                    }

                    // failed decryption during trial decryption.
                    Ok(None) => continue,

                    Ok(Some(message)) => message,

                    Err(err) => return Err(Self::handle_deframe_error(common_state, err, state)),
                };

                let Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                } = message;

                if want_close_before_decrypt {
                    common_state.send_close_notify();
                }

                break (plaintext, iter.bytes_consumed());
            };

            if hs_deframer.aligned().is_none() && message.typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage.into());
            }

            match message.payload.len() {
                0 => {
                    if *seen_consecutive_empty_fragments == ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX
                    {
                        return Err(PeerMisbehaved::TooManyEmptyFragments.into());
                    }
                    *seen_consecutive_empty_fragments += 1;
                }
                _ => {
                    *seen_consecutive_empty_fragments = 0;
                }
            };

            buffer_progress.add_processed(processed);

            // do an end-run around the borrow checker, converting `message` (containing
            // a borrowed slice) to an unborrowed one (containing a `Range` into the
            // same buffer).  the reborrow happens inside the branch that returns the
            // message.
            //
            // is fixed by -Zpolonius
            // https://github.com/rust-lang/rfcs/blob/master/text/2094-nll.md#problem-case-3-conditional-control-flow-across-functions
            let unborrowed = InboundUnborrowedMessage::unborrow(&locator, message);

            if unborrowed.typ != ContentType::Handshake {
                let message = unborrowed.reborrow(&Delocator::new(buffer));
                buffer_progress.add_discard(processed);
                return Ok(Some(message));
            }

            let message = unborrowed.reborrow(&Delocator::new(buffer));
            hs_deframer.input_message(message, &locator, buffer_progress.processed());
            hs_deframer.coalesce(buffer)?;

            common_state.aligned_handshake = hs_deframer.aligned();

            if hs_deframer.has_message_ready() {
                // trial decryption finishes with the first handshake message after it started.
                common_state
                    .record_layer
                    .finish_trial_decryption();

                return Ok(Self::take_handshake_message(
                    hs_deframer,
                    buffer,
                    buffer_progress,
                ));
            }
        }
    }

    // ConnectionCore::handle_deframe_error()
    fn handle_deframe_error(
        common_state: &mut CommonState,
        error: Error,
        state: Option<&dyn State<ClientConnectionData>>,
    ) -> Error {
        match error {
            error @ Error::InvalidMessage(_) => {
                if common_state.is_quic() {
                    common_state.quic.alert = Some(AlertDescription::DecodeError);
                    error
                } else {
                    common_state.send_fatal_alert(AlertDescription::DecodeError, error)
                }
            }
            Error::PeerSentOversizedRecord => {
                common_state.send_fatal_alert(AlertDescription::RecordOverflow, error)
            }
            Error::DecryptError => {
                if let Some(state) = state {
                    state.handle_decrypt_error();
                }
                common_state.send_fatal_alert(AlertDescription::BadRecordMac, error)
            }

            error => error,
        }
    }
}

/// The output of [`Reader::recv_tls()`].
pub struct Received {
    /// The number of bytes read.
    pub bytes_read: usize,

    /// An action the writer should take, if any.
    pub writer_action: Option<WriterAction>,
}

/// A reader of plaintext data from a [`ClientReader`].
pub struct PlaintextReader<'a> {
    /// The underlying reader.
    reader: &'a mut ClientReader,
}

impl io::Read for PlaintextReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut common_state = self.reader.common_state.lock().unwrap();
        let common = &mut *common_state;
        crate::Reader {
            received_plaintext: &mut common.received_plaintext,
            has_received_close_notify: common.has_received_close_notify,
            has_seen_eof: common.has_seen_eof,
        }
        .read(buf)
    }
}

//----------- Writer ---------------------------------------------------------

/// The writing half of a client-side TLS connection.
pub struct ClientWriter {
    state: Arc<Mutex<Result<Box<dyn State<ClientConnectionData>>, Error>>>,
    common_state: Arc<Mutex<CommonState>>,

    /// A buffer of plaintext to encrypt and send.
    sendable_plaintext: ChunkVecBuffer,
}

impl ClientWriter {
    /// A writer for plaintext data.
    pub fn writer(&mut self) -> PlaintextWriter<'_> {
        PlaintextWriter { writer: self }
    }

    /// Enact a [`WriterAction`] sent by the [`Reader`].
    pub fn enact(&mut self, action: WriterAction) {
        let WriterAction {} = action;
    }

    /// Send prepared TLS messages over the network.
    pub fn send_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        let mut common_state = self.common_state.lock().unwrap();
        let mut total = 0;
        while common_state.wants_write() {
            match common_state.sendable_tls.write_to(wr) {
                Ok(0) => return Ok(total),
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        return Ok(total);
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(total)
    }

    // ConnectionCore::maybe_refresh_traffic_keys()
    fn maybe_refresh_traffic_keys(
        state: &mut Result<Box<dyn State<ClientConnectionData>>, Error>,
        common_state: &mut CommonState,
    ) {
        if mem::take(&mut common_state.refresh_traffic_keys_pending) {
            if let Ok(state) = state {
                let _ = state.send_key_update_request(common_state);
            }
        }
    }
}

/// A writer of plaintext data into a [`ClientWriter`].
pub struct PlaintextWriter<'a> {
    /// The underlying writer.
    writer: &'a mut ClientWriter,
}

impl PlaintextSink for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.writer.state.lock().unwrap();
        let mut common_state = self.writer.common_state.lock().unwrap();
        let len = common_state.buffer_plaintext(buf.into(), &mut self.writer.sendable_plaintext);
        ClientWriter::maybe_refresh_traffic_keys(&mut state, &mut common_state);
        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let payload_owner: Vec<&[u8]>;
        let payload = match bufs.len() {
            0 => return Ok(0),
            1 => OutboundChunks::Single(bufs[0].deref()),
            _ => {
                payload_owner = bufs
                    .iter()
                    .map(|io_slice| io_slice.deref())
                    .collect();

                OutboundChunks::new(&payload_owner)
            }
        };

        let mut state = self.writer.state.lock().unwrap();
        let mut common_state = self.writer.common_state.lock().unwrap();
        let len = common_state.buffer_plaintext(payload, &mut self.writer.sendable_plaintext);
        ClientWriter::maybe_refresh_traffic_keys(&mut state, &mut common_state);
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        crate::Writer::new(self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        crate::Writer::new(self).flush()
    }
}

/// An action commanded by the [`Reader`].
pub struct WriterAction {}

impl WriterAction {
    /// Whether this action is a no-op.
    fn is_empty(&self) -> bool {
        matches!(self, Self {})
    }
}
