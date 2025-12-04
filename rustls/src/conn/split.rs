//! A split reader-writer interface.
//!
//! This module offers an alternative API for TLS connections with completed
//! handshakes.  It separates the read and write halves of the connection into
//! [`Reader`] and [`Writer`] respectively.  These halves can be used fairly
//! independently, making it easier to pipeline and maximize throughput.

use std::{
    io, mem,
    ops::Deref,
    sync::{Arc, Mutex},
    vec::Vec,
};

use crate::{
    CommonState, Connection, ConnectionCommon, Error, HandshakeKind, ServerConnection, Side,
    SupportedCipherSuite,
    check::{inappropriate_handshake_message, inappropriate_message},
    client::ClientConnection,
    common_state::{KxState, Limit, TemperCounters, TrafficState, UnborrowedPayload},
    conn::{ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX, ConnectionCore, InboundUnborrowedMessage},
    crypto::{
        Identity,
        cipher::{
            Decrypted, InboundPlainMessage, OutboundChunks, OutboundOpaqueMessage,
            OutboundPlainMessage, PlainMessage, PreEncryptAction, RecordLayer,
        },
        tls13::OkmBlock,
    },
    enums::{ContentType, HandshakeType, ProtocolVersion},
    error::{AlertDescription, InvalidMessage, PeerMisbehaved},
    msgs::{
        alert::AlertMessagePayload,
        deframer::{
            BufferProgress, DeframerIter, DeframerVecBuffer, Delocator, HandshakeAlignedProof,
            HandshakeDeframer, Locator,
        },
        enums::{AlertLevel, KeyUpdateRequest},
        fragmenter::MessageFragmenter,
        handshake::{HandshakeMessagePayload, HandshakePayload, ProtocolName},
        message::{Message, MessagePayload},
    },
    tls13::key_schedule::KeyScheduleSuite,
    vecbuf::ChunkVecBuffer,
};

//----------- split ----------------------------------------------------------

/// Split a [`Connection`] into reader-writer halves.
///
/// # Errors
///
/// Fails if `conn.is_handshaking()` or if it is a QUIC connection.
pub fn split(conn: impl Into<Connection>) -> Result<(Reader, Writer), Error> {
    // Destructure the state into a type-independent thing.
    let (
        state,
        common_state,
        hs_deframer,
        seen_consecutive_empty_fragments,
        deframer_buffer,
        sendable_plaintext,
    ) = match conn.into() {
        Connection::Client(ClientConnection { inner }) => {
            let ConnectionCommon {
                core,
                deframer_buffer,
                sendable_plaintext,
            } = inner;
            let ConnectionCore {
                state,
                side: _,
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
            } = core;

            (
                state?.into_traffic()?,
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
                deframer_buffer,
                sendable_plaintext,
            )
        }

        Connection::Server(ServerConnection { inner }) => {
            let ConnectionCommon {
                core,
                deframer_buffer,
                sendable_plaintext,
            } = inner;
            let ConnectionCore {
                state,
                side: _,
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
            } = core;

            (
                state?.into_traffic()?,
                common_state,
                hs_deframer,
                seen_consecutive_empty_fragments,
                deframer_buffer,
                sendable_plaintext,
            )
        }
    };

    let CommonState {
        negotiated_version,
        handshake_kind,
        side,
        record_layer,
        suite,
        kx_state: KxState::Complete(_),
        alpn_protocol,
        exporter: _,
        early_exporter: _,
        aligned_handshake,
        may_send_application_data: true,
        may_receive_application_data: true,
        early_traffic: false,
        sent_fatal_alert: false,
        has_sent_close_notify: false,
        has_received_close_notify: false,
        has_seen_eof: false,
        peer_identity,
        message_fragmenter,
        received_plaintext,
        sendable_tls,
        queued_key_update_message,
        // QUIC is not supported here
        protocol: _,
        quic: _,
        // TODO: No support for secret extraction
        enable_secret_extraction: _,
        temper_counters,
        refresh_traffic_keys_pending,
        // TODO: Expose FIPS support
        fips: _,
        // TODO: Support TLS 1.3 session tickets
        tls13_tickets_received: _,
    } = common_state
    else {
        panic!("unexpected state");
    };

    assert!(sendable_plaintext.is_empty());

    let info = Arc::new(ConnectionInfo {
        version: negotiated_version.unwrap(),
        handshake_kind: handshake_kind.unwrap(),
        side: side,
        suite: suite.unwrap(),
        _alpn_protocol: alpn_protocol,
        peer_identity: peer_identity.unwrap(),
    });
    let [encryption_secret, decryption_secret] = match state {
        TrafficState::Tls12 => {
            assert!(!info.is_tls13());
            [None, None]
        }
        TrafficState::Tls13 {
            decryption_secret: server_traffic_secret,
            encryption_secret: client_traffic_secret,
        } => {
            assert!(info.is_tls13());
            match info.side {
                Side::Client => [client_traffic_secret, server_traffic_secret],
                Side::Server => [server_traffic_secret, client_traffic_secret],
            }
            .map(Some)
        }
    };
    let record_layer = Arc::new(Mutex::new(record_layer));

    Ok((
        Reader {
            info: info.clone(),
            record_layer: record_layer.clone(),

            has_seen_eof: false,
            buffered_error: None,
            deframer_buffer,
            hs_deframer,
            aligned_handshake,
            decryption_secret,
            temper_counters,
            seen_consecutive_empty_fragments,
            has_received_close_notify: false,
            received_plaintext,
        },
        Writer {
            info: info.clone(),
            record_layer: record_layer.clone(),

            sendable_tls,
            refresh_traffic_keys_pending,
            queued_key_update_message,
            encryption_secret,
            message_fragmenter,
            enqueued_fatal_error: false,
        },
    ))
}

/// Immutable information about a connection.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConnectionInfo {
    /// The TLS protocol version in use.
    pub version: ProtocolVersion,

    /// Which kind of handshake was performed.
    ///
    /// Relevant for resumptions.
    pub handshake_kind: HandshakeKind,

    /// Which side of the connection this is.
    pub side: Side,

    /// The cipher suite in use.
    pub suite: SupportedCipherSuite,

    /// The negotiated ALPN protocol, if any.
    _alpn_protocol: Option<ProtocolName>,

    /// The identity of the peer.
    pub peer_identity: Identity<'static>,
}

impl ConnectionInfo {
    /// Whether this is a TLS 1.3 connection.
    const fn is_tls13(&self) -> bool {
        matches!(self.version, ProtocolVersion::TLSv1_3)
    }
}

//----------- Reader ---------------------------------------------------------

/// The reading half of a client-side TLS connection.
pub struct Reader {
    /// Immutable information about the connection.
    info: Arc<ConnectionInfo>,

    record_layer: Arc<Mutex<RecordLayer>>,

    /// Whether the underlying transport has reported EOF.
    has_seen_eof: bool,

    /// A buffered TLS error, if any.
    ///
    /// If a TLS error occurs, it is buffered here, and an appropriate writer
    /// action is returned to the caller.  The error is returned in the next
    /// invocation (and all subsequent ones).  This prevents the caller from
    /// forgetting about the writer action in the failing case.
    buffered_error: Option<Error>,

    /// A buffer of received TLS frames to coalesce.
    deframer_buffer: DeframerVecBuffer,

    /// De-framing state specific to handshake messages.
    hs_deframer: HandshakeDeframer,

    /// Whether `hs_deframer` is aligned on handshake messages.
    aligned_handshake: Option<HandshakeAlignedProof>,

    /// The secret from which decryption keys are derived.
    ///
    /// Only available in TLS 1.3 connections, as it can change over time.
    decryption_secret: Option<OkmBlock>,

    /// Counters for tracking peer misbehavior.
    temper_counters: TemperCounters,

    /// The number of consecutive empty fragments we've received.
    ///
    /// We limit consecutive empty fragments to avoid a route for the peer to
    /// send us significant but fruitless traffic.
    seen_consecutive_empty_fragments: u8,

    /// Whether the peer has closed their half of the connection.
    has_received_close_notify: bool,

    /// A buffer of received plaintext.
    received_plaintext: ChunkVecBuffer,
}

impl Reader {
    /// Information about the connection.
    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    /// A reader for plaintext data.
    pub fn reader(&mut self) -> PlaintextReader<'_> {
        PlaintextReader { reader: self }
    }

    /// Receive TLS messages from the network.
    pub fn recv_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<Received> {
        if let Some(error) = &self.buffered_error {
            // We have a buffered TLS error.  Any associated writer action has
            // already been sent out, so we can now show the real error.  This
            // also fuses the reader.
            return Err(io::Error::new(io::ErrorKind::InvalidData, error.clone()));
        }

        let mut record_layer = self.record_layer.lock().unwrap();
        let mut writer_action = None;

        let mut total = 0;
        let mut eof = false;

        while !eof && self.received_plaintext.is_empty() && !self.has_received_close_notify {
            match Self::read_tls(
                &mut self.has_seen_eof,
                &mut self.hs_deframer,
                &mut self.deframer_buffer,
                &mut self.has_received_close_notify,
                &mut self.received_plaintext,
                rd,
            ) {
                Ok(0) => eof = true,
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        break;
                    } else {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                }

                Err(err) => return Err(err),
            }

            match Self::process_new_packets(
                &self.info,
                &mut record_layer,
                &mut writer_action,
                &mut self.hs_deframer,
                &mut self.aligned_handshake,
                &mut self.decryption_secret,
                &mut self.temper_counters,
                &mut self.seen_consecutive_empty_fragments,
                &mut self.has_received_close_notify,
                &mut self.received_plaintext,
                &mut self.deframer_buffer,
            ) {
                Ok(()) => {}
                Err(err) => {
                    // Buffer the error and stop.
                    self.buffered_error = Some(err);
                    break;
                }
            }

            // Stop if we have a writer action.
            if let Some(writer_action) = writer_action.take() {
                return Ok(Received::WriterAction(writer_action));
            }
        }

        if let Some(error) = &self.buffered_error {
            // There was no writer action; show the error immediately.
            Err(io::Error::new(io::ErrorKind::InvalidData, error.clone()))
        } else if let Some(writer_action) = writer_action {
            Ok(Received::WriterAction(writer_action))
        } else {
            Ok(Received::Read(self.received_plaintext.len()))
        }
    }

    // ConnectionCommon::read_tls()
    fn read_tls(
        has_seen_eof: &mut bool,
        hs_deframer: &mut HandshakeDeframer,
        deframer_buffer: &mut DeframerVecBuffer,
        has_received_close_notify: &bool,
        received_plaintext: &mut ChunkVecBuffer,
        rd: &mut dyn io::Read,
    ) -> io::Result<usize> {
        if received_plaintext.is_full() {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if *has_received_close_notify {
            return Ok(0);
        }

        let res = deframer_buffer.read(rd, hs_deframer.is_active());
        if let Ok(0) = res {
            *has_seen_eof = true;
        }
        res
    }

    // ConnectionCore::process_new_packets()
    fn process_new_packets(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        writer_action: &mut Option<WriterAction>,
        hs_deframer: &mut HandshakeDeframer,
        aligned_handshake: &mut Option<HandshakeAlignedProof>,
        decryption_secret: &mut Option<OkmBlock>,
        temper_counters: &mut TemperCounters,
        seen_consecutive_empty_fragments: &mut u8,
        has_received_close_notify: &mut bool,
        received_plaintext: &mut ChunkVecBuffer,
        deframer_buffer: &mut DeframerVecBuffer,
    ) -> Result<(), Error> {
        // Should `InboundPlainMessage` resolve to plaintext application
        // data it will be allocated within `plaintext` and written to
        // `CommonState.received_plaintext` buffer.
        let mut buffer_progress = hs_deframer.progress();

        loop {
            let buffer = deframer_buffer.filled_mut();
            let locator = Locator::new(buffer);
            let res = Self::deframe(
                info,
                record_layer,
                writer_action,
                hs_deframer,
                aligned_handshake,
                seen_consecutive_empty_fragments,
                buffer,
                &mut buffer_progress,
            );

            let opt_msg = match res {
                Ok(opt_msg) => opt_msg,
                Err(e) => {
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            };

            let Some(msg) = opt_msg else {
                break;
            };

            let plaintext = match Self::process_main_protocol(
                info,
                record_layer,
                aligned_handshake,
                decryption_secret,
                temper_counters,
                has_received_close_notify,
                writer_action,
                msg,
                &locator,
            ) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            };

            if *has_received_close_notify {
                // "Any data received after a closure alert has been received MUST be ignored."
                // -- <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
                // This is data that has already been accepted in `read_tls`.
                buffer_progress.add_discard(deframer_buffer.filled().len());
                break;
            }

            if let Some(payload) = plaintext {
                let payload = payload.reborrow(&Delocator::new(buffer));
                received_plaintext.append(payload.into_vec());
            }

            deframer_buffer.discard(buffer_progress.take_discard());

            if writer_action.is_some() {
                // We have a writer action; stop immediately.
                return Ok(());
            }
        }

        deframer_buffer.discard(buffer_progress.take_discard());
        Ok(())
    }

    // ConnectionCore::deframe()
    fn deframe<'b>(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        writer_action: &mut Option<WriterAction>,
        hs_deframer: &mut HandshakeDeframer,
        aligned_handshake: &mut Option<HandshakeAlignedProof>,
        seen_consecutive_empty_fragments: &mut u8,
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
                info,
                record_layer,
                writer_action,
                hs_deframer,
                aligned_handshake,
                seen_consecutive_empty_fragments,
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
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        writer_action: &mut Option<WriterAction>,
        hs_deframer: &mut HandshakeDeframer,
        aligned_handshake: &mut Option<HandshakeAlignedProof>,
        seen_consecutive_empty_fragments: &mut u8,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<InboundPlainMessage<'b>>, Error> {
        let locator = Locator::new(buffer);

        loop {
            let mut iter = DeframerIter::new(&mut buffer[buffer_progress.processed()..]);

            let (message, processed) = loop {
                let message = match iter.next().transpose() {
                    Ok(Some(message)) => message,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(Self::handle_deframe_error(writer_action, err)),
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
                        if info.is_tls13()
                            && !record_layer.has_decrypted()
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

                let message = match record_layer.decrypt_incoming(message) {
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

                    Err(err) => return Err(Self::handle_deframe_error(writer_action, err)),
                };

                let Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                } = message;

                if want_close_before_decrypt {
                    // The peer should have rotated their keys (or closed the
                    // connection) by now, but they're still going.  We'll try
                    // to stop them by closing our end of the connection.
                    debug_assert!(writer_action.is_none());
                    *writer_action = Some(WriterAction(WriterActionImpl::EnqueueAlert(
                        AlertLevel::Warning,
                        AlertDescription::CloseNotify,
                    )));
                    return Err(Error::DecryptError);
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

            *aligned_handshake = hs_deframer.aligned();

            if hs_deframer.has_message_ready() {
                // trial decryption finishes with the first handshake message after it started.
                record_layer.finish_trial_decryption();

                return Ok(Self::take_handshake_message(
                    hs_deframer,
                    buffer,
                    buffer_progress,
                ));
            }
        }
    }

    // ConnectionCore::handle_deframe_error()
    fn handle_deframe_error(writer_action: &mut Option<WriterAction>, error: Error) -> Error {
        match error {
            error @ Error::InvalidMessage(_) => {
                Self::send_fatal_alert(writer_action, AlertDescription::DecodeError, error)
            }
            Error::PeerSentOversizedRecord => {
                Self::send_fatal_alert(writer_action, AlertDescription::RecordOverflow, error)
            }
            Error::DecryptError => {
                Self::send_fatal_alert(writer_action, AlertDescription::BadRecordMac, error)
            }

            error => error,
        }
    }

    // CommonState::process_main_protocol()
    fn process_main_protocol(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        aligned_handshake: &mut Option<HandshakeAlignedProof>,
        decryption_secret: &mut Option<OkmBlock>,
        temper_counters: &mut TemperCounters,
        has_received_close_notify: &mut bool,
        writer_action: &mut Option<WriterAction>,
        msg: InboundPlainMessage<'_>,
        plaintext_locator: &Locator,
    ) -> Result<Option<UnborrowedPayload>, Error> {
        // Now we can fully parse the message payload.
        let msg = match Message::try_from(msg) {
            Ok(msg) => msg,
            Err(err) => {
                return Err(Self::send_fatal_alert(
                    writer_action,
                    AlertDescription::from(err),
                    err,
                ));
            }
        };

        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if !info.is_tls13() {
            let reject_ty = match info.side {
                Side::Client => HandshakeType::HelloRequest,
                Side::Server => HandshakeType::ClientHello,
            };

            if msg.handshake_type() == Some(reject_ty) {
                temper_counters.received_renegotiation_request()?;
                debug_assert!(writer_action.is_none());
                *writer_action = Some(WriterAction(WriterActionImpl::EnqueueAlert(
                    AlertLevel::Warning,
                    AlertDescription::NoRenegotiation,
                )));
                return Ok(None);
            }
        }

        let result = match msg.payload {
            MessagePayload::ApplicationData(payload) => {
                temper_counters.received_app_data();
                Ok(Some(UnborrowedPayload::unborrow(
                    plaintext_locator,
                    payload,
                )))
            }

            // For alerts, we have separate logic.
            MessagePayload::Alert(alert) => Self::process_alert(
                info,
                temper_counters,
                has_received_close_notify,
                writer_action,
                &alert,
            )
            .map(|()| None),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(_)),
                ..
            } if info.is_tls13() && info.side == Side::Client => {
                // TODO: Restore support for session tickets
                Ok(None)
            }

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(key_update)),
                ..
            } if info.is_tls13() => Self::handle_key_update(
                info,
                record_layer,
                aligned_handshake,
                decryption_secret,
                temper_counters,
                writer_action,
                key_update,
            )
            .map(|()| None),

            other => Err(match (info.is_tls13(), info.side) {
                (false, _) => inappropriate_message(&other, &[ContentType::ApplicationData]),

                (true, Side::Client) => inappropriate_handshake_message(
                    &other,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
                ),

                (true, Side::Server) => inappropriate_handshake_message(
                    &other,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::KeyUpdate],
                ),
            }),
        };

        match result {
            Ok(received_plaintext) => Ok(received_plaintext),
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => Err(Self::send_fatal_alert(
                writer_action,
                AlertDescription::UnexpectedMessage,
                e,
            )),
            Err(e) => Err(e),
        }
    }

    // CommonState::process_alert()
    fn process_alert(
        info: &ConnectionInfo,
        temper_counters: &mut TemperCounters,
        has_received_close_notify: &mut bool,
        writer_action: &mut Option<WriterAction>,
        alert: &AlertMessagePayload,
    ) -> Result<(), Error> {
        // Reject unknown AlertLevels.
        if let AlertLevel::Unknown(_) = alert.level {
            return Err(Self::send_fatal_alert(
                writer_action,
                AlertDescription::IllegalParameter,
                Error::AlertReceived(alert.description),
            ));
        }

        // If we get a CloseNotify, make a note to declare EOF to our
        // caller.  But do not treat unauthenticated alerts like this.
        if alert.description == AlertDescription::CloseNotify {
            *has_received_close_notify = true;
            return Ok(());
        }

        // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
        // (except, for no good reason, user_cancelled).
        let err = Error::AlertReceived(alert.description);
        if alert.level == AlertLevel::Warning {
            temper_counters.received_warning_alert()?;
            if info.is_tls13() && alert.description != AlertDescription::UserCanceled {
                return Err(Self::send_fatal_alert(
                    writer_action,
                    AlertDescription::DecodeError,
                    err,
                ));
            }

            // Some implementations send pointless `user_canceled` alerts, don't log them
            // in release mode (https://bugs.openjdk.org/browse/JDK-8323517).
            if alert.description != AlertDescription::UserCanceled || cfg!(debug_assertions) {
                log::warn!("TLS alert warning received: {alert:?}");
            }

            return Ok(());
        }

        Err(err)
    }

    fn handle_key_update(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        aligned_handshake: &mut Option<HandshakeAlignedProof>,
        decryption_secret: &mut Option<OkmBlock>,
        temper_counters: &mut TemperCounters,
        writer_action: &mut Option<WriterAction>,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        temper_counters.received_key_update_request()?;

        // Figure out whether we should update our own side.
        match request {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                // Set the writer action.
                debug_assert!(writer_action.is_none());
                *writer_action = Some(WriterAction(WriterActionImpl::UpdateSendingKeys));
            }
            KeyUpdateRequest::Unknown(_) => {
                return Err(Self::send_fatal_alert(
                    writer_action,
                    AlertDescription::IllegalParameter,
                    InvalidMessage::InvalidKeyUpdate,
                ));
            }
        }

        let proof = aligned_handshake.ok_or_else(|| {
            Self::send_fatal_alert(
                writer_action,
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::KeyEpochWithPendingFragment,
            )
        })?;

        // Update our read-side keys.
        let SupportedCipherSuite::Tls13(suite) = info.suite else {
            unreachable!()
        };
        let decryption_secret = decryption_secret.as_mut().unwrap();
        let ks = KeyScheduleSuite::from(suite);
        *decryption_secret = ks.derive_next(&decryption_secret);
        record_layer.set_message_decrypter(ks.derive_decrypter(decryption_secret), &proof);

        Ok(())
    }

    // CommonState::send_fatal_alert()
    fn send_fatal_alert(
        writer_action: &mut Option<WriterAction>,
        desc: AlertDescription,
        err: impl Into<Error>,
    ) -> Error {
        debug_assert!(writer_action.is_none());
        *writer_action = Some(WriterAction(WriterActionImpl::EnqueueAlert(
            AlertLevel::Fatal,
            desc,
        )));
        err.into()
    }
}

/// The output of [`Reader::recv_tls()`].
#[must_use = "If there is a writer action, it must be enacted"]
pub enum Received {
    /// Data was read successfully.
    Read(usize),

    /// A writer action must be sent.
    WriterAction(WriterAction),
}

/// A reader of plaintext data from a [`ClientReader`].
pub struct PlaintextReader<'a> {
    /// The underlying reader.
    reader: &'a mut Reader,
}

impl io::Read for PlaintextReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        crate::Reader {
            received_plaintext: &mut self.reader.received_plaintext,
            has_received_close_notify: self.reader.has_received_close_notify,
            has_seen_eof: self.reader.has_seen_eof,
        }
        .read(buf)
    }
}

//----------- Writer ---------------------------------------------------------

/// The writing half of a client-side TLS connection.
pub struct Writer {
    /// Immutable information about the connection.
    info: Arc<ConnectionInfo>,

    record_layer: Arc<Mutex<RecordLayer>>,

    /// A buffer of TLS fragments ready to send.
    sendable_tls: ChunkVecBuffer,

    /// Whether the traffic keys need to be refreshed.
    refresh_traffic_keys_pending: bool,

    /// A queued key update message.
    queued_key_update_message: Option<Vec<u8>>,

    /// State for fragmenting messages.
    message_fragmenter: MessageFragmenter,

    /// The secret from which encryption keys are derived.
    ///
    /// Only available in TLS 1.3 connections, as it can change over time.
    encryption_secret: Option<OkmBlock>,

    /// An enqueued fatal alert to send.
    ///
    /// If this is `true`, then the appropriate alert has been enqueued.
    /// Any further enqueued application data should be ignored.
    enqueued_fatal_error: bool,
}

impl Writer {
    /// Information about the connection.
    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    /// A writer for plaintext data.
    pub fn writer(&mut self) -> PlaintextWriter<'_> {
        PlaintextWriter { writer: self }
    }

    /// Enact a [`WriterAction`] sent by the [`Reader`].
    pub fn enact(&mut self, action: WriterAction) {
        let WriterAction(action) = action;
        match action {
            WriterActionImpl::EnqueueAlert(level, desc) => {
                // Enqueue the alert.
                let msg = Message::build_alert(level, desc);
                let mut record_layer = self.record_layer.lock().unwrap();
                Self::send_msg_encrypt(
                    &self.info,
                    &mut record_layer,
                    &mut self.sendable_tls,
                    &mut self.queued_key_update_message,
                    &mut self.message_fragmenter,
                    &mut self.refresh_traffic_keys_pending,
                    msg.into(),
                );

                // Update internal state accordingly.
                if matches!(level, AlertLevel::Fatal)
                    || matches!(desc, AlertDescription::CloseNotify)
                {
                    self.enqueued_fatal_error = true;
                }
            }

            WriterActionImpl::UpdateSendingKeys => {
                let mut record_layer = self.record_layer.lock().unwrap();

                let SupportedCipherSuite::Tls13(suite) = self.info.suite else {
                    unreachable!()
                };
                let secret = self.encryption_secret.as_mut().unwrap();
                let ks = KeyScheduleSuite::from(suite);
                *secret = ks.derive_next(&secret);
                {
                    let message = PlainMessage::from(Message::build_key_update_notify());
                    self.queued_key_update_message = Some(
                        record_layer
                            .encrypt_outgoing(message.borrow_outbound())
                            .encode(),
                    );
                };
                record_layer.set_message_encrypter(
                    ks.derive_encrypter(&secret),
                    suite.common.confidentiality_limit,
                );
            }
        }
    }

    /// Send prepared TLS messages over the network.
    pub fn send_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        let mut total = 0;
        while !self.sendable_tls.is_empty() {
            match self.sendable_tls.write_to(wr) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
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
        info: &ConnectionInfo,
        encryption_secret: &mut Option<OkmBlock>,
        record_layer: &mut RecordLayer,
        sendable_tls: &mut ChunkVecBuffer,
        message_fragmenter: &mut MessageFragmenter,
        queued_key_update_message: &mut Option<Vec<u8>>,
        refresh_traffic_keys_pending: &mut bool,
    ) {
        if mem::take(refresh_traffic_keys_pending) {
            Self::send_msg_encrypt(
                info,
                record_layer,
                sendable_tls,
                queued_key_update_message,
                message_fragmenter,
                refresh_traffic_keys_pending,
                Message::build_key_update_request().into(),
            );

            let SupportedCipherSuite::Tls13(suite) = info.suite else {
                unreachable!()
            };
            let secret = encryption_secret.as_mut().unwrap();
            let ks = KeyScheduleSuite::from(suite);
            *secret = ks.derive_next(&secret);
            record_layer.set_message_encrypter(
                ks.derive_encrypter(&secret),
                suite.common.confidentiality_limit,
            );
        }
    }

    // CommonState::buffer_plaintext()
    fn buffer_plaintext(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        sendable_tls: &mut ChunkVecBuffer,
        queued_key_update_message: &mut Option<Vec<u8>>,
        refresh_traffic_keys_pending: &mut bool,
        message_fragmenter: &mut MessageFragmenter,
        payload: OutboundChunks<'_>,
    ) -> usize {
        Self::perhaps_write_key_update(sendable_tls, queued_key_update_message);
        Self::send_appdata_encrypt(
            info,
            record_layer,
            sendable_tls,
            message_fragmenter,
            queued_key_update_message,
            refresh_traffic_keys_pending,
            payload,
            Limit::Yes,
        )
    }

    // CommonState::perhaps_write_key_update()
    fn perhaps_write_key_update(
        sendable_tls: &mut ChunkVecBuffer,
        queued_key_update_message: &mut Option<Vec<u8>>,
    ) {
        if let Some(message) = queued_key_update_message.take() {
            sendable_tls.append(message);
        }
    }

    // CommonState::send_msg_encrypt()
    fn send_msg_encrypt(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        sendable_tls: &mut ChunkVecBuffer,
        queued_key_update_message: &mut Option<Vec<u8>>,
        message_fragmenter: &mut MessageFragmenter,
        refresh_traffic_keys_pending: &mut bool,
        m: PlainMessage,
    ) {
        let iter = message_fragmenter.fragment_message(&m);
        for m in iter {
            Self::send_single_fragment(
                info,
                record_layer,
                sendable_tls,
                message_fragmenter,
                queued_key_update_message,
                refresh_traffic_keys_pending,
                m,
            );
        }
    }

    // CommonState::send_appdata_encrypt()
    fn send_appdata_encrypt(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        sendable_tls: &mut ChunkVecBuffer,
        message_fragmenter: &mut MessageFragmenter,
        queued_key_update_message: &mut Option<Vec<u8>>,
        refresh_traffic_keys_pending: &mut bool,
        payload: OutboundChunks<'_>,
        limit: Limit,
    ) -> usize {
        if payload.is_empty() {
            // Don't send empty fragments.
            return 0;
        }

        // Here, the limit on sendable_tls applies to encrypted data,
        // but we're respecting it for plaintext data -- so we'll
        // be out by whatever the cipher+record overhead is.  That's a
        // constant and predictable amount, so it's not a terrible issue.
        let len = match limit {
            #[cfg(feature = "std")]
            Limit::Yes => sendable_tls.apply_limit(payload.len()),
            Limit::No => payload.len(),
        };

        let iter = message_fragmenter.fragment_payload(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload.split_at(len).0,
        );
        for m in iter {
            Self::send_single_fragment(
                info,
                record_layer,
                sendable_tls,
                message_fragmenter,
                queued_key_update_message,
                refresh_traffic_keys_pending,
                m,
            );
        }

        len
    }

    // CommonState::send_single_fragment()
    fn send_single_fragment(
        info: &ConnectionInfo,
        record_layer: &mut RecordLayer,
        sendable_tls: &mut ChunkVecBuffer,
        message_fragmenter: &mut MessageFragmenter,
        queued_key_update_message: &mut Option<Vec<u8>>,
        refresh_traffic_keys_pending: &mut bool,
        m: OutboundPlainMessage<'_>,
    ) {
        if m.typ == ContentType::Alert {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            let em = record_layer.encrypt_outgoing(m);
            Self::queue_tls_message(sendable_tls, queued_key_update_message, em);
            return;
        }

        match record_layer.next_pre_encrypt_action() {
            PreEncryptAction::Nothing => {}

            // Close connection once we start to run out of
            // sequence space.
            PreEncryptAction::RefreshOrClose => {
                match info.version {
                    ProtocolVersion::TLSv1_3 => {
                        // driven by caller, as we don't have the `State` here
                        *refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        log::error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        log::debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
                        let m = Message::build_alert(
                            AlertLevel::Warning,
                            AlertDescription::CloseNotify,
                        );
                        Self::send_msg_encrypt(
                            info,
                            record_layer,
                            sendable_tls,
                            queued_key_update_message,
                            message_fragmenter,
                            refresh_traffic_keys_pending,
                            m.into(),
                        );
                        return;
                    }
                }
            }

            // Refuse to wrap counter at all costs.  This
            // is basically untestable unfortunately.
            PreEncryptAction::Refuse => {
                return;
            }
        };

        let em = record_layer.encrypt_outgoing(m);
        Self::queue_tls_message(sendable_tls, queued_key_update_message, em);
    }

    // CommonState::queue_tls_message()
    fn queue_tls_message(
        sendable_tls: &mut ChunkVecBuffer,
        queued_key_update_message: &mut Option<Vec<u8>>,
        m: OutboundOpaqueMessage,
    ) {
        Self::perhaps_write_key_update(sendable_tls, queued_key_update_message);
        sendable_tls.append(m.encode());
    }
}

/// A writer of plaintext data into a [`ClientWriter`].
pub struct PlaintextWriter<'a> {
    /// The underlying writer.
    writer: &'a mut Writer,
}

impl io::Write for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Ignore if a fatal error has been enqueued.
        if self.writer.enqueued_fatal_error {
            return Ok(0);
        }

        let mut record_layer = self.writer.record_layer.lock().unwrap();
        let len = Writer::buffer_plaintext(
            &self.writer.info,
            &mut record_layer,
            &mut self.writer.sendable_tls,
            &mut self.writer.queued_key_update_message,
            &mut self.writer.refresh_traffic_keys_pending,
            &mut self.writer.message_fragmenter,
            buf.into(),
        );
        Writer::maybe_refresh_traffic_keys(
            &self.writer.info,
            &mut self.writer.encryption_secret,
            &mut record_layer,
            &mut self.writer.sendable_tls,
            &mut self.writer.message_fragmenter,
            &mut self.writer.queued_key_update_message,
            &mut self.writer.refresh_traffic_keys_pending,
        );
        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        // Ignore if a fatal error has been enqueued.
        if self.writer.enqueued_fatal_error {
            return Ok(0);
        }

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

        let mut record_layer = self.writer.record_layer.lock().unwrap();
        let len = Writer::buffer_plaintext(
            &self.writer.info,
            &mut record_layer,
            &mut self.writer.sendable_tls,
            &mut self.writer.queued_key_update_message,
            &mut self.writer.refresh_traffic_keys_pending,
            &mut self.writer.message_fragmenter,
            payload,
        );
        Writer::maybe_refresh_traffic_keys(
            &self.writer.info,
            &mut self.writer.encryption_secret,
            &mut record_layer,
            &mut self.writer.sendable_tls,
            &mut self.writer.message_fragmenter,
            &mut self.writer.queued_key_update_message,
            &mut self.writer.refresh_traffic_keys_pending,
        );
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An action commanded by the [`Reader`].
#[must_use = "Pass this object to 'Writer::enact()'"]
pub struct WriterAction(WriterActionImpl);

enum WriterActionImpl {
    /// Enqueue an alert.
    ///
    /// If the alert is fatal, the writer will refuse new application data.
    EnqueueAlert(AlertLevel, AlertDescription),

    /// Update the sending keys.
    ///
    /// This action is sent in response to a key update request from the peer,
    /// so the writer shouldn't request the peer to update their keys again.
    UpdateSendingKeys,
}
