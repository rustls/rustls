use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::mem;
use core::ops::{Deref, DerefMut, Range};
use std::io::{self, BufRead, Read};

use kernel::KernelConnection;

use crate::common_state::{
    CommonState, ConnectionOutputs, DEFAULT_BUFFER_LIMIT, Input, IoState, Output, State,
    process_main_protocol,
};
use crate::crypto::cipher::{Decrypted, EncodedMessage};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{ApiMisuse, Error, PeerMisbehaved};
use crate::msgs::{
    BufferProgress, DeframerIter, Delocator, HEADER_SIZE, HandshakeDeframer, Locator, MAX_PAYLOAD,
    Message, Random,
};
use crate::suites::ExtractedSecrets;
use crate::vecbuf::ChunkVecBuffer;

// pub so that it can be re-exported from the crate root
pub mod kernel;
pub(crate) mod unbuffered;

use crate::crypto::cipher::OutboundPlain;

/// A trait generalizing over buffered client or server connections.
pub trait Connection: Debug + Deref<Target = ConnectionOutputs> + DerefMut {
    /// Writes TLS messages to `wr`.
    ///
    /// On success, this function returns `Ok(n)` where `n` is a number of bytes written to `wr`
    /// (after encoding and encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully flushed. The
    /// [`Connection::wants_write()`] function can be used to check if the output buffer is
    /// empty.
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error>;

    /// Returns true if the caller should call [`Connection::read_tls`] as soon
    /// as possible.
    ///
    /// If there is pending plaintext data to read with [`Connection::reader`],
    /// this returns false.  If your application respects this mechanism,
    /// only one full TLS message will be buffered by rustls.
    ///
    /// [`Connection::reader`]: crate::Connection::reader
    /// [`Connection::read_tls`]: crate::Connection::read_tls
    fn wants_read(&self) -> bool;

    /// Returns true if the caller should call [`Connection::write_tls`] as soon as possible.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    fn wants_write(&self) -> bool;

    /// Returns an object that allows reading plaintext.
    fn reader(&mut self) -> Reader<'_>;

    /// Returns an object that allows writing plaintext.
    fn writer(&mut self) -> Writer<'_>;

    /// Processes any new packets read by a previous call to
    /// [`Connection::read_tls`].
    ///
    /// Errors from this function relate to TLS protocol errors, and
    /// are fatal to the connection.  Future calls after an error will do
    /// no new work and will return the same error. After an error is
    /// received from [`process_new_packets()`], you should not call [`read_tls()`]
    /// any more (it will fill up buffers to no purpose). However, you
    /// may call the other methods on the connection, including `write`,
    /// `send_close_notify`, and `write_tls`. Most likely you will want to
    /// call `write_tls` to send any alerts queued by the error and then
    /// close the underlying connection.
    ///
    /// Success from this function comes with some sundry state data
    /// about the connection.
    ///
    /// [`process_new_packets()`]: Connection::process_new_packets
    /// [`read_tls()`]: Connection::read_tls
    fn process_new_packets(&mut self, buf: &mut TlsInputBuffer) -> Result<IoState, Error>;

    /// Returns an object that can derive key material from the agreed connection secrets.
    ///
    /// See [RFC5705][] for more details on what this is for.
    ///
    /// This function can be called at most once per connection.
    ///
    /// This function will error:
    ///
    /// - if called prior to the handshake completing; (check with
    ///   [`Connection::is_handshaking()`] first).
    /// - if called more than once per connection.
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error>;

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    ///
    /// Should be used with care as it exposes secret key material.
    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error>;

    /// Sets a limit on the internal buffers used to buffer
    /// unsent plaintext (prior to completing the TLS handshake)
    /// and unsent TLS records.  This limit acts only on application
    /// data written through [`Connection::writer`].
    ///
    /// By default the limit is 64KB.  The limit can be set
    /// at any time, even if the current buffer use is higher.
    ///
    /// [`None`] means no limit applies, and will mean that written
    /// data is buffered without bound -- it is up to the application
    /// to appropriately schedule its plaintext and TLS writes to bound
    /// memory usage.
    ///
    /// For illustration: `Some(1)` means a limit of one byte applies:
    /// [`Connection::writer`] will accept only one byte, encrypt it and
    /// add a TLS header.  Once this is sent via [`Connection::write_tls`],
    /// another byte may be sent.
    ///
    /// # Internal write-direction buffering
    /// rustls has two buffers whose size are bounded by this setting:
    ///
    /// ## Buffering of unsent plaintext data prior to handshake completion
    ///
    /// Calls to [`Connection::writer`] before or during the handshake
    /// are buffered (up to the limit specified here).  Once the
    /// handshake completes this data is encrypted and the resulting
    /// TLS records are added to the outgoing buffer.
    ///
    /// ## Buffering of outgoing TLS records
    ///
    /// This buffer is used to store TLS records that rustls needs to
    /// send to the peer.  It is used in these two circumstances:
    ///
    /// - by [`Connection::process_new_packets`] when a handshake or alert
    ///   TLS record needs to be sent.
    /// - by [`Connection::writer`] post-handshake: the plaintext is
    ///   encrypted and the resulting TLS record is buffered.
    ///
    /// This buffer is emptied by [`Connection::write_tls`].
    ///
    /// [`Connection::writer`]: crate::Connection::writer
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    /// [`Connection::process_new_packets`]: crate::Connection::process_new_packets
    fn set_buffer_limit(&mut self, limit: Option<usize>);

    /// Sets a limit on the internal buffers used to buffer decoded plaintext.
    ///
    /// See [`Self::set_buffer_limit`] for more information on how limits are applied.
    fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>);

    /// Sends a TLS1.3 `key_update` message to refresh a connection's keys.
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// Note that this process does not happen synchronously: this call just
    /// arranges that the `key_update` message will be included in the next
    /// `write_tls` output.
    ///
    /// This fails with `Error::HandshakeNotComplete` if called before the initial
    /// handshake is complete, or if a version prior to TLS1.3 is negotiated.
    ///
    /// # Usage advice
    /// Note that other implementations (including rustls) may enforce limits on
    /// the number of `key_update` messages allowed on a given connection to prevent
    /// denial of service.  Therefore, this should be called sparingly.
    ///
    /// rustls implicitly and automatically refreshes traffic keys when needed
    /// according to the selected cipher suite's cryptographic constraints.  There
    /// is therefore no need to call this manually to avoid cryptographic keys
    /// "wearing out".
    ///
    /// The main reason to call this manually is to roll keys when it is known
    /// a connection will be idle for a long period.
    fn refresh_traffic_keys(&mut self) -> Result<(), Error>;

    /// Queues a `close_notify` warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    fn send_close_notify(&mut self);

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    ///
    /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
    fn is_handshaking(&self) -> bool;
}

/// A structure that implements [`std::io::Read`] for reading plaintext.
pub struct Reader<'a> {
    pub(super) received_plaintext: &'a mut ChunkVecBuffer,
    pub(super) has_received_close_notify: bool,
    pub(super) has_seen_eof: bool,
}

impl<'a> Reader<'a> {
    /// Check the connection's state if no bytes are available for reading.
    fn check_no_bytes_state(&self) -> io::Result<()> {
        match (self.has_received_close_notify, self.has_seen_eof) {
            // cleanly closed; don't care about TCP EOF: express this as Ok(0)
            (true, _) => Ok(()),
            // unclean closure
            (false, true) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                UNEXPECTED_EOF_MESSAGE,
            )),
            // connection still going, but needs more data: signal `WouldBlock` so that
            // the caller knows this
            (false, false) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Obtain a chunk of plaintext data received from the peer over this TLS connection.
    ///
    /// This method consumes `self` so that it can return a slice whose lifetime is bounded by
    /// the [`Connection`] that created this [`Reader`].
    pub fn into_first_chunk(self) -> io::Result<&'a [u8]> {
        match self.received_plaintext.chunk() {
            Some(chunk) => Ok(chunk),
            None => {
                self.check_no_bytes_state()?;
                Ok(&[])
            }
        }
    }
}

impl Read for Reader<'_> {
    /// Obtain plaintext data received from the peer over this TLS connection.
    ///
    /// If the peer closes the TLS session cleanly, this returns `Ok(0)`  once all
    /// the pending data has been read. No further data can be received on that
    /// connection, so the underlying TCP connection should be half-closed too.
    ///
    /// If the peer closes the TLS session uncleanly (a TCP EOF without sending a
    /// `close_notify` alert) this function returns a `std::io::Error` of type
    /// `ErrorKind::UnexpectedEof` once any pending data has been read.
    ///
    /// Note that support for `close_notify` varies in peer TLS libraries: many do not
    /// support it and uncleanly close the TCP connection (this might be
    /// vulnerable to truncation attacks depending on the application protocol).
    /// This means applications using rustls must both handle EOF
    /// from this function, *and* unexpected EOF of the underlying TCP connection.
    ///
    /// If there are no bytes to read, this returns `Err(ErrorKind::WouldBlock.into())`.
    ///
    /// You may learn the number of bytes available at any time by inspecting
    /// the return of [`Connection::process_new_packets`].
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.received_plaintext.read(buf)?;
        if len > 0 || buf.is_empty() {
            return Ok(len);
        }

        self.check_no_bytes_state()
            .map(|()| len)
    }
}

impl BufRead for Reader<'_> {
    /// Obtain a chunk of plaintext data received from the peer over this TLS connection.
    /// This reads the same data as [`Reader::read()`], but returns a reference instead of
    /// copying the data.
    ///
    /// The caller should call [`Reader::consume()`] afterward to advance the buffer.
    ///
    /// See [`Reader::into_first_chunk()`] for a version of this function that returns a
    /// buffer with a longer lifetime.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Reader {
            // reborrow
            received_plaintext: self.received_plaintext,
            ..*self
        }
        .into_first_chunk()
    }

    fn consume(&mut self, amt: usize) {
        self.received_plaintext
            .consume_first_chunk(amt)
    }
}

const UNEXPECTED_EOF_MESSAGE: &str = "peer closed connection without sending TLS close_notify: \
https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof";

/// A structure that implements [`std::io::Write`] for writing plaintext.
pub struct Writer<'a> {
    sink: &'a mut dyn PlaintextSink,
}

impl<'a> Writer<'a> {
    /// Create a new Writer.
    ///
    /// This is not an external interface.  Get one of these objects
    /// from [`Connection::writer`].
    pub(crate) fn new(sink: &'a mut dyn PlaintextSink) -> Self {
        Writer { sink }
    }
}

impl io::Write for Writer<'_> {
    /// Send the plaintext `buf` to the peer, encrypting
    /// and authenticating it.  Once this function succeeds
    /// you should call [`Connection::write_tls`] which will output the
    /// corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the
    /// TLS handshake completes, and sends it as soon
    /// as it can.  See [`Connection::set_buffer_limit()`] to control
    /// the size of this buffer.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.sink.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// Internal trait implemented by the [`ServerConnection`]/[`ClientConnection`]
/// allowing them to be the subject of a [`Writer`].
///
/// [`ServerConnection`]: crate::ServerConnection
/// [`ClientConnection`]: crate::ClientConnection
pub(crate) trait PlaintextSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize>;
    fn flush(&mut self) -> io::Result<()>;
}

impl<Side: SideData> PlaintextSink for ConnectionCommon<Side> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self
            .core
            .side
            .send
            .buffer_plaintext(buf.into(), &mut self.sendable_plaintext);
        self.core.maybe_refresh_traffic_keys();
        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let payload_owner: Vec<&[u8]>;
        let payload = match bufs.len() {
            0 => return Ok(0),
            1 => OutboundPlain::Single(bufs[0].deref()),
            _ => {
                payload_owner = bufs
                    .iter()
                    .map(|io_slice| io_slice.deref())
                    .collect();

                OutboundPlain::new(&payload_owner)
            }
        };
        let len = self
            .core
            .side
            .send
            .buffer_plaintext(payload, &mut self.sendable_plaintext);
        self.core.maybe_refresh_traffic_keys();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An object of this type can export keying material.
pub struct KeyingMaterialExporter {
    pub(crate) inner: Box<dyn Exporter>,
}

impl KeyingMaterialExporter {
    /// Derives key material from the agreed connection secrets.
    ///
    /// This function fills in `output` with `output.len()` bytes of key
    /// material derived from a master connection secret using `label`
    /// and `context` for diversification. Ownership of the buffer is taken
    /// by the function and returned via the Ok result to ensure no key
    /// material leaks if the function fails.
    ///
    /// See [RFC5705][] for more details on what this does and is for.  In
    /// other libraries this is often named `SSL_export_keying_material()`
    /// or `SslExportKeyingMaterial()`.
    ///
    /// This function is not meaningful if `output.len()` is zero and will
    /// return an error in that case.
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    pub fn derive<T: AsMut<[u8]>>(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        mut output: T,
    ) -> Result<T, Error> {
        if output.as_mut().is_empty() {
            return Err(ApiMisuse::ExporterOutputZeroLength.into());
        }

        self.inner
            .derive(label, context, output.as_mut())
            .map(|_| output)
    }
}

impl Debug for KeyingMaterialExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyingMaterialExporter")
            .finish_non_exhaustive()
    }
}

/// This trait is for any object that can export keying material.
///
/// The terminology comes from [RFC5705](https://datatracker.ietf.org/doc/html/rfc5705)
/// but doesn't really involve "exporting" key material (in the usual meaning of "export"
/// -- of moving an artifact from one domain to another) but is best thought of as key
/// diversification using an existing secret.  That secret is implicit in this interface,
/// so is assumed to be held by `self`. The secret should be zeroized in `drop()`.
///
/// There are several such internal implementations, depending on the context
/// and protocol version.
pub(crate) trait Exporter: Send + Sync {
    /// Fills in `output` with derived keying material.
    ///
    /// This is deterministic depending on a base secret (implicit in `self`),
    /// plus the `label` and `context` values.
    ///
    /// Must fill in `output` entirely, or return an error.
    fn derive(&self, label: &[u8], context: Option<&[u8]>, output: &mut [u8]) -> Result<(), Error>;
}

#[derive(Debug)]
pub(crate) struct ConnectionRandoms {
    pub(crate) client: [u8; 32],
    pub(crate) server: [u8; 32],
}

impl ConnectionRandoms {
    pub(crate) fn new(client: Random, server: Random) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

/// TLS connection state with side-specific data (`Side`).
///
/// This is one of the core abstractions of the rustls API. It represents a single connection
/// to a peer, and holds all the state associated with that connection. Note that it does
/// not hold any IO objects: the application is responsible for reading and writing TLS records.
/// If you want an object that does hold IO objects, see `rustls_util::Stream` and
/// `rustls_util::StreamOwned`.
///
/// This object is generic over the `Side` type parameter, which must implement the marker trait
/// [`SideData`]. This is used to store side-specific data.
pub(crate) struct ConnectionCommon<Side: SideData> {
    pub(crate) core: ConnectionCore<Side>,
    pub(crate) sendable_plaintext: ChunkVecBuffer,
}

impl<Side: SideData> ConnectionCommon<Side> {
    #[inline]
    pub(crate) fn process_new_packets(
        &mut self,
        buf: &mut TlsInputBuffer,
    ) -> Result<IoState, Error> {
        if buf.has_seen_eof {
            self.core.side.recv.has_seen_eof = true;
        } else if self.recv.received_plaintext.is_full() {
            return Err(ApiMisuse::ReceivedPlaintextBufferFull.into());
        }

        let io_state = self.core.process_new_packets(buf)?;

        if !self
            .core
            .side
            .send
            .may_send_application_data
            || self.sendable_plaintext.is_empty()
        {
            return Ok(io_state);
        }

        self.core
            .side
            .send
            .send_buffered_plaintext(&mut self.sendable_plaintext);
        Ok(self.core.side.current_io_state())
    }

    pub(crate) fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.core.exporter()
    }

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    /// Should be used with care as it exposes secret key material.
    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.core.dangerous_extract_secrets()
    }

    pub(crate) fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.sendable_plaintext.set_limit(limit);
        self.send.sendable_tls.set_limit(limit);
    }

    pub(crate) fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>) {
        self.core
            .side
            .recv
            .received_plaintext
            .set_limit(limit);
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core.refresh_traffic_keys()
    }
}

impl<Side: SideData> ConnectionCommon<Side> {
    /// Returns an object that allows reading plaintext.
    pub(crate) fn reader(&mut self) -> Reader<'_> {
        let common = &mut self.core.side;
        let has_seen_eof = std::dbg!(common.recv.has_seen_eof);
        let has_received_close_notify = std::dbg!(common.recv.has_received_close_notify);
        Reader {
            received_plaintext: &mut common.recv.received_plaintext,
            // Are we done? i.e., have we processed all received messages, and received a
            // close_notify to indicate that no new messages will arrive?
            has_received_close_notify,
            has_seen_eof,
        }
    }

    /// Returns an object that allows writing plaintext.
    pub(crate) fn writer(&mut self) -> Writer<'_> {
        Writer::new(self)
    }

    /// Extract the first handshake message.
    ///
    /// This is a shortcut to the `process_new_packets()` -> `process_msg()` ->
    /// `process_handshake_messages()` path, specialized for the first handshake message.
    pub(crate) fn first_handshake_message(
        &mut self,
        buf: &mut TlsInputBuffer,
    ) -> Result<Option<Input<'static>>, Error> {
        let mut buffer_progress = self.core.hs_deframer.progress();

        let res = self
            .core
            .deframe(buf.filled_mut(), &mut buffer_progress)
            .map(|opt| opt.map(|pm| Message::try_from(&pm).map(|m| m.into_owned())));

        match res? {
            Some(Ok(msg)) => {
                buf.discard(buffer_progress.take_discard());
                Ok(Some(Input {
                    message: msg,
                    aligned_handshake: self.core.hs_deframer.aligned(),
                }))
            }
            Some(Err(err)) => Err(err.into()),
            None => Ok(None),
        }
    }

    pub(crate) fn replace_state(&mut self, new: Box<dyn State<Side>>) {
        self.core.state = Ok(new);
    }

    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.send.sendable_tls.write_to(wr)
    }
}

impl<Side: SideData> Deref for ConnectionCommon<Side> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.side
    }
}

impl<Side: SideData> DerefMut for ConnectionCommon<Side> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.side
    }
}

impl<Side: SideData> From<ConnectionCore<Side>> for ConnectionCommon<Side> {
    fn from(core: ConnectionCore<Side>) -> Self {
        Self {
            core,
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
        }
    }
}

pub(crate) struct ConnectionCore<Side: SideData> {
    pub(crate) state: Result<Box<dyn State<Side>>, Error>,
    pub(crate) side: Side,
    pub(crate) hs_deframer: HandshakeDeframer,

    /// We limit consecutive empty fragments to avoid a route for the peer to send
    /// us significant but fruitless traffic.
    seen_consecutive_empty_fragments: u8,
}

impl<Side: SideData> ConnectionCore<Side> {
    pub(crate) fn new(state: Box<dyn State<Side>>, side: Side) -> Self {
        Self {
            state: Ok(state),
            side,
            hs_deframer: HandshakeDeframer::default(),
            seen_consecutive_empty_fragments: 0,
        }
    }

    pub(crate) fn process_new_packets(
        &mut self,
        deframer_buffer: &mut TlsInputBuffer,
    ) -> Result<IoState, Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                self.state = Err(e.clone());
                return Err(e);
            }
        };

        // Should `EncodedMessage<Payload>` resolve to plaintext application
        // data it will be allocated within `plaintext` and written to the
        // `ReadPath::received_plaintext` buffer.
        let mut plaintext = None;
        let mut buffer_progress = self.hs_deframer.progress();

        loop {
            let buffer = deframer_buffer.filled_mut();
            let locator = Locator::new(buffer);
            let res = self.deframe(buffer, &mut buffer_progress);

            let opt_msg = match res {
                Ok(opt_msg) => opt_msg,
                Err(e) => {
                    self.side
                        .send
                        .maybe_send_fatal_alert(&e);
                    if let Error::DecryptError = e {
                        state.handle_decrypt_error();
                    }
                    self.state = Err(e.clone());
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            };

            let Some(msg) = opt_msg else {
                break;
            };

            match process_main_protocol(
                msg,
                self.hs_deframer.aligned(),
                state,
                &locator,
                &mut plaintext,
                &mut self.side,
            ) {
                Ok(new) => state = new,
                Err(e) => {
                    self.side
                        .send
                        .maybe_send_fatal_alert(&e);
                    self.state = Err(e.clone());
                    deframer_buffer.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            }

            if self.side.recv.has_received_close_notify {
                // "Any data received after a closure alert has been received MUST be ignored."
                // -- <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
                // This is data that has already been accepted in `read_tls`.
                buffer_progress.add_discard(deframer_buffer.filled().len());
                deframer_buffer.has_received_close_notify = true;
                break;
            }

            if let Some(payload) = plaintext.take() {
                let payload = payload.reborrow(&Delocator::new(buffer));
                self.side
                    .recv
                    .received_plaintext
                    .append(payload.into_vec());
            }

            deframer_buffer.discard(buffer_progress.take_discard());
        }

        deframer_buffer.discard(buffer_progress.take_discard());
        self.state = Ok(state);
        Ok(self.side.current_io_state())
    }

    /// Pull a message out of the deframer and send any messages that need to be sent as a result.
    fn deframe<'b>(
        &mut self,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<EncodedMessage<&'b [u8]>>, Error> {
        // before processing any more of `buffer`, return any extant messages from `hs_deframer`
        if self.hs_deframer.has_message_ready() {
            Ok(self.take_handshake_message(buffer, buffer_progress))
        } else {
            self.process_more_input(buffer, buffer_progress)
        }
    }

    fn take_handshake_message<'b>(
        &mut self,
        buffer: &'b [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Option<EncodedMessage<&'b [u8]>> {
        self.hs_deframer
            .iter(buffer)
            .next()
            .map(|(message, discard)| {
                buffer_progress.add_discard(discard);
                message
            })
    }

    fn process_more_input<'b>(
        &mut self,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<EncodedMessage<&'b [u8]>>, Error> {
        let version_is_tls13 =
            matches!(self.side.negotiated_version, Some(ProtocolVersion::TLSv1_3));

        let locator = Locator::new(buffer);

        loop {
            let mut iter = DeframerIter::new(&mut buffer[buffer_progress.processed()..]);

            let (message, processed) = loop {
                let message = match iter.next().transpose() {
                    Ok(Some(message)) => message,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(err),
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
                            && !self
                                .side
                                .recv
                                .decrypt_state
                                .has_decrypted()
                            && message.payload.len() <= 2 =>
                    {
                        true
                    }
                    // In other circumstances, we expect all messages to be encrypted.
                    _ => false,
                };

                if allowed_plaintext && !self.hs_deframer.is_active() {
                    break (message.into_plain_message(), iter.bytes_consumed());
                }

                let message = match self
                    .side
                    .recv
                    .decrypt_state
                    .decrypt_incoming(message)
                {
                    // failed decryption during trial decryption is not allowed to be
                    // interleaved with partial handshake data.
                    Ok(None) if self.hs_deframer.aligned().is_none() => {
                        return Err(
                            PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage.into(),
                        );
                    }

                    // failed decryption during trial decryption.
                    Ok(None) => continue,

                    Ok(Some(message)) => message,

                    Err(err) => return Err(err),
                };

                let Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                } = message;

                if want_close_before_decrypt {
                    self.side.send_close_notify();
                }

                break (plaintext, iter.bytes_consumed());
            };

            if self.hs_deframer.aligned().is_none() && message.typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage.into());
            }

            match message.payload.len() {
                0 => {
                    if self.seen_consecutive_empty_fragments
                        == ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX
                    {
                        return Err(PeerMisbehaved::TooManyEmptyFragments.into());
                    }
                    self.seen_consecutive_empty_fragments += 1;
                }
                _ => {
                    self.seen_consecutive_empty_fragments = 0;
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
            self.hs_deframer
                .input_message(message, &locator, buffer_progress.processed());
            self.hs_deframer.coalesce(buffer)?;

            if self.hs_deframer.has_message_ready() {
                // trial decryption finishes with the first handshake message after it started.
                self.side
                    .recv
                    .decrypt_state
                    .finish_trial_decryption();

                return Ok(self.take_handshake_message(buffer, buffer_progress));
            }
        }
    }

    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        Ok(self
            .dangerous_into_kernel_connection()?
            .0)
    }

    pub(crate) fn dangerous_into_kernel_connection(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Side>), Error> {
        let common = self.side.into_common();

        if common.is_handshaking() {
            return Err(Error::HandshakeNotComplete);
        }

        if !common.send.sendable_tls.is_empty() {
            return Err(ApiMisuse::SecretExtractionWithPendingSendableData.into());
        }

        let state = self.state?;

        let read_seq = common.recv.decrypt_state.read_seq();
        let write_seq = common.send.encrypt_state.write_seq();

        let (secrets, state) = state.into_external_state()?;
        let secrets = ExtractedSecrets {
            tx: (write_seq, secrets.tx),
            rx: (read_seq, secrets.rx),
        };
        let external = KernelConnection::new(state, common)?;

        Ok((secrets, external))
    }

    pub(crate) fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.side.exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None if self.side.is_handshaking() => Err(Error::HandshakeNotComplete),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }

    pub(crate) fn early_exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.side.early_exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }

    /// Trigger a `refresh_traffic_keys` if required by `CommonState`.
    fn maybe_refresh_traffic_keys(&mut self) {
        if mem::take(
            &mut self
                .side
                .send
                .refresh_traffic_keys_pending,
        ) {
            let _ = self.refresh_traffic_keys();
        }
    }

    fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        match &mut self.state {
            Ok(st) => st.send_key_update_request(&mut self.side),
            Err(e) => Err(e.clone()),
        }
    }
}

/// Buffer for data read from the socket, in the process of being parsed into messages.
#[derive(Default, Debug)]
pub struct TlsInputBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,

    /// Whether we've seen a 0-byte read.
    has_seen_eof: bool,

    /// Whether a CloseNotify alert has been seen.
    has_received_close_notify: bool,
}

impl TlsInputBuffer {
    /// Read some bytes from `rd`, and add them to the buffer.
    pub fn read(&mut self, rd: &mut dyn Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        } else if self.has_received_close_notify {
            return Ok(0);
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(&mut self.buf[self.used..])?;
        if new_bytes == 0 {
            self.has_seen_eof = true;
        }

        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        /// TLS allows for handshake messages of up to 16MB.  We
        /// restrict that to 64KB to limit potential for denial-of-
        /// service.
        const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

        const READ_SIZE: usize = 4096;

        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => Self::MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `MAX_WIRE_SIZE`),
        // make sure to reduce the buffer size again (large messages should be rare).
        // Also, reduce the buffer size if there are neither full nor partial messages in it,
        // which usually means that the other side suspended sending data.
        let need_capacity = Ord::min(allow_max, self.used + READ_SIZE);
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.used == 0 || self.buf.len() > allow_max {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        Ok(())
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went.
    pub(crate) fn extend_hs(&mut self, bytes: &[u8]) -> Range<usize> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }

    /// Discard `taken` bytes from the start of our buffer.
    pub(crate) fn discard(&mut self, taken: usize) {
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf
                .copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken >= self.used {
            self.used = 0;
        }
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    /// Maximum on-the-wire message size.
    pub(crate) const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;
}

/// Data specific to the peer's side (client or server).
#[expect(private_bounds)]
pub trait SideData: private::SideData {}

pub(crate) mod private {
    use super::*;

    pub(crate) trait SideData:
        Output + Debug + Deref<Target = CommonState> + DerefMut
    {
        fn into_common(self) -> CommonState;
    }
}

/// An [`EncodedMessage<Payload<'_>>`] which does not borrow its payload, but
/// references a range that can later be borrowed.
struct InboundUnborrowedMessage {
    typ: ContentType,
    version: ProtocolVersion,
    bounds: Range<usize>,
}

impl InboundUnborrowedMessage {
    fn unborrow(locator: &Locator, msg: EncodedMessage<&'_ [u8]>) -> Self {
        Self {
            typ: msg.typ,
            version: msg.version,
            bounds: locator.locate(msg.payload),
        }
    }

    fn reborrow<'b>(self, delocator: &Delocator<'b>) -> EncodedMessage<&'b [u8]> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: delocator.slice_from_range(&self.bounds),
        }
    }
}

/// cf. BoringSSL's `kMaxEmptyRecords`
/// <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls_record.cc#L124-L128>
const ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX: u8 = 32;
