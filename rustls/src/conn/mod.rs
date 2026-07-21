use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::ops::{Deref, DerefMut};
use std::io;

use kernel::KernelConnection;
use pki_types::FipsStatus;

use crate::common_state::{
    CommonState, ConnectionOutput, ConnectionOutputs, Event, Output, OutputEvent,
};
use crate::error::{ApiMisuse, Error};
use crate::kernel::KernelState;
use crate::msgs::{Delocator, Message, Random, ServerExtensionsInput};
use crate::quic::QuicOutput;
use crate::server::{ChooseConfig, ServerConfig, ServerSide};
use crate::suites::{ExtractedSecrets, PartiallyExtractedSecrets};
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::vecbuf::ChunkVecBuffer;

// pub so that it can be re-exported from the crate root
pub mod kernel;

mod receive;
use receive::JoinOutput;
pub(crate) use receive::{Input, MessageIter, ReceivePath, TrafficTemperCounters};
pub use receive::{SliceInput, TlsInputBuffer, VecInput};

mod send;
use send::DEFAULT_BUFFER_LIMIT;
pub(crate) use send::{SendOutput, SendPath};

pub(crate) mod split;
use split::SplitConnection;

use crate::crypto::cipher::{OutboundPlain, Payload};

/// A trait generalizing over buffered client or server connections.
pub trait Connection<Side: SideData>: Debug + Deref<Target = ConnectionOutputs> {
    /// Writes TLS messages to `wr`.
    ///
    /// On success, this function returns `Ok(n)` where `n` is a number of bytes written to `wr`
    /// (after encoding and encryption).
    ///
    /// After this function returns, the connection buffer may not yet be fully flushed. The
    /// [`Self::wants_write()`] function can be used to check if the output buffer is
    /// empty.
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error>;

    /// Returns true if the caller should call [`Self::process_new_packets()`] as soon as possible.
    fn wants_read(&self) -> bool;

    /// Returns true if the caller should call [`Self::write_tls()`] as soon as possible.
    fn wants_write(&self) -> bool;

    /// Returns an object that allows writing plaintext.
    fn writer(&mut self) -> Writer<'_>;

    /// Processes any new packets from the buffer supplied in `buf`.
    ///
    /// Errors from this function relate to TLS protocol errors, and
    /// are fatal to the connection.  Future calls after an error will do
    /// no new work and will return the same error. After an error is
    /// received from this function, you should not continue to fill up the buffer.
    /// However, you may call the other methods on the connection, including [`Self::writer()`],
    /// [`Self::send_close_notify()`], and [`Self::write_tls()`]. Most likely you will want to
    /// call [`Self::write_tls()`] to send any alerts queued by the error and then
    /// close the underlying connection.
    ///
    /// Success from this function comes with some sundry state data
    /// about the connection.
    fn process_new_packets<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
    ) -> MessageHandler<'a, 'm, Side>;

    /// Returns an object that can derive key material from the agreed connection secrets.
    ///
    /// See [RFC5705][] for more details on what this is for.
    ///
    /// This function can be called at most once per connection.
    ///
    /// This function will error:
    ///
    /// - if called prior to the handshake completing; (check with
    ///   [`Self::is_handshaking()`] first).
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
    /// data written through [`Self::writer()`].
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
    /// [`Self::writer()`] will accept only one byte, encrypt it and
    /// add a TLS header.  Once this is sent via [`Self::write_tls()`],
    /// another byte may be sent.
    ///
    /// # Internal write-direction buffering
    /// rustls has two buffers whose size are bounded by this setting:
    ///
    /// ## Buffering of unsent plaintext data prior to handshake completion
    ///
    /// Calls to [`Self::writer()`] before or during the handshake
    /// are buffered (up to the limit specified here).  Once the
    /// handshake completes this data is encrypted and the resulting
    /// TLS records are added to the outgoing buffer.
    ///
    /// ## Buffering of outgoing TLS records
    ///
    /// This buffer is used to store TLS records that rustls needs to
    /// send to the peer.  It is used in these two circumstances:
    ///
    /// - by [`Self::process_new_packets()`] when a handshake or alert
    ///   TLS record needs to be sent.
    /// - by [`Self::writer()`] post-handshake: the plaintext is
    ///   encrypted and the resulting TLS record is buffered.
    ///
    /// This buffer is emptied by [`Self::write_tls()`].
    fn set_buffer_limit(&mut self, limit: Option<usize>);

    /// Sends a TLS1.3 `key_update` message to refresh a connection's keys.
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// Note that this process does not happen synchronously: this call just
    /// arranges that the `key_update` message will be included in the next
    /// [`Self::write_tls()`] output.
    ///
    /// This fails with [`Error::HandshakeNotComplete`] if called before the initial
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

    /// Queues a `close_notify` warning alert to be sent in the next [`Self::write_tls`] call.
    ///
    /// This informs the peer that the connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    fn send_close_notify(&mut self);

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Self::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    fn is_handshaking(&self) -> bool;

    /// Return the FIPS validation status of the connection.
    ///
    /// This is different from [`CryptoProvider::fips()`][]:
    /// it is concerned only with cryptography, whereas this _also_ covers TLS-level
    /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
    ///
    /// [`CryptoProvider::fips()`]: crate::crypto::CryptoProvider::fips()
    fn fips(&self) -> FipsStatus;
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
    buffers: Buffers,
}

impl<Side: SideData> ConnectionCommon<Side> {
    pub(crate) fn new(core: ConnectionCore<Side>) -> Self {
        Self {
            core,
            buffers: Buffers::new(),
        }
    }

    pub(crate) fn process_new_packets<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
    ) -> MessageHandler<'a, 'm, Side> {
        MessageHandler::new(input, &mut self.buffers, &mut self.core)
    }

    pub(crate) fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        !self.recv.has_received_close_notify
            && (self.send.may_send_application_data || self.send.sendable_tls.is_empty())
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
        self.buffers
            .sendable_plaintext
            .set_limit(limit);
        self.send.sendable_tls.set_limit(limit);
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core
            .common
            .send
            .refresh_traffic_keys()
    }

    pub(crate) fn split(self) -> Result<SplitConnection<Side>, Error> {
        // `SplitConnection` cannot be used to progress a handshake.
        if self.is_handshaking() {
            return Err(ApiMisuse::SplitDuringHandshake.into());
        }

        // We are about to drop `Buffers`
        if !self.buffers.is_empty() {
            return Err(ApiMisuse::SplitWithPendingBuffers.into());
        }

        SplitConnection::try_from(self.core)
    }
}

impl<Side: SideData> ConnectionCommon<Side> {
    /// Returns an object that allows writing plaintext.
    pub(crate) fn writer(&mut self) -> Writer<'_> {
        Writer::new(self)
    }

    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.send.sendable_tls.write_to(wr)
    }
}

impl<Side: SideData> Deref for ConnectionCommon<Side> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common
    }
}

impl<Side: SideData> DerefMut for ConnectionCommon<Side> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common
    }
}

pub(crate) struct ConnectionCore<Side: SideData> {
    pub(crate) state: Result<Side::State, Error>,
    pub(crate) side: Side::Data,
    pub(crate) common: CommonState,
}

impl<Side: SideData> ConnectionCore<Side> {
    pub(crate) fn new(state: Side::State, side: Side::Data, common: CommonState) -> Self {
        Self {
            state: Ok(state),
            side,
            common,
        }
    }

    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        Ok(self
            .dangerous_into_kernel_connection()?
            .0)
    }

    pub(crate) fn dangerous_into_kernel_connection(
        mut self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Side>), Error> {
        if self.common.is_handshaking() {
            return Err(Error::HandshakeNotComplete);
        }
        Self::from_parts_into_kernel_connection(
            &mut self.common.send,
            self.common.recv,
            self.common.outputs,
            self.state?,
        )
    }

    pub(crate) fn from_parts_into_kernel_connection(
        send: &mut SendPath,
        recv: ReceivePath,
        outputs: ConnectionOutputs,
        state: Side::State,
    ) -> Result<(ExtractedSecrets, KernelConnection<Side>), Error> {
        if !send.sendable_tls.is_empty() {
            return Err(ApiMisuse::SecretExtractionWithPendingSendableData.into());
        }

        let read_seq = recv.decrypt_state.read_seq();
        let write_seq = send.encrypt_state.write_seq();

        let tls13_key_schedule = send.tls13_key_schedule.take();

        let (secrets, state) = state.into_external_state(&tls13_key_schedule)?;
        let secrets = ExtractedSecrets {
            tx: (write_seq, secrets.tx),
            rx: (read_seq, secrets.rx),
        };
        let external = KernelConnection::new(state, outputs, tls13_key_schedule)?;

        Ok((secrets, external))
    }

    pub(crate) fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.common.exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None if self.common.is_handshaking() => Err(Error::HandshakeNotComplete),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }

    pub(crate) fn early_exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.common.early_exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }
}

impl ConnectionCore<ServerSide> {
    pub(crate) fn accepted(
        &mut self,
        choose: Box<ChooseConfig>,
        exts: ServerExtensionsInput,
        quic: Option<&mut dyn QuicOutput>,
        config: Arc<ServerConfig>,
    ) -> Result<(), Error> {
        self.common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        self.common.fips = config.fips();

        let mut output = SideCommonOutput {
            side: &mut self.side,
            quic,
            common: &mut self.common,
        };

        self.state = Ok(choose.use_config(config, exts, &mut output)?);
        Ok(())
    }
}

/// Driver for handling messages from the `TlsInputBuffer`.
///
/// Must be driven to completion to make progress, by calling either [`Self::handle_all()`] or
/// repeatedly calling [`Self::next_payload()`] until it returns `None`.
#[must_use]
pub struct MessageHandler<'a, 'm, Side: SideData> {
    iter: MessageIter<'a, 'm, Side, SendPath>,
    buffers: &'a mut Buffers,
    done: bool,
}

impl<'a, 'm, Side: SideData> MessageHandler<'a, 'm, Side> {
    pub(crate) fn new(
        input: &'m mut dyn TlsInputBuffer,
        buffers: &'a mut Buffers,
        core: &'a mut ConnectionCore<Side>,
    ) -> Self {
        if input.has_seen_eof() {
            buffers.has_seen_eof = true;
        }

        Self {
            iter: MessageIter::new(input, None, core),
            buffers,
            done: false,
        }
    }
}

impl<'a, 'm, Side: SideData> MessageHandler<'a, 'm, Side> {
    /// Handles all complete messages from the input buffer.
    ///
    /// Writes any plaintext application data from the input into `buf`, and returns the I/O
    /// state of the connection after processing the last message. If an error is returned,
    /// the connection is in a fatal error state and no further progress can be made.
    pub fn handle_all(mut self, buf: &mut Vec<u8>) -> Result<IoState, Error> {
        while let Some(result) = self.next_payload() {
            buf.extend_from_slice(result?.bytes());
        }

        Ok(self.state())
    }

    /// Yields the first payload of plaintext application data from the input buffer.
    ///
    /// Should be called repeatedly until it returns `None`, at which point the input buffer no
    /// longer contains any complete messages and should be refilled by the application.
    pub fn next_payload(&mut self) -> Option<Result<Payload<'_>, Error>> {
        if self.done {
            return None;
        }

        let Some(result) = self.iter.next() else {
            self.done = true;
            return None;
        };

        let payload = match result {
            Ok(payload) => payload,
            Err(err) => {
                self.done = true;
                return Some(Err(err));
            }
        };

        Some(Ok(
            payload.reborrow(&Delocator::new(self.iter.input.slice_mut()))
        ))
    }

    /// The I/O state of the connection after processing the last message.
    pub fn state(self) -> IoState {
        IoState::new(self.iter.output.send, self.iter.recv)
    }
}

impl<'a, 'm, Side: SideData + private::Side> Drop for MessageHandler<'a, 'm, Side> {
    fn drop(&mut self) {
        let MessageIter {
            input,
            recv,
            output: JoinOutput { send, .. },
            ..
        } = &mut self.iter;

        input.discard(recv.deframer.take_discard());

        // Release unsent buffered plaintext.
        if send.may_send_application_data
            && !self
                .buffers
                .sendable_plaintext
                .is_empty()
        {
            send.send_buffered_plaintext(&mut self.buffers.sendable_plaintext);
        }
    }
}

impl<S: SideData> Debug for MessageHandler<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextIter")
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

/// Common items for buffered, std::io-using connections.
pub(crate) struct Buffers {
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    pub(crate) has_seen_eof: bool,
}

impl Buffers {
    fn new() -> Self {
        Self {
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            has_seen_eof: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.sendable_plaintext.is_empty()
    }
}

/// A structure that implements [`std::io::Write`] for writing plaintext.
pub struct Writer<'a> {
    sink: &'a mut dyn PlaintextSink,
}

impl<'a> Writer<'a> {
    /// Create a new Writer.
    ///
    /// This is not an external interface.  Get one of these objects
    /// from [`Connection::writer()`].
    pub(crate) fn new(sink: &'a mut dyn PlaintextSink) -> Self {
        Writer { sink }
    }
}

impl io::Write for Writer<'_> {
    /// Send the plaintext `buf` to the peer, encrypting and authenticating it.
    ///
    /// Once this function succeeds you should call [`Connection::write_tls()`] which will output
    /// the corresponding TLS records.
    ///
    /// This function buffers plaintext sent before the TLS handshake completes, and sends it as soon
    /// as it can.  See [`Connection::set_buffer_limit()`] to control the size of this buffer.
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
            .common
            .send
            .buffer_plaintext(buf.into(), &mut self.buffers.sendable_plaintext);
        self.send.maybe_refresh_traffic_keys();
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
            .common
            .send
            .buffer_plaintext(payload, &mut self.buffers.sendable_plaintext);
        self.send.maybe_refresh_traffic_keys();
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

/// Values of this structure are returned from [`Connection::process_new_packets()`]
/// and tell the caller the current I/O state of the TLS connection.
#[derive(Debug, Eq, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    peer_has_closed: bool,
}

impl IoState {
    pub(crate) fn new(send: &SendPath, recv: &ReceivePath) -> Self {
        Self {
            tls_bytes_to_write: send.sendable_tls.len(),
            peer_has_closed: recv.has_received_close_notify,
        }
    }

    /// How many bytes could be written by [`Connection::write_tls()`] if called right now.
    ///
    /// A non-zero value implies [`CommonState::wants_write()`].
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// True if the peer has sent us a close_notify alert.
    ///
    /// This is the TLS mechanism to securely half-close a TLS connection, and signifies that
    /// the peer will not send any further data on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from [`std::io::Read`], after all the
    /// received bytes have been retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

pub(crate) struct SideCommonOutput<'a, 'q> {
    pub(crate) side: &'a mut dyn SideOutput,
    pub(crate) quic: Option<&'q mut dyn QuicOutput>,
    pub(crate) common: &'a mut CommonState,
}

impl<'q> Output<'_> for SideCommonOutput<'_, 'q> {
    fn emit(&mut self, ev: Event<'_>) {
        self.side.emit(ev);
    }

    fn output(&mut self, ev: OutputEvent<'_>) {
        if let OutputEvent::ProtocolVersion(ver) = ev {
            self.common.recv.negotiated_version = Some(ver);
            self.common.send.negotiated_version(ver);
        }
        self.common.outputs.handle(ev);
    }

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        match self.quic() {
            Some(quic) => quic.send_msg(m, must_encrypt),
            None => self
                .common
                .send
                .send_msg(m, must_encrypt),
        }
    }

    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        match self.quic.as_mut() {
            Some(q) => Some(&mut **q),
            None => None,
        }
    }

    fn start_traffic(&mut self) {
        self.common
            .recv
            .may_receive_application_data = true;
        self.common
            .send
            .start_outgoing_traffic();
    }

    fn receive(&mut self) -> &mut ReceivePath {
        &mut self.common.recv
    }

    fn send(&mut self) -> &mut dyn SendOutput {
        &mut self.common.send
    }
}

/// Data specific to the peer's side (client or server).
#[expect(private_bounds)]
pub trait SideData: private::Side {}

pub(crate) mod private {
    use super::*;

    pub(crate) trait Side: Debug {
        /// Data storage type.
        type Data: SideOutput;
        /// State machine type.
        type State: StateMachine;
    }

    pub(crate) trait SideOutput {
        fn emit(&mut self, ev: Event<'_>);
    }
}

use private::SideOutput;

pub(crate) trait StateMachine: Sized {
    fn handle<'m>(self, input: Input<'m>, output: &mut dyn Output<'m>) -> Result<Self, Error>;
    fn wants_input(&self) -> bool;
    fn is_traffic(&self) -> bool;
    fn handle_decrypt_error(&mut self);
    fn into_external_state(
        self,
        send_keys: &Option<Box<KeyScheduleTrafficSend>>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error>;
}
