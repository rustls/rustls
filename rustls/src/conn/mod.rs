use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::ops::{Deref, DerefMut};

use kernel::KernelConnection;
use pki_types::FipsStatus;

use crate::common_state::{
    CommonState, ConnectionOutput, ConnectionOutputs, Event, Output, OutputEvent,
};
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::error::{ApiMisuse, Error};
use crate::kernel::KernelState;
use crate::msgs::{Delocator, Message, Random, ServerExtensionsInput};
use crate::quic::QuicOutput;
use crate::server::{ChooseConfig, ServerConfig, ServerSide};
use crate::suites::{ExtractedSecrets, PartiallyExtractedSecrets};
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleTrafficSend;

// pub so that it can be re-exported from the crate root
pub mod kernel;

mod receive;
pub(crate) use receive::{Input, MessageIter, ReceivePath, TrafficTemperCounters};
pub use receive::{SliceInput, TlsInputBuffer, VecInput};

mod send;
pub(crate) use send::{SendOutput, SendPath};

pub(crate) mod split;
use split::SplitConnection;

/// A trait generalizing over buffered client or server connections.
pub trait Connection: Debug + Deref<Target = ConnectionOutputs> {
    /// The side (client or server) that this type implements.
    type Side: SideData;

    /// Writes the application data from `plaintext` into TLS records and appends them to `tls`.
    ///
    /// This will fail if either the handshake is not complete yet (because we don't yet have the
    /// keys to encrypt application data) or if the send path has been closed by sending a
    /// `close_notify` alert.
    fn write_tls(&mut self, plaintext: OutboundPlain<'_>, tls: &mut Vec<u8>) -> Result<(), Error>;

    /// Returns true if the caller should call [`Self::process_new_packets()`] as soon as possible.
    fn wants_read(&self) -> bool;

    /// Build a [`MessageHandler`] to process messages from the input buffer.
    fn process_new_packets<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        tls: &'a mut Vec<u8>,
    ) -> MessageHandler<'a, 'm, Self::Side>;

    /// Returns an object that can derive key material from the agreed connection secrets.
    ///
    /// See [RFC 5705][] for more details on what this is for.
    ///
    /// This function can be called at most once per connection.
    ///
    /// This function will error:
    ///
    /// - if called prior to the handshake completing; (check with
    ///   [`Self::is_handshaking()`] first).
    /// - if called more than once per connection.
    ///
    /// [RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error>;

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    ///
    /// Should be used with care as it exposes secret key material.
    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error>;

    /// Sends a TLS1.3 `key_update` message into `tls` to refresh a connection's keys.
    ///
    /// The main reason to call this manually is to roll keys when it is known
    /// a connection will be idle for a long period.
    ///
    /// rustls implicitly and automatically refreshes traffic keys when needed
    /// according to the selected cipher suite's cryptographic constraints.  There
    /// is therefore no need to call this manually to avoid cryptographic keys
    /// "wearing out".
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// This fails with [`Error::HandshakeNotComplete`] if called before the initial
    /// handshake is complete, or if a version prior to TLS1.3 is negotiated.
    ///
    /// # Usage advice
    /// Note that other implementations (including rustls) may enforce limits on
    /// the number of `key_update` messages allowed on a given connection to prevent
    /// denial of service.  Therefore, this should be called sparingly.
    ///
    /// rustls only allows one outstanding request at a time; this function succeeds
    /// but sends nothing if a request is already in-flight.
    fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error>;

    /// Writes a `close_notify` warning alert into `tls`.
    ///
    /// This informs the peer that the connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    fn send_close_notify(&mut self, tls: &mut Vec<u8>);

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time, [`Self::write_tls()`] will return an error.
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
    pub(crate) state: Result<Side::State, Error>,
    pub(crate) side: Side::Data,
    pub(crate) common: CommonState,
}

impl<Side: SideData> ConnectionCommon<Side> {
    pub(crate) fn new(state: Side::State, side: Side::Data, common: CommonState) -> Self {
        Self {
            state: Ok(state),
            side,
            common,
        }
    }

    pub(crate) fn process_new_packets<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        tls: &'a mut Vec<u8>,
    ) -> MessageHandler<'a, 'm, Side> {
        MessageHandler::new(input, tls, self)
    }

    pub(crate) fn write_tls(
        &mut self,
        plaintext: OutboundPlain<'_>,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if plaintext.is_empty() {
            return Ok(());
        } else if !self
            .common
            .send
            .may_send_application_data
        {
            return Err(ApiMisuse::WriteTlsBeforeHandshakeComplete.into());
        } else if self.common.send.has_sent_close_notify {
            return Err(ApiMisuse::WriteTlsAfterSendPathClosed.into());
        }

        self.common
            .send
            .send_appdata_encrypt(plaintext, tls);

        Ok(())
    }

    pub(crate) fn wants_read(&self) -> bool {
        // We want to read more data all the time, except after the peer has sent us
        // a close notification.
        !self
            .common
            .recv
            .has_received_close_notify
    }

    pub(crate) fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        self.common
            .send
            .refresh_traffic_keys(tls)
    }

    pub(crate) fn split(self) -> Result<SplitConnection<Side>, Error> {
        // `SplitConnection` cannot be used to progress a handshake.
        if self.is_handshaking() {
            return Err(ApiMisuse::SplitDuringHandshake.into());
        }

        SplitConnection::try_from(self)
    }

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    /// Should be used with care as it exposes secret key material.
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
}

impl ConnectionCommon<ServerSide> {
    pub(crate) fn accepted(
        &mut self,
        choose: Box<ChooseConfig>,
        exts: ServerExtensionsInput,
        quic: Option<&mut dyn QuicOutput>,
        config: Arc<ServerConfig>,
        tls: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        self.common.fips = config.fips();

        let mut output = SideCommonOutput {
            side: &mut self.side,
            quic,
            common: &mut self.common,
            tls,
        };

        self.state = Ok(choose.use_config(config, exts, &mut output)?);
        Ok(())
    }
}

impl<Side: SideData> Deref for ConnectionCommon<Side> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl<Side: SideData> DerefMut for ConnectionCommon<Side> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

/// Driver for handling messages from the [`TlsInputBuffer`].
///
/// Must be driven to completion to make progress, by calling either [`Self::handle_all()`] or
/// repeatedly calling [`Self::next_payload()`] until it returns `None`.
///
/// Backpressure is provided by the [`TlsInputBuffer`] implementation. When using a [`VecInput`]
/// buffer, [`VecInput::read()`] will not ingest more data once the internal buffer is full.
#[must_use]
pub struct MessageHandler<'a, 'm, Side: SideData> {
    iter: MessageIter<'a, 'm, Side, SendPath>,
    done: bool,
}

impl<'a, 'm, Side: SideData> MessageHandler<'a, 'm, Side> {
    pub(crate) fn new(
        input: &'m mut dyn TlsInputBuffer,
        tls: &'a mut Vec<u8>,
        core: &'a mut ConnectionCommon<Side>,
    ) -> Self {
        Self {
            iter: MessageIter::new(input, tls, None, core),
            done: false,
        }
    }
}

impl<'a, 'm, Side: SideData> MessageHandler<'a, 'm, Side> {
    /// Handles all complete messages from the input buffer.
    ///
    /// Writes any plaintext application data from the input into `buf`, and returns the I/O
    /// state of the connection after processing the last message. If an error is returned,
    /// the connection is in a fatal error state and no further progress can be made. After
    /// an error is received from this function, you should not continue to fill up the buffer.
    ///
    /// However, you may call the other methods on the connection, including
    /// [`Connection::send_close_notify()`]. Any alert produced by the error will have
    /// been appended to the `tls` buffer; most likely you will want to send that data
    /// to the peer and then close the underlying connection.
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
    ///
    /// Early ("0-RTT") data received by a server while the handshake is still in progress
    /// is not yielded here; it is only available from
    /// [`next_early_data()`][MessageHandler::next_early_data] and is dropped if
    /// encountered by this method.
    pub fn next_payload(&mut self) -> Option<Result<Payload<'_>, Error>> {
        if self.done {
            return None;
        }

        let Some(result) = self.iter.next(false) else {
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
        IoState::new(self.iter.recv)
    }
}

impl<'a, 'm> MessageHandler<'a, 'm, ServerSide> {
    /// Yields the next payload application data received from the client.
    ///
    /// Early data is only received during the handshake, from clients resuming an earlier
    /// session, and only if the connection was configured with a non-zero
    /// [`ServerConfig::max_early_data_size`][crate::ServerConfig::max_early_data_size].
    ///
    /// **Beware** that early data is subject to replay by an attacker; see [RFC 8446
    /// appendix E.5][] for more detail.
    ///
    /// Call this until it returns `None` before processing regular application data with
    /// [`next_payload()`][MessageHandler::next_payload] or
    /// [`handle_all()`][MessageHandler::handle_all]: early data encountered by those
    /// methods is dropped.
    ///
    /// `None` means no early data is currently available: the early data phase may have
    /// ended, or processing may require further input.
    ///
    /// If this yields an error, stop calling it: the same error will also be reported by
    /// [`next_payload()`][MessageHandler::next_payload] and
    /// [`handle_all()`][MessageHandler::handle_all], so it can be ignored here.
    ///
    /// [RFC 8446 appendix E.5]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5
    pub fn next_early_data(&mut self) -> Option<Result<Payload<'_>, Error>> {
        if self.done {
            return None;
        }

        if let Ok(state) = &self.iter.state {
            if state.is_traffic() {
                return None; // early data phase has ended
            }
        }

        let Some(result) = self.iter.next(true) else {
            self.done = true;
            return None;
        };

        let payload = match result {
            Ok(payload) => payload,
            Err(err) => return Some(Err(err)),
        };

        Some(Ok(
            payload.reborrow(&Delocator::new(self.iter.input.slice_mut()))
        ))
    }
}

impl<'a, 'm, Side: SideData + private::Side> Drop for MessageHandler<'a, 'm, Side> {
    fn drop(&mut self) {
        let MessageIter { input, recv, .. } = &mut self.iter;
        input.discard(recv.deframer.take_discard());
    }
}

impl<S: SideData> Debug for MessageHandler<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageHandler")
            .field("done", &self.done)
            .finish_non_exhaustive()
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
    /// See [RFC 5705][] for more details on what this does and is for.  In
    /// other libraries this is often named `SSL_export_keying_material()`
    /// or `SslExportKeyingMaterial()`.
    ///
    /// This function is not meaningful if `output.len()` is zero and will
    /// return an error in that case.
    ///
    /// [RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
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
/// The terminology comes from [RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705)
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
    peer_has_closed: bool,
}

impl IoState {
    pub(crate) fn new(recv: &ReceivePath) -> Self {
        Self {
            peer_has_closed: recv.has_received_close_notify,
        }
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
    pub(crate) tls: &'a mut Vec<u8>,
}

impl<'q> Output<'_> for SideCommonOutput<'_, 'q> {
    fn emit(&mut self, ev: Event) {
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
                .send_msg(m, must_encrypt, self.tls),
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
        fn emit(&mut self, ev: Event);
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
