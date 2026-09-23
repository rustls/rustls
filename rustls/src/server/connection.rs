use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

use pki_types::{DnsName, FipsStatus};

use super::config::ServerConfig;
use crate::common_state::{CommonState, ConnectionOutputs, EarlyDataEvent, Event, Protocol, Side};
use crate::conn::private::SideOutput;
use crate::conn::split::SplitConnection;
use crate::conn::{
    Accepted, Connection, ConnectionCommon, Core, KeyingMaterialExporter, MessageHandler,
    NeedsInput, ServerNext, SideData, SideTransport, Tcp, TlsInputBuffer, VerifyPeerIdentity,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::OutboundPlain;
use crate::error::Error;
use crate::msgs::ServerExtensionsInput;
use crate::quic::{Quic, ServerHandshake as QuicServerHandshake};
use crate::server::hs::{ExpectClientHello, ReadClientHello, ServerState};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::verify::ClientIdentity;

/// This represents a single TLS server connection.
///
/// Encrypt data destined for the peer using [`Connection::write()`].
/// Process received data from the peer using [`Connection::read_tls()`].
pub struct ServerConnection {
    pub(super) inner: ConnectionCommon<ServerSide>,
}

impl ServerConnection {
    /// Make a new ServerConnection.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCommon::for_server(
                config,
                ServerExtensionsInput::default(),
                Protocol::Tcp,
            )?,
        })
    }

    /// Split a post-handshake connection into a [`SplitConnection`].
    ///
    /// This allows the two directions (transmit and receive) of the connection to be progressed
    /// separately (including by different threads, which would allow dedicating a CPU core for each
    /// direction rather than one per connection; this can dramatically improve performance for
    /// full-duplex protocols).
    ///
    /// It also separates out the [`ConnectionOutputs`] which gives the application direct control
    /// of how long this is kept.
    ///
    /// This fails if:
    ///
    /// - the handshake is not complete. Check with [`Connection::is_handshaking()`].
    /// - there is any buffered TLS data to send.  Obtain it first with [`Connection::write()`].
    pub fn split(self) -> Result<SplitConnection<ServerSide>, Error> {
        self.inner.split()
    }

    /// Retrieves the server name, if any, used to select the certificate and
    /// private key.
    ///
    /// This returns `None` until some time after the client's server name indication
    /// (SNI) extension value is processed during the handshake. It will never be
    /// `None` when the connection is ready to send or process application data,
    /// unless the client does not support SNI.
    ///
    /// This is useful for application protocols that need to enforce that the
    /// server name matches an application layer protocol hostname. For
    /// example, HTTP/1.1 servers commonly expect the `Host:` header field of
    /// every request on a connection to match the hostname in the SNI extension
    /// when the client provides the SNI extension.
    ///
    /// The server name is also used to match sessions during session resumption.
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        self.inner.side.server_name()
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner
            .side
            .received_resumption_data()
    }

    /// Set the resumption data to embed in future resumption tickets supplied to the client.
    ///
    /// Defaults to the empty byte string. Must be less than 2^15 bytes to allow room for other
    /// data. Should be called while `is_handshaking` returns true to ensure all transmitted
    /// resumption tickets are affected.
    ///
    /// Integrity will be assured by rustls, but the data will be visible to the client. If secrecy
    /// from the client is desired, encrypt the data separately.
    pub fn set_resumption_data(&mut self, data: &[u8]) -> Result<(), Error> {
        assert!(data.len() < 2usize.pow(15));
        match &mut self.inner.state {
            Ok(st) => st.set_resumption_data(data),
            Err(e) => Err(e.clone()),
        }
    }

    /// Returns a handle to TLS1.3 0RTT/"early" data facilities if the client's early
    /// data offer was accepted.
    ///
    /// The early data itself is read via [`MessageHandler::next_early_data()`] while
    /// processing input; this handle gives access to the "early" keying material exporter.
    ///
    /// This returns `None` in many circumstances, such as :
    ///
    /// - Early data is disabled if [`ServerConfig::max_early_data_size`] is zero (the default).
    /// - The session negotiated with the client is not TLS1.3.
    /// - The client just doesn't support early data.
    /// - The connection doesn't resume an existing session.
    /// - The client hasn't sent a full ClientHello yet.
    pub fn early_data(&mut self) -> Option<ReadEarlyData<'_>> {
        if self
            .inner
            .side
            .early_data
            .was_accepted()
        {
            Some(ReadEarlyData::new(&mut self.inner))
        } else {
            None
        }
    }
}

impl Connection for ServerConnection {
    type Side = ServerSide;

    fn write(&mut self, plaintext: OutboundPlain<'_>, tls: &mut Vec<u8>) -> Result<(), Error> {
        self.inner.write(plaintext, tls)
    }

    fn wants_read(&self) -> bool {
        self.inner.wants_read()
    }

    fn read_tls<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        tls: &'a mut Vec<u8>,
    ) -> MessageHandler<'a, 'm, ServerSide> {
        self.inner.read_tls(input, tls)
    }

    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.inner.exporter()
    }

    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }

    fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        self.inner.refresh_traffic_keys(tls)
    }

    fn send_close_notify(&mut self, tls: &mut Vec<u8>) {
        self.inner.send_close_notify(tls);
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn fips(&self) -> FipsStatus {
        self.inner.fips
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .finish_non_exhaustive()
    }
}

impl ConnectionCommon<ServerSide> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, config.fips());
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        Ok(Self::new(
            Box::new(ExpectClientHello::new(
                config,
                extra_exts,
                Vec::new(),
                protocol,
            ))
            .into(),
            ServerConnectionData::default(),
            common,
        ))
    }

    pub(crate) fn for_acceptor(protocol: Protocol) -> Self {
        Self::new(
            ReadClientHello::new(protocol).into(),
            ServerConnectionData::default(),
            CommonState::new(Side::Server, FipsStatus::Unvalidated),
        )
    }
}

/// An in-progress TLS server handshake.
#[non_exhaustive]
#[derive(Debug)]
pub enum ServerHandshake {
    /// More data needs to be received to make progress.
    NeedsInput(NeedsInput<ServerSide>),

    /// A complete `ClientHello` has been received.
    ///
    /// The handshake can be progressed by choosing a [`ServerConfig`] based on
    /// [`Accepted::client_hello()`] and providing it to [`Accepted::choose_config()`].
    Accepted(Accepted<Tcp>),

    /// The client's presented identity must be verified.
    ///
    /// See [`VerifyPeerIdentity`] for how to proceed.
    VerifyClientIdentity(VerifyPeerIdentity<ServerSide, Tcp>),

    /// The handshake is complete.
    ///
    /// Now see [`SplitConnection`] to continue the connection.
    Complete(SplitConnection<ServerSide>),
}

impl ServerHandshake {
    /// Creates a new [`ServerHandshake`] via the payload of the [`ServerHandshake::NeedsInput`] variant.
    ///
    /// It is a fundamental fact of server TLS connections that the server reads first; this is reflected
    /// in the returned type.
    ///
    /// You may wrap this in the [`ServerHandshake::NeedsInput`] variant to generalise the type to a
    /// [`ServerHandshake`].
    ///
    /// The returned object should be fed data from a single potential client.
    pub fn start() -> NeedsInput<ServerSide> {
        NeedsInput::new(ConnectionCommon::for_acceptor(Protocol::Tcp))
    }
}

impl TryFrom<Core<ServerSide, Tcp>> for ServerHandshake {
    type Error = Error;

    fn try_from(core: Core<ServerSide, Tcp>) -> Result<Self, Error> {
        Ok(match ServerNext::try_from(core)? {
            ServerNext::NeedsInput(core) => Self::NeedsInput(NeedsInput(core)),

            ServerNext::ChooseConfig(accepted) => Self::Accepted(accepted),

            ServerNext::VerifyClientIdentity(verify) => Self::VerifyClientIdentity(verify),

            ServerNext::Complete(core) => Self::Complete(SplitConnection::try_from(core.inner)?),
        })
    }
}

/// State associated with a server connection.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct ServerSide;

impl SideData for ServerSide {
    type PeerIdentity<'a> = ClientIdentity<'static, 'a>;
}

impl SideTransport<Tcp> for ServerSide {
    type Handshake = ServerHandshake;

    #[expect(private_interfaces)]
    fn handshake_from_core(core: Core<Self, Tcp>) -> Result<Self::Handshake, Error> {
        ServerHandshake::try_from(core)
    }
}

impl SideTransport<Quic> for ServerSide {
    type Handshake = QuicServerHandshake;

    #[expect(private_interfaces)]
    fn handshake_from_core(core: Core<Self, Quic>) -> Result<Self::Handshake, Error> {
        QuicServerHandshake::from_core(core)
    }
}

impl crate::conn::private::Side for ServerSide {
    type Data = ServerConnectionData;
    type State = ServerState;
}

/// State associated with a server connection.
#[derive(Default)]
pub(crate) struct ServerConnectionData {
    sni: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
    early_data: EarlyDataState,
}

impl ServerConnectionData {
    pub(crate) fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }

    pub(crate) fn server_name(&self) -> Option<&DnsName<'static>> {
        self.sni.as_ref()
    }
}

impl SideOutput for ServerConnectionData {
    fn emit(&mut self, ev: Event) {
        match ev {
            Event::EarlyData(EarlyDataEvent::Accepted) => self.early_data.accept(),
            Event::ReceivedServerName(sni) => self.sni = sni,
            Event::ResumptionData(data) => self.received_resumption_data = Some(data),
            _ => unreachable!(),
        }
    }
}

/// Access to early data facilities in resumed TLS1.3 connections.
///
/// "Early data" is also known as "0-RTT data".
///
/// The early data itself is read via [`MessageHandler::next_early_data()`]; this
/// type provides the matching "early" keying material exporter.
pub struct ReadEarlyData<'a> {
    common: &'a mut ConnectionCommon<ServerSide>,
}

impl<'a> ReadEarlyData<'a> {
    fn new(common: &'a mut ConnectionCommon<ServerSide>) -> Self {
        ReadEarlyData { common }
    }

    /// Returns the "early" exporter that can derive key material for use in early data
    ///
    /// See [RFC 5705][] for general details on what exporters are, and [RFC 9846 S7.5][] for
    /// specific details on the "early" exporter.
    ///
    /// **Beware** that the early exporter requires care, as it is subject to the same
    /// potential for replay as early data itself.  See [RFC 9846 appendix F.5.1][] for
    /// more detail.
    ///
    /// This function can be called at most once per connection. This function will error:
    /// if called more than once per connection.
    ///
    /// If you are looking for the normal exporter, this is available from
    /// [`Connection::exporter()`].
    ///
    /// [RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
    /// [RFC 9846 S7.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-7.5
    /// [RFC 9846 appendix F.5.1]: https://datatracker.ietf.org/doc/html/rfc9846#appendix-F.5.1
    /// [`Connection::exporter()`]: crate::conn::Connection::exporter()
    pub fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.common.common.early_exporter()
    }
}

#[derive(Default)]
pub(super) enum EarlyDataState {
    #[default]
    New,
    Accepted,
}

impl EarlyDataState {
    fn accept(&mut self) {
        *self = Self::Accepted;
    }

    fn was_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}
