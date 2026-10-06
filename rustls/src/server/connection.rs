use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use pki_types::{DnsName, FipsStatus};

use super::config::ServerConfig;
use crate::common_state::{CommonState, Event, Side};
use crate::conn::private::SideOutput;
use crate::conn::split::SplitConnection;
use crate::conn::{
    Accepted, Connection, NeedsInput, ServerNext, SideData, Tcp, Transport, VerifyPeerIdentity,
};
#[cfg(doc)]
use crate::crypto;
use crate::error::Error;
use crate::msgs::ServerExtensionsInput;
use crate::quic::{Quic, QuicEvent, ServerHandshake as QuicServerHandshake};
use crate::server::hs::{ExpectClientHello, ReadClientHello, ServerState};
use crate::sync::Arc;
use crate::verify::ClientIdentity;

impl Connection<ServerSide, Tcp> {
    /// Make a new [`ServerSide`] [`Connection`].
    ///
    /// `config` controls how we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Self::for_server(config, ServerExtensionsInput::default(), Tcp)
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
        match &mut self.state {
            Ok(st) => st.set_resumption_data(data),
            Err(e) => Err(e.clone()),
        }
    }
}

impl<T: Transport> Connection<ServerSide, T> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        transport: T,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, config.fips());
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        let protocol = transport.protocol();
        Ok(Self {
            state: Ok(Box::new(ExpectClientHello::new(
                config,
                extra_exts,
                Vec::new(),
                protocol,
            ))
            .into()),
            side: ServerSide::default(),
            transport,
            common,
        })
    }

    pub(crate) fn for_acceptor(transport: T) -> Self {
        Self {
            state: Ok(ReadClientHello::new(transport.protocol()).into()),
            side: ServerSide::default(),
            transport,
            common: CommonState::new(Side::Server, FipsStatus::Unvalidated),
        }
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
        NeedsInput::new(Connection::for_acceptor(Tcp))
    }
}

impl TryFrom<Connection<ServerSide, Tcp>> for ServerHandshake {
    type Error = Error;

    fn try_from(conn: Connection<ServerSide, Tcp>) -> Result<Self, Error> {
        Ok(match ServerNext::try_from(conn)? {
            ServerNext::NeedsInput(conn) => Self::NeedsInput(NeedsInput(conn)),

            ServerNext::ChooseConfig(accepted) => Self::Accepted(accepted),

            ServerNext::VerifyClientIdentity(verify) => Self::VerifyClientIdentity(verify),

            ServerNext::Complete(conn) => Self::Complete(SplitConnection::try_from(conn)?),
        })
    }
}

/// State associated with a server connection.
#[derive(Default)]
pub struct ServerSide {
    sni: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
}

impl ServerSide {
    /// Retrieves the resumption data supplied by the client, if any.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }

    /// Retrieves the server name, if any, used to select the certificate and private key.
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
    pub fn server_name(&self) -> Option<&DnsName<'static>> {
        self.sni.as_ref()
    }
}

impl SideData for ServerSide {
    type Handshake = ServerHandshake;
    type QuicHandshake = QuicServerHandshake;

    type PeerIdentity<'a> = ClientIdentity<'static, 'a>;

    fn tcp_handshake_from_conn(conn: Connection<Self, Tcp>) -> Result<Self::Handshake, Error> {
        ServerHandshake::try_from(conn)
    }

    fn quic_handshake_from_conn(
        conn: Connection<Self, Quic>,
        outputs: &mut Vec<QuicEvent>,
    ) -> Result<Self::QuicHandshake, Error> {
        QuicServerHandshake::from_conn(conn, outputs)
    }
}

impl SideOutput for ServerSide {
    fn emit(&mut self, ev: Event) {
        match ev {
            Event::ReceivedServerName(sni) => self.sni = sni,
            Event::ResumptionData(data) => self.received_resumption_data = Some(data),
            _ => unreachable!(),
        }
    }
}

impl crate::conn::private::Side for ServerSide {
    type State = ServerState;
}

impl fmt::Debug for ServerSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSide")
            .field("sni", &self.sni)
            .finish_non_exhaustive()
    }
}
