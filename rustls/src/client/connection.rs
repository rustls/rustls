use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};

use pki_types::ServerName;

use super::config::ClientConfig;
use super::hs::{ClientHelloInput, ClientState};
use crate::client::EchStatus;
use crate::common_state::{CommonState, EarlyDataEvent, Event, Side};
use crate::conn::private::SideOutput;
use crate::conn::split::SplitConnection;
use crate::conn::{
    ClientNext, Connection, DataKind, NeedsInput, SideCommonOutput, SideData, Tcp, Transport,
    VerifyPeerIdentity,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::enums::ApplicationProtocol;
use crate::error::{ApiMisuse, Error};
use crate::msgs::{ClientExtensionsInput, TransportParameters};
use crate::quic::{self, ClientConnection as QuicClientConnection, Quic};
use crate::sync::Arc;
use crate::tracing::trace;
use crate::verify::ServerIdentity;

/// This represents a single TLS client connection.
///
/// Encrypt data destined for the peer using [`Connection::write()`].
/// Process received data from the peer using [`Connection::read_tls()`].
pub struct ClientConnection {
    inner: Connection<ClientSide, Tcp>,
}

impl ClientConnection {
    /// Allows writing TLS1.3 0RTT/"early" data.
    ///
    /// This returns None in many circumstances when the capability to
    /// send early data is not available, including but not limited to:
    ///
    /// - The server hasn't been talked to previously.
    /// - The server does not support resumption.
    /// - The server does not support early data.
    /// - The resumption data for the server has expired.
    ///
    /// The server specifies a maximum amount of early data.  You can
    /// learn this limit through the returned object, and writes through
    /// it will process only this many bytes.
    ///
    /// The server can choose not to accept any sent early data --
    /// in this case the data is lost but the connection continues.  You
    /// can tell this happened using [`ClientSide::is_early_data_accepted()`].
    pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        let Connection { side, common, .. } = &mut self.inner;
        WriteEarlyData::new(&mut side.early_data, common)
    }

    /// Temporary hack to allow access to methods that take [`Connection`] ownership.
    pub fn into_inner(self) -> Connection<ClientSide, Tcp> {
        self.inner
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner
            .common
            .recv
            .tls13_tickets_received
    }
}

impl Deref for ClientConnection {
    type Target = Connection<ClientSide, Tcp>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .finish_non_exhaustive()
    }
}

/// Builder for [`ClientConnection`] values.
///
/// Create one with [`ClientConfig::connect()`].
pub struct ClientConnectionBuilder {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) name: ServerName<'static>,
    pub(crate) alpn_protocols: Option<Vec<ApplicationProtocol<'static>>>,
}

impl ClientConnectionBuilder {
    /// Specify the ALPN protocols to use for this connection.
    pub fn with_alpn(mut self, alpn_protocols: Vec<ApplicationProtocol<'static>>) -> Self {
        self.alpn_protocols = Some(alpn_protocols);
        self
    }

    /// Finalize the builder and create the `ClientConnection`.
    pub fn build(self, tls: &mut Vec<u8>) -> Result<ClientConnection, Error> {
        let Self {
            config,
            name,
            alpn_protocols,
        } = self;

        let alpn_protocols = alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone());
        Ok(ClientConnection {
            inner: Connection::for_client(
                config,
                name,
                ClientExtensionsInput::from_alpn(alpn_protocols),
                Tcp,
                tls,
            )?,
        })
    }

    /// Finalize the builder and create a QUIC `ClientConnection`.
    ///
    /// This differs from `ClientConnectionBuilder::build()` in that it takes an extra `params`
    /// argument, which contains the TLS-encoded transport parameters to send, and an extra
    /// `version` argument, specifying the QUIC protocol version.
    pub fn build_quic(
        self,
        version: quic::Version,
        params: Vec<u8>,
    ) -> Result<QuicClientConnection, Error> {
        let suites = &self
            .config
            .provider()
            .tls13_cipher_suites;
        if suites.is_empty() {
            return Err(ApiMisuse::QuicRequiresTls13Support.into());
        }

        if !suites
            .iter()
            .any(|scs| scs.quic.is_some())
        {
            return Err(ApiMisuse::NoQuicCompatibleCipherSuites.into());
        }

        let exts = ClientExtensionsInput {
            transport_parameters: Some(match version {
                quic::Version::V1 | quic::Version::V2 => {
                    TransportParameters::Quic(Payload::new(params))
                }
            }),

            ..ClientExtensionsInput::from_alpn(
                self.alpn_protocols
                    .unwrap_or_else(|| self.config.alpn_protocols.clone()),
            )
        };

        let quic = Quic {
            version,
            ..Quic::default()
        };

        let mut tls = Vec::new();
        let inner = Connection::for_client(self.config, self.name, exts, quic, &mut tls)?;

        // In QUIC mode, handshake output is emitted via `QuicEvent`s, not `tls`.
        debug_assert!(tls.is_empty());
        Ok(QuicClientConnection::from(inner))
    }

    /// Finalize the builder and create a [`ClientHandshake`].
    ///
    /// It is a fundamental fact of client TLS connections that the client writes first; this data
    /// is written to `tls`.  The client then always reads the server's response, as represented
    /// by the [`NeedsInput`] return value.
    ///
    /// You may wrap this in the [`ClientHandshake::NeedsInput`] variant to generalise the type to a
    /// [`ClientHandshake`].
    ///
    /// The returned object should be fed data from a single server.
    pub fn start_handshake(self, tls: &mut Vec<u8>) -> Result<NeedsInput<ClientSide>, Error> {
        let Self {
            config,
            name,
            alpn_protocols,
        } = self;

        let alpn_protocols = alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone());
        Ok(NeedsInput::new(Connection::for_client(
            config,
            name,
            ClientExtensionsInput::from_alpn(alpn_protocols),
            Tcp,
            tls,
        )?))
    }
}

/// An in-progress TLS client handshake.
///
/// Make one of these using [`ClientConnectionBuilder::start_handshake()`].
#[non_exhaustive]
#[derive(Debug)]
pub enum ClientHandshake {
    /// More data needs to be received to make progress.
    NeedsInput(NeedsInput<ClientSide>),

    /// The server's presented identity must be verified.
    ///
    /// See [`VerifyPeerIdentity`] for how to proceed.
    VerifyServerIdentity(VerifyPeerIdentity<ClientSide, Tcp>),

    /// The handshake is complete.
    ///
    /// Now see [`SplitConnection`] to continue the connection.
    Complete(SplitConnection<ClientSide>),
}

impl TryFrom<Connection<ClientSide, Tcp>> for ClientHandshake {
    type Error = Error;

    fn try_from(conn: Connection<ClientSide, Tcp>) -> Result<Self, Error> {
        Ok(match ClientNext::try_from(conn)? {
            ClientNext::NeedsInput(conn) => Self::NeedsInput(NeedsInput(conn)),

            ClientNext::VerifyServerIdentity(verify) => Self::VerifyServerIdentity(verify),

            ClientNext::Complete(conn) => Self::Complete(SplitConnection::try_from(conn)?),
        })
    }
}

impl NeedsInput<ClientSide> {
    /// Returns an object you can use to send TLS1.3 early data (a.k.a. "0-RTT data")
    /// to the server.
    ///
    /// This returns None in many circumstances when the capability to
    /// send early data is not available, including but not limited to:
    ///
    /// - The server hasn't been talked to previously.
    /// - The server does not support resumption.
    /// - The server does not support early data.
    /// - The resumption data for the server has expired.
    ///
    /// The server specifies a maximum amount of early data.  You can
    /// learn this limit through the returned object, and writes through
    /// it will process only this many bytes.
    ///
    /// The server can choose not to accept any sent early data --
    /// in this case the data is lost but the connection continues.  You
    /// can tell this happened using [`ClientSide::is_early_data_accepted()`].
    pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        let Connection { side, common, .. } = &mut self.0;
        WriteEarlyData::new(&mut side.early_data, common)
    }
}

/// Allows writing of early data in resumed TLS 1.3 connections.
///
/// "Early data" is also known as "0-RTT data".
///
/// Use [`Self::write()`] to encrypt early data into TLS records.
pub struct WriteEarlyData<'a> {
    early_data: &'a mut EarlyData,
    common: &'a mut CommonState,
}

impl<'a> WriteEarlyData<'a> {
    fn new(early_data: &'a mut Option<EarlyData>, common: &'a mut CommonState) -> Option<Self> {
        let early_data = early_data.as_mut()?;

        match early_data.state {
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted => {
                Some(WriteEarlyData { early_data, common })
            }
            _ => None,
        }
    }

    /// Encrypt early data as TLS records and encode them into `tls`.
    ///
    /// Yields the number of bytes of `plaintext` that were consumed.  This may be less than
    /// the length of `plaintext` if the server has limited the amount of early data that
    /// may be sent.
    #[must_use]
    pub fn write(
        &mut self,
        plaintext: OutboundPlain<'_>,
        tls: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        let state = &mut self.early_data;
        let plaintext = match state.state {
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted => {
                let take = Ord::min(plaintext.len(), state.left);
                state.left -= take;
                plaintext.split_at(take).0
            }
            EarlyDataState::AcceptedFinished => return Ok(0),
        };

        self.common
            .send
            .send_appdata_encrypt(DataKind::Early(plaintext), tls)
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.early_data.left
    }
}

impl<T: Transport> Connection<ClientSide, T> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extra_exts: ClientExtensionsInput,
        mut transport: T,
        tls: &mut Vec<u8>,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client, config.fips());
        common_state
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        let mut data = ClientSide::default();

        let protocol = transport.protocol();
        let mut output = SideCommonOutput {
            side: &mut data,
            quic: transport.quic(),
            common: &mut common_state,
            tls,
        };

        let input = ClientHelloInput::new(name, &extra_exts, protocol, &mut output, config)?;
        let state = input.start_handshake(extra_exts, &mut output)?;

        Ok(Self::new(state, data, transport, common_state))
    }
}

/// TLS client-specific information determined during a connection.
#[derive(Debug, Default)]
pub struct ClientSide {
    early_data: Option<EarlyData>,
    ech_status: EchStatus,
}

impl ClientSide {
    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        matches!(
            &self.early_data,
            Some(EarlyData {
                state: EarlyDataState::Accepted | EarlyDataState::AcceptedFinished,
                ..
            })
        )
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        self.ech_status
    }
}

impl SideData for ClientSide {
    type Handshake = ClientHandshake;
    type QuicHandshake = ();

    type PeerIdentity<'a> = ServerIdentity<'static, 'a>;

    fn tcp_handshake_from_conn(conn: Connection<Self, Tcp>) -> Result<Self::Handshake, Error> {
        ClientHandshake::try_from(conn)
    }

    fn quic_handshake_from_conn(
        _core: Connection<Self, Quic>,
        _output: &mut Vec<quic::QuicEvent>,
    ) -> Result<Self::QuicHandshake, Error> {
        todo!("nyi")
    }
}

impl SideOutput for ClientSide {
    fn emit(&mut self, ev: Event) {
        match ev {
            Event::EchStatus(ech) => self.ech_status = ech,
            Event::EarlyData(event) => match (event, &mut self.early_data) {
                (EarlyDataEvent::Enable(sz), None) => self.early_data = Some(EarlyData::new(sz)),
                (EarlyDataEvent::Start, Some(early_data)) => {
                    assert_eq!(early_data.state, EarlyDataState::Ready);
                    early_data.state = EarlyDataState::Sending;
                }
                (EarlyDataEvent::Accepted, Some(early_data)) => {
                    trace!("EarlyData accepted");
                    assert_eq!(early_data.state, EarlyDataState::Sending);
                    early_data.state = EarlyDataState::Accepted;
                }
                (EarlyDataEvent::Rejected, _) => self.early_data = None,
                (EarlyDataEvent::Finished, Some(early_data)) => {
                    trace!("EarlyData finished");
                    early_data.state = match early_data.state {
                        EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
                        _ => panic!("bad EarlyData state"),
                    }
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

impl crate::conn::private::Side for ClientSide {
    type State = ClientState;
}

#[derive(Debug)]
pub(super) struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new(left: usize) -> Self {
        Self {
            state: EarlyDataState::Ready,
            left,
        }
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Ready,
    Sending,
    Accepted,
    AcceptedFinished,
}
