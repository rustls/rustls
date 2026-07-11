use alloc::vec::Vec;
use core::ops::Deref;
use core::{fmt, mem};

use pki_types::{EchConfigListBytes, FipsStatus, ServerName};

use super::config::ClientConfig;
use super::hs::{ClientHelloInput, ClientState};
use crate::client::EchStatus;
use crate::client::ech::{EchConfig, EchMode};
use crate::common_state::{CommonState, ConnectionOutputs, EarlyDataEvent, Event, Protocol, Side};
use crate::conn::private::SideOutput;
use crate::conn::split::SplitConnection;
use crate::conn::{
    Connection, ConnectionCommon, KeyingMaterialExporter, MessageHandler, SideCommonOutput,
    SideData, StateMachine, VerifyPeerIdentity,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::enums::ApplicationProtocol;
use crate::error::{ApiMisuse, Error, RejectedEch};
use crate::msgs::{ClientExtensionsInput, TransportParameters};
use crate::quic::{self, ClientConnection as QuicClientConnection, Quic, QuicCommon, QuicOutput};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::tracing::trace;
use crate::verify::ServerIdentity;
use crate::{NeedsInput, TlsInputBuffer};

/// This represents a single TLS client connection.
///
/// Encrypt data destined for the peer using [`Connection::write()`].
/// Process received data from the peer using [`Connection::read_tls()`].
pub struct ClientConnection {
    inner: ConnectionCommon<ClientSide>,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .finish_non_exhaustive()
    }
}

impl ClientConnection {
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
    pub fn split(self) -> Result<SplitConnection<ClientSide>, Error> {
        self.inner.split()
    }

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
    /// can tell this happened using `is_early_data_accepted`.
    pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
        let ConnectionCommon { side, common, .. } = &mut self.inner;
        let early_data = side.early_data.as_mut()?;
        match early_data.state {
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted => {
                Some(WriteEarlyData { early_data, common })
            }
            _ => None,
        }
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.is_early_data_accepted()
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        self.inner.side.ech_status
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner
            .common
            .recv
            .tls13_tickets_received
    }
}

impl Connection for ClientConnection {
    type Side = ClientSide;

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
    ) -> MessageHandler<'a, 'm, ClientSide> {
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

impl Deref for ClientConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Builder for [`ClientConnection`] values.
///
/// Create one with [`ClientConfig::connect()`].
#[derive(Debug)]
pub struct ClientConnectionBuilder {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) name: ServerName<'static>,
    pub(crate) alpn_protocols: Option<Vec<ApplicationProtocol<'static>>>,
    pub(crate) ech_mode: Option<EchMode>,
}

impl ClientConnectionBuilder {
    /// Specify the ALPN protocols to use for this connection.
    pub fn with_alpn(mut self, alpn_protocols: Vec<ApplicationProtocol<'static>>) -> Self {
        self.alpn_protocols = Some(alpn_protocols);
        self
    }

    /// Provide a slice of [`EchConfigListBytes`] configurations to use to
    /// connect using ECH. The slice's elements will be iterated until an ECH
    /// configuration that is compatible with one of the HPKE suites provided
    /// with [`ConfigBuilder::with_ech_hpke_suites`].
    ///
    /// The config list bytes should be sourced from a DNS-over-HTTPS lookup resolving the `HTTPS`
    /// resource record for the host name of the server you wish to connect via ECH,
    /// and extracting the ECH configuration from the `ech` parameter. The extracted bytes should
    /// be base64 decoded to yield the `EchConfigListBytes` you provide to rustls.
    ///
    /// # Errors
    ///
    /// One of the provided ECH configurations must be compatible with the HPKE provider's supported
    /// suites or an [`EncryptedClientHelloError::NoCompatibleConfig`] error will be returned.
    ///
    /// If no ECH HPKE suites were provided with [`ConfigBuilder::with_ech_hpke_suites`],
    /// [`ApiMisuse::NoEchHpkeSuites`] will be returned instead.
    ///
    /// [`ConfigBuilder::with_ech_hpke_suites`]: crate::builder::ConfigBuilder::with_ech_hpke_suites
    /// [`EncryptedClientHelloError::NoCompatibleConfig`]: crate::error::EncryptedClientHelloError::NoCompatibleConfig
    pub fn with_ech(
        mut self,
        ech_config_list_slice: &[EchConfigListBytes<'_>],
    ) -> Result<Self, Error> {
        if self.config.ech_hpke_suites.is_empty() {
            return Err(Error::ApiMisuse(ApiMisuse::NoEchHpkeSuites));
        }

        self.ech_mode = Some(EchMode::from_ech_config_list(
            ech_config_list_slice,
            &self.config.ech_hpke_suites,
        )?);

        Ok(self)
    }

    /// Configure the builder to use ECH GREASE.
    ///
    /// ECH GREASE is a mechanism to make a non-ECH connection appear as if it is one.
    /// This way, the extent to which ECH connections stick out is reduced and
    /// thus, network ossification is mitigated.
    ///
    /// If your client uses ECH but doesn't have a configuration for a server it
    /// wants to connect to, it is recommended per ECH's RFC 9849 to instead
    /// GREASE the connection for the reasons listed above.
    ///
    /// # Note
    ///
    /// In order to not stick out, this method will use the first provided HPKE suite and stick with
    /// it.
    ///
    /// # Errors
    ///
    /// This method will error if the selected HPKE suite (the first one provided with
    /// [`ConfigBuilder::with_ech_hpke_suites`]) fails to generate a placeholder public key.
    ///
    /// If no ECH HPKE suites were provided with [`ConfigBuilder::with_ech_hpke_suites`],
    /// [`ApiMisuse::NoEchHpkeSuites`] will be returned instead.
    ///
    /// [`ConfigBuilder::with_ech_hpke_suites`]: crate::builder::ConfigBuilder::with_ech_hpke_suites
    pub fn with_ech_grease(mut self) -> Result<Self, Error> {
        if self.config.ech_hpke_suites.is_empty() {
            return Err(Error::ApiMisuse(ApiMisuse::NoEchHpkeSuites));
        }

        // just pick the first HPKE suite and stick with it
        //
        // the RFC says that the suites should vary to prevent fingerprinting,
        // but both BoringSSL + NSS seem to do what we do here, so in order to
        // not stick out, we just copy that behavior
        self.ech_mode = Some(EchMode::grease_from_suite(self.config.ech_hpke_suites[0])?);

        Ok(self)
    }

    /// Configure the connection to retry ECH using a config from a server's previous rejection.
    ///
    /// # Errors
    ///
    /// Returns an error if the server provided no retry configurations in [`RejectedEch`], or if
    /// none of the retry configurations are compatible with the HPKE provider's supported suites.
    ///
    /// If no ECH HPKE suites were provided with [`ConfigBuilder::with_ech_hpke_suites`],
    /// [`ApiMisuse::NoEchHpkeSuites`] will be returned instead.
    ///
    /// [`ConfigBuilder::with_ech_hpke_suites`]: crate::builder::ConfigBuilder::with_ech_hpke_suites
    pub fn with_ech_for_retry(mut self, rejection: RejectedEch) -> Result<Self, Error> {
        if self.config.ech_hpke_suites.is_empty() {
            return Err(Error::ApiMisuse(ApiMisuse::NoEchHpkeSuites));
        }

        self.ech_mode = Some(EchMode::Enable(EchConfig::for_retry(
            rejection,
            &self.config.ech_hpke_suites,
        )?));

        Ok(self)
    }

    /// Finalize the builder and create the `ClientConnection`.
    pub fn build(self, tls: &mut Vec<u8>) -> Result<ClientConnection, Error> {
        let Self {
            config,
            name,
            alpn_protocols,
            ech_mode,
        } = self;

        let alpn_protocols = alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone());
        Ok(ClientConnection {
            inner: ConnectionCommon::for_client(
                config,
                name,
                ClientExtensionsInput::from_alpn(alpn_protocols),
                None,
                Protocol::Tcp,
                ech_mode,
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

        let mut quic = Quic {
            version,
            ..Quic::default()
        };

        let mut tls = Vec::new();
        let inner = ConnectionCommon::for_client(
            self.config,
            self.name,
            exts,
            Some(&mut quic),
            Protocol::Quic(version),
            self.ech_mode,
            &mut tls,
        )?;

        // In QUIC mode, handshake output is emitted via `QuicEvent`s, not `tls`.
        debug_assert!(tls.is_empty());
        Ok(QuicClientConnection::from(QuicCommon::new(inner, quic)))
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
            ech_mode,
        } = self;

        let alpn_protocols = alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone());
        Ok(NeedsInput {
            inner: ConnectionCommon::for_client(
                config,
                name,
                ClientExtensionsInput::from_alpn(alpn_protocols),
                None,
                Protocol::Tcp,
                ech_mode,
                tls,
            )?,
        })
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
    VerifyServerIdentity(VerifyPeerIdentity<ClientSide>),

    /// The handshake is complete.
    ///
    /// Now see [`SplitConnection`] to continue the connection.
    Complete(SplitConnection<ClientSide>),
}

impl TryFrom<ConnectionCommon<ClientSide>> for ClientHandshake {
    type Error = Error;

    fn try_from(mut inner: ConnectionCommon<ClientSide>) -> Result<Self, Error> {
        const MISUSED: Error = Error::Unreachable("forgot to restore state");

        Ok(match mem::replace(&mut inner.state, Err(MISUSED))? {
            ClientState::VerifyServerIdentity(verify_identity) => {
                Self::VerifyServerIdentity(VerifyPeerIdentity {
                    inner,
                    verify_identity,
                })
            }

            state if state.is_traffic() => {
                inner.state = Ok(state);
                Self::Complete(SplitConnection::try_from(inner)?)
            }

            state => {
                inner.state = Ok(state);
                Self::NeedsInput(NeedsInput { inner })
            }
        })
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
    /// Encrypt early data as TLS records and encode them into `tls`.
    ///
    /// Yields the number of bytes of `plaintext` that were consumed.  This may be less than
    /// the length of `plaintext` if the server has limited the amount of early data that
    /// may be sent.
    #[must_use]
    pub fn write(&mut self, plaintext: OutboundPlain<'_>, tls: &mut Vec<u8>) -> usize {
        let state = &mut self.early_data;
        let plaintext = match state.state {
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted => {
                let take = Ord::min(plaintext.len(), state.left);
                state.left -= take;
                plaintext.split_at(take).0
            }
            EarlyDataState::AcceptedFinished => return 0,
        };

        self.common
            .send
            .send_appdata_encrypt(plaintext, tls)
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.early_data.left
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
        self.common.early_exporter()
    }
}

impl ConnectionCommon<ClientSide> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extra_exts: ClientExtensionsInput,
        quic: Option<&mut dyn QuicOutput>,
        protocol: Protocol,
        ech_mode: Option<EchMode>,
        tls: &mut Vec<u8>,
    ) -> Result<Self, Error> {
        if ech_mode.is_none() && !config.ech_hpke_suites.is_empty() {
            return Err(Error::ApiMisuse(ApiMisuse::EchNotConfigured));
        }

        let mut common_state = CommonState::new(Side::Client, config.fips());
        common_state
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        let mut data = ClientConnectionData::default();

        let mut output = SideCommonOutput {
            side: &mut data,
            quic,
            common: &mut common_state,
            tls,
        };

        let input =
            ClientHelloInput::new(name, &extra_exts, protocol, &mut output, config, ech_mode)?;
        let state = input.start_handshake(extra_exts, &mut output)?;

        Ok(Self::new(state, data, common_state))
    }

    pub(crate) fn is_early_data_accepted(&self) -> bool {
        matches!(
            &self.side.early_data,
            Some(EarlyData {
                state: EarlyDataState::Accepted | EarlyDataState::AcceptedFinished,
                ..
            })
        )
    }
}

/// State associated with a client connection.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct ClientSide;

impl SideData for ClientSide {
    type Handshake = ClientHandshake;
    type PeerIdentity<'a> = ServerIdentity<'static, 'a>;

    #[expect(private_interfaces)]
    fn handshake_from_inner(common: ConnectionCommon<Self>) -> Result<Self::Handshake, Error> {
        ClientHandshake::try_from(common)
    }
}

impl crate::conn::private::Side for ClientSide {
    type Data = ClientConnectionData;
    type State = ClientState;
}

impl SideOutput for ClientConnectionData {
    fn emit(&mut self, ev: Event<'_>) {
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

#[derive(Default)]
pub(crate) struct ClientConnectionData {
    early_data: Option<EarlyData>,
    ech_status: EchStatus,
}

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
