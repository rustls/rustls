use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;

use pki_types::DnsName;

use super::config::{CipherSuiteSelector, OfferedKxGroup, VersionSuiteSelector};
use super::tls13::{FirstClientHello, handle_retried_client_hello};
use super::{ClientHello, ServerConfig};
use crate::SupportedCipherSuite;
use crate::common_state::{Event, Output, OutputEvent, Protocol};
use crate::conn::{ConnectionRandoms, Input, State, VerifySidePeerIdentity};
use crate::crypto::cipher::Payload;
use crate::crypto::hash::Hash;
use crate::crypto::kx::{KeyExchangeAlgorithm, NamedGroup, SupportedKxGroup};
use crate::crypto::{CipherSuite, CryptoProvider, SelectedCredential, SignatureScheme};
use crate::enums::{ApplicationProtocol, CertificateType, HandshakeType, ProtocolVersion};
use crate::error::{ApiMisuse, Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::kernel::KernelState;
use crate::msgs::{
    ClientHelloPayload, Compression, EncryptedExtensions, HandshakeAlignedProof,
    HandshakeMessagePayload, HandshakePayload, KeyShareEntry, Message, MessagePayload, Random,
    ServerExtensions, ServerExtensionsInput, ServerNamePayload, ServerTicketRequestHint, SessionId,
    SingleProtocolName, TransportParameters,
};
use crate::sealed::Sealed;
use crate::server::ServerSide;
use crate::suites::{PartiallyExtractedSecrets, Suite};
use crate::sync::Arc;
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::tracing::{debug, trace};

pub(crate) enum ServerState {
    /// Reading an entire ClientHello
    ///
    /// Validations that do not rely on a config can be performed here, but most are
    /// deferred until [`ServerState::ClientHello`].
    ReadClientHello(ReadClientHello),

    /// Choose a [`ServerConfig`] based on the received ClientHello.
    ChooseConfig(Box<ChooseConfig>),

    /// Processing the received ClientHello.
    ClientHello(Box<ExpectClientHello>),

    /// Verifying the client's present certificate chain.
    VerifyClientIdentity(Box<dyn VerifySidePeerIdentity<ServerSide>>),

    Tls12(Box<dyn State<ServerSide>>),
    Tls13(Box<dyn State<ServerSide>>),
}

impl ServerState {
    pub(crate) fn set_resumption_data(&mut self, resumption_data: &[u8]) -> Result<(), Error> {
        match self {
            Self::ReadClientHello(e) => e.set_resumption_data(resumption_data),
            Self::ChooseConfig(e) => e.set_resumption_data(resumption_data),
            Self::ClientHello(e) => e.set_resumption_data(resumption_data),
            _ => Err(ApiMisuse::ResumptionDataProvidedTooLate.into()),
        }
    }
}

impl crate::conn::StateMachine for ServerState {
    fn handle<'m>(self, input: Input<'m>, output: &mut dyn Output<'m>) -> Result<Self, Error> {
        match self {
            Self::ReadClientHello(r) => r.handle(input, output),
            Self::ChooseConfig(_) | Self::VerifyClientIdentity(_) => {
                Err(Error::Unreachable("state cannot process a message"))
            }
            Self::ClientHello(e) => e.handle(input, output),
            Self::Tls12(sm) => sm.handle(input, output),
            Self::Tls13(sm) => sm.handle(input, output),
        }
    }

    fn wants_input(&self) -> bool {
        !matches!(self, Self::ChooseConfig(_) | Self::VerifyClientIdentity(_))
    }

    fn handle_without_input(self, output: &mut dyn Output<'_>) -> Result<Self, Error> {
        match self {
            Self::VerifyClientIdentity(vci) => {
                let verified = vci.verify_with_config()?;
                vci.continue_with(verified, output)
            }
            _ => Ok(self),
        }
    }

    fn is_traffic(&self) -> bool {
        match self {
            Self::Tls12(sm) | Self::Tls13(sm) => sm.is_traffic(),
            _ => false,
        }
    }

    fn handle_decrypt_error(&mut self) {
        if let Self::Tls12(sm) | Self::Tls13(sm) = self {
            sm.handle_decrypt_error();
        }
    }

    fn into_external_state(
        self,
        send_keys: &Option<Box<KeyScheduleTrafficSend>>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        match self {
            Self::Tls12(sm) | Self::Tls13(sm) => sm.into_external_state(send_keys),
            _ => Err(Error::HandshakeNotComplete),
        }
    }
}

pub(super) struct Tls12Extensions {
    pub(super) common: CommonExtensions,
    resuming: bool,
    renegotiation_info_ack: bool,
    session_ticket_ack: bool,
    extended_main_secret_ack: bool,
    certificate_status_request_ack: bool,
}

impl Tls12Extensions {
    pub(super) fn new(
        hello: &ClientHelloPayload,
        extra_exts: ServerExtensionsInput,
        ocsp_response: &mut Option<&[u8]>,
        resuming: bool,
        using_ems: bool,
        config: &ServerConfig,
    ) -> Result<Self, Error> {
        let common = CommonExtensions::new(hello, extra_exts, config)?;

        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        //
        // RFC 5746 section 3.6: `renegotiated_connection` must be empty in an
        // initial handshake.  A non-empty value means the client believes it is
        // renegotiating an existing connection.
        if hello
            .renegotiation_info
            .as_ref()
            .is_some_and(|info| !info.is_empty())
        {
            return Err(PeerMisbehaved::NonEmptyRenegotiationInfo.into());
        }

        let renegotiation_info_ack = hello.renegotiation_info.is_some()
            || hello
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        // Discard OCSP response if it is not necessary.
        if resuming || !common.ocsp_requested {
            ocsp_response.take();
        }

        Ok(Self {
            common,
            resuming,
            renegotiation_info_ack,
            // Tickets:
            // If we get any SessionTicket extension and have tickets enabled,
            // we send an ack.
            session_ticket_ack: hello.session_ticket.is_some() && config.ticketer.is_some(),
            extended_main_secret_ack: using_ems,
            certificate_status_request_ack: matches!(ocsp_response, Some([_, ..])),
        })
    }

    pub(super) fn send_ticket(&self) -> bool {
        self.session_ticket_ack
    }

    pub(super) fn into_response(
        self,
        output: &mut dyn Output<'_>,
    ) -> Box<ServerExtensions<'static>> {
        let Self {
            common,
            resuming,
            renegotiation_info_ack,
            session_ticket_ack,
            extended_main_secret_ack,
            certificate_status_request_ack,
        } = self;
        let common = common.into_response(resuming, output);

        Box::new(ServerExtensions {
            server_name_ack: common.server_name_ack,
            selected_protocol: common.selected_protocol,
            transport_parameters: common.transport_parameters,
            renegotiation_info: renegotiation_info_ack.then(|| Vec::new().into()),
            session_ticket_ack: session_ticket_ack.then_some(()),
            extended_main_secret_ack: extended_main_secret_ack.then_some(()),
            certificate_status_request_ack: certificate_status_request_ack.then_some(()),
            ..ServerExtensions::default()
        })
    }
}

/// TLS 1.3 extension decisions, made from a `ClientHello`.
///
/// Decisions that may differ after a HelloRetryRequest are instead in
/// [`Tls13RetryableExtensions`].
pub(super) struct Tls13Extensions {
    pub(super) common: CommonExtensions,
    pub(super) certificate_types: CertificateTypes,
    client_certificate_type_ack: Option<CertificateType>,
    server_certificate_type_ack: Option<CertificateType>,
}

impl Tls13Extensions {
    pub(super) fn new(
        hello: &ClientHelloPayload,
        extra_exts: ServerExtensionsInput,
        output: &mut dyn Output<'_>,
        config: &ServerConfig,
    ) -> Result<Self, Error> {
        let common = CommonExtensions::new(hello, extra_exts, config)?;

        let expected_client_type = select_cert_type(
            hello
                .client_certificate_types
                .as_deref(),
            config
                .verifier
                .supported_certificate_types(),
        )?;

        let expected_server_type = select_cert_type(
            hello
                .server_certificate_types
                .as_deref(),
            config
                .cert_resolver
                .supported_certificate_types(),
        )?;

        if let Some(quic) = output.quic() {
            // RFC9001: "When using ALPN, endpoints MUST immediately close a connection
            // (...) if an application protocol is not negotiated."
            if !matches!(
                common.alpn,
                AlpnDecision::Selected(_) | AlpnDecision::Disabled
            ) {
                return Err(Error::NoApplicationProtocol);
            }
            match hello.transport_parameters.as_ref() {
                Some(params) => quic.transport_parameters(params.to_owned().into_vec()),
                None => {
                    return Err(PeerMisbehaved::MissingQuicTransportParameters.into());
                }
            }
        }

        Ok(Self {
            common,
            certificate_types: CertificateTypes {
                client: expected_client_type,
            },
            client_certificate_type_ack: (hello.client_certificate_types.is_some()
                && config.verifier.offer_client_auth())
            .then_some(expected_client_type),
            server_certificate_type_ack: hello
                .server_certificate_types
                .is_some()
                .then_some(expected_server_type),
        })
    }

    pub(super) fn into_response(
        self,
        retryable: Tls13RetryableExtensions,
        output: &mut dyn Output<'_>,
    ) -> Box<EncryptedExtensions<'static>> {
        let Self {
            common,
            certificate_types: _,
            client_certificate_type_ack,
            server_certificate_type_ack,
        } = self;
        let Tls13RetryableExtensions {
            resuming,
            early_data_ack,
            ticket_request,
        } = retryable;
        let common = common.into_response(resuming, output);

        Box::new(EncryptedExtensions {
            server_name_ack: common.server_name_ack,
            selected_protocol: common.selected_protocol,
            transport_parameters: common.transport_parameters,
            client_certificate_type: client_certificate_type_ack,
            server_certificate_type: server_certificate_type_ack,
            early_data_ack: early_data_ack.then_some(()),
            ticket_request,
            ..EncryptedExtensions::default()
        })
    }
}

/// TLS 1.3 extension decisions that may differ after a HelloRetryRequest.
///
/// These are made from the `ClientHello` that leads to the `ServerHello`.
pub(super) struct Tls13RetryableExtensions {
    pub(super) resuming: bool,
    pub(super) early_data_ack: bool,
    pub(super) ticket_request: Option<ServerTicketRequestHint>,
}

/// Extension decisions common to TLS 1.2 and TLS 1.3, taken from one `ClientHello`.
pub(super) struct CommonExtensions {
    alpn: AlpnDecision,
    sni_offered: bool,
    pub(super) ocsp_requested: bool,
    transport_parameters: Option<Payload<'static>>,
}

impl CommonExtensions {
    fn new(
        hello: &ClientHelloPayload,
        extra_exts: ServerExtensionsInput,
        config: &ServerConfig,
    ) -> Result<Self, Error> {
        // ALPN
        let our_protocols = &config.alpn_protocols;
        let alpn = match (&hello.protocols, our_protocols.as_slice()) {
            (Some(their_protocols), [_, ..]) => {
                let selected_protocol = our_protocols
                    .iter()
                    .find(|ours| {
                        their_protocols
                            .iter()
                            .any(|theirs| theirs.as_ref() == ours.as_ref())
                    })
                    .ok_or(Error::NoApplicationProtocol)?;
                debug!("Chosen ALPN protocol {selected_protocol:?}");

                AlpnDecision::Selected(SingleProtocolName::new(selected_protocol.to_owned()))
            }
            (None, []) => AlpnDecision::Disabled,
            (_, []) => AlpnDecision::NoServerOffer,
            (None, _) => AlpnDecision::NoClientOffer,
        };

        let ServerExtensionsInput {
            transport_parameters,
        } = extra_exts;

        Ok(Self {
            alpn,
            sni_offered: matches!(hello.server_name, Some(ServerNamePayload::SingleDnsName(_))),
            ocsp_requested: hello
                .certificate_status_request
                .is_some(),
            transport_parameters: transport_parameters.map(|TransportParameters::Quic(v)| v),
        })
    }

    pub(super) fn alpn_protocol(&self) -> Option<&ApplicationProtocol<'static>> {
        let AlpnDecision::Selected(protocol) = &self.alpn else {
            return None;
        };

        Some(protocol.as_ref())
    }

    fn into_response(self, resuming: bool, output: &mut dyn Output<'_>) -> CommonResponse {
        let Self {
            alpn,
            sni_offered,
            ocsp_requested: _,
            transport_parameters,
        } = self;

        if let AlpnDecision::Selected(protocol) = &alpn {
            output.output(OutputEvent::ApplicationProtocol(protocol.as_ref().clone()));
        }

        CommonResponse {
            server_name_ack: (sni_offered && !resuming).then_some(()),
            selected_protocol: alpn.into(),
            transport_parameters,
        }
    }
}

#[derive(Default)]
enum AlpnDecision {
    #[default]
    Disabled,
    Selected(SingleProtocolName),
    NoServerOffer,
    NoClientOffer,
}

impl From<AlpnDecision> for Option<SingleProtocolName> {
    fn from(value: AlpnDecision) -> Self {
        match value {
            AlpnDecision::Selected(protocol) => Some(protocol),
            _ => None,
        }
    }
}

/// Extension values common to both TLS 1.2 ServerHello & TLS 1.3 EncryptedExtensions.
struct CommonResponse {
    server_name_ack: Option<()>,
    selected_protocol: Option<SingleProtocolName>,
    transport_parameters: Option<Payload<'static>>,
}

fn select_cert_type(
    client: Option<&[CertificateType]>,
    server: &[CertificateType],
) -> Result<CertificateType, Error> {
    if server.is_empty() {
        return Err(ApiMisuse::NoSupportedCertificateTypes.into());
    }

    // https://www.rfc-editor.org/info/rfc7250#section-4.1
    // If the client has no remaining certificate types to send in
    // the client hello, other than the default X.509 type, it MUST omit the
    // client_certificate_type extension in the client hello.

    // If the client has no remaining certificate types to send in
    // the client hello, other than the default X.509 certificate type, it
    // MUST omit the entire server_certificate_type extension from the
    // client hello.
    let client = match client {
        Some([]) => {
            return Err(PeerIncompatible::IncorrectCertificateTypeExtension.into());
        }
        Some(c) => c,
        None => {
            return match server.contains(&CertificateType::X509) {
                true => Ok(CertificateType::X509),
                false => Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
            };
        }
    };

    for &ct in client {
        if server.contains(&ct) {
            return Ok(ct);
        }
    }

    Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
}

pub(super) struct CertificateTypes {
    pub(super) client: CertificateType,
}

pub(crate) struct ReadClientHello {
    protocol: Protocol,
    resumption_data: Vec<u8>,
}

impl ReadClientHello {
    pub(crate) fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            resumption_data: Vec::new(),
        }
    }

    pub(crate) fn handle<'m>(
        self,
        input: Input<'m>,
        _output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error> {
        ClientHelloInput::from_input(&input)?;
        Ok(Box::new(ChooseConfig {
            client_hello: Input {
                message: input.message.into_owned(),
                aligned_handshake: input.aligned_handshake,
            },
            resumption_data: self.resumption_data,
            protocol: self.protocol,
        })
        .into())
    }

    fn set_resumption_data(&mut self, resumption_data: &[u8]) -> Result<(), Error> {
        self.resumption_data = resumption_data.to_vec();
        Ok(())
    }
}

impl From<ReadClientHello> for ServerState {
    fn from(value: ReadClientHello) -> Self {
        Self::ReadClientHello(value)
    }
}

pub(crate) struct ChooseConfig {
    protocol: Protocol,
    resumption_data: Vec<u8>,
    client_hello: Input<'static>,
}

impl ChooseConfig {
    pub(crate) fn use_config(
        self,
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error> {
        ExpectClientHello::new(config, extra_exts, self.resumption_data, self.protocol)
            .with_input(ClientHelloInput::from_input(&self.client_hello)?, output)
    }

    pub(crate) fn client_hello(&self) -> ClientHello<'_> {
        let MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(client_hello)),
            ..
        } = &self.client_hello.message.payload
        else {
            unreachable!();
        };

        let server_name = client_hello
            .server_name
            .as_ref()
            .and_then(ServerNamePayload::to_dns_name_normalized)
            .map(Cow::Owned);

        ClientHello::new(client_hello, None, server_name, None)
    }

    fn set_resumption_data(&mut self, resumption_data: &[u8]) -> Result<(), Error> {
        self.resumption_data = resumption_data.to_vec();
        Ok(())
    }
}

impl From<Box<ChooseConfig>> for ServerState {
    fn from(value: Box<ChooseConfig>) -> Self {
        Self::ChooseConfig(value)
    }
}

pub(crate) struct ExpectClientHello {
    pub(super) config: Arc<ServerConfig>,
    pub(super) protocol: Protocol,
    pub(super) extra_exts: ServerExtensionsInput,
    pub(super) transcript: HandshakeHashOrBuffer,
    pub(super) session_id: SessionId,
    pub(super) sni: Option<DnsName<'static>>,
    pub(super) resumption_data: Vec<u8>,
    pub(super) using_ems: bool,
    pub(super) previous_hello: Option<Box<FirstClientHello>>,
    pub(super) send_tickets: usize,
}

impl ExpectClientHello {
    pub(super) fn new(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        resumption_data: Vec<u8>,
        protocol: Protocol,
    ) -> Self {
        let mut transcript_buffer = HandshakeHashBuffer::new();

        if config.verifier.offer_client_auth() {
            transcript_buffer.set_client_auth_enabled();
        }

        Self {
            config,
            protocol,
            extra_exts,
            transcript: HandshakeHashOrBuffer::Buffer(transcript_buffer),
            session_id: SessionId::empty(),
            sni: None,
            resumption_data,
            using_ems: false,
            previous_hello: None,
            send_tickets: 0,
        }
    }

    /// Continues handling of a `ClientHello` message once config and certificate are available.
    pub(super) fn with_input(
        self,
        input: ClientHelloInput<'_>,
        output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error> {
        let tls13_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_3, self.protocol);
        let tls12_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_2, self.protocol);

        // Are we doing TLS1.3?
        if let Some(versions) = &input.client_hello.supported_versions {
            if versions.tls13 && tls13_enabled {
                self.with_version::<Tls13CipherSuite>(input, output)
            } else if !versions.tls12 || !tls12_enabled {
                Err(PeerIncompatible::Tls12NotOfferedOrEnabled.into())
            } else if self.protocol.is_quic() {
                Err(PeerIncompatible::Tls13RequiredForQuic.into())
            } else {
                self.with_version::<Tls12CipherSuite>(input, output)
            }
        } else if u16::from(input.client_hello.client_version) < u16::from(ProtocolVersion::TLSv1_2)
        {
            Err(PeerIncompatible::Tls12NotOffered.into())
        } else if self.protocol.is_quic() {
            Err(PeerIncompatible::Tls13RequiredForQuic.into())
        } else if !tls12_enabled && tls13_enabled {
            Err(PeerIncompatible::SupportedVersionsExtensionRequired.into())
        } else {
            self.with_version::<Tls12CipherSuite>(input, output)
        }
    }

    fn with_version<T: Suite + 'static>(
        mut self,
        input: ClientHelloInput<'_>,
        output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error>
    where
        CryptoProvider: Borrow<[&'static T]>,
        SupportedCipherSuite: From<&'static T>,
        dyn CipherSuiteSelector: VersionSuiteSelector<T>,
    {
        output.output(OutputEvent::ProtocolVersion(T::VERSION));

        let sni = self
            .config
            .invalid_sni_policy
            .accept(input.client_hello.server_name.as_ref())?;
        output.emit(Event::ReceivedServerName(sni.clone()));

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let suites = <CryptoProvider as Borrow<[&'static T]>>::borrow(&self.config.provider);

        let mut sig_schemes = input.sig_schemes.to_owned();
        T::filter_signature_schemes(&mut sig_schemes, &input.client_hello.cipher_suites, suites);

        // Choose a certificate.
        let credentials = self
            .config
            .cert_resolver
            .resolve(&ClientHello::new(
                input.client_hello,
                Some(&sig_schemes),
                sni.as_ref().map(Cow::Borrowed),
                Some(T::VERSION),
            ))?;
        self.sni = sni;

        let (suite, skxg) = self.choose_suite_and_kx_group(
            suites,
            credentials.signer.scheme(),
            input
                .client_hello
                .named_groups
                .as_deref()
                .unwrap_or_default(),
            input
                .client_hello
                .key_shares
                .as_deref()
                .unwrap_or_default(),
            &input.client_hello.cipher_suites,
        )?;

        debug!("decided upon suite {suite:?}");
        output.output(OutputEvent::CipherSuite(suite.into()));

        suite
            .server_handler()
            .handle_client_hello(suite, skxg, credentials, input, self, output)
    }

    fn choose_suite_and_kx_group<T: Suite + 'static>(
        &self,
        suites: &[&'static T],
        sig_scheme: SignatureScheme,
        client_groups: &[NamedGroup],
        client_shares: &[KeyShareEntry],
        client_suites: &[CipherSuite],
    ) -> Result<(&'static T, &'static dyn SupportedKxGroup), Error>
    where
        SupportedCipherSuite: From<&'static T>,
        dyn CipherSuiteSelector: VersionSuiteSelector<T>,
    {
        // Determine which `KeyExchangeAlgorithm`s are theoretically possible, based
        // on the offered and supported groups.
        let mut ecdhe_possible = false;
        let mut ffdhe_possible = false;
        let mut ffdhe_offered = false;

        for offered_group in client_groups {
            let supported = self
                .config
                .provider
                .find_kx_group(*offered_group, T::VERSION)
                .is_some();

            match offered_group.key_exchange_algorithm() {
                KeyExchangeAlgorithm::DHE => {
                    ffdhe_possible |= supported;
                    ffdhe_offered = true;
                }
                KeyExchangeAlgorithm::ECDHE => {
                    ecdhe_possible |= supported;
                }
            }
        }

        let first_supported_dhe_kxg = if T::VERSION == ProtocolVersion::TLSv1_2 {
            // https://www.rfc-editor.org/info/rfc7919#section-4 (paragraph 2)
            let first_supported_dhe_kxg = self
                .config
                .provider
                .kx_groups
                .iter()
                .find(|skxg| skxg.name().key_exchange_algorithm() == KeyExchangeAlgorithm::DHE);
            ffdhe_possible |= !ffdhe_offered && first_supported_dhe_kxg.is_some();
            first_supported_dhe_kxg
        } else {
            // In TLS1.3, the server may only directly negotiate a group.
            None
        };

        if !ecdhe_possible && !ffdhe_possible {
            return Err(PeerIncompatible::NoKxGroupsInCommon.into());
        }

        // RFC 7919 (https://www.rfc-editor.org/info/rfc7919#section-4) requires us to send
        // the InsufficientSecurity alert in case we don't recognize client's FFDHE groups (i.e.,
        // `suitable_suites` becomes empty). But that does not make a lot of sense (e.g., client
        // proposes FFDHE4096 and we only support FFDHE2048), so we ignore that requirement here,
        // and continue to send HandshakeFailure.

        let mut client_suites = client_suites
            .iter()
            .filter_map(|&suite| {
                let &suite = suites
                    .iter()
                    .find(|ss| ss.suite() == suite)?;

                // Reduce our supported ciphersuites by the certified key's algorithm.
                (suite.usable_for_signature_scheme(sig_scheme)
                // And usable by the current protocol
                && suite.usable_for_protocol(self.protocol)
                // And support for one of the key exchange groups
                && (ecdhe_possible && suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::ECDHE)
                || ffdhe_possible && suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::DHE)))
                .then_some(suite)
            });

        let suite = self
            .config
            .cipher_suite_selector
            .select(&mut client_suites, suites)
            .ok_or(PeerIncompatible::NoCipherSuitesInCommon)?;

        // Finally, choose a key exchange group that is compatible with the selected cipher
        // suite.
        let offered = || {
            client_groups
                .iter()
                .filter_map(|&name| {
                    self.config
                        .provider
                        .find_kx_group(name, T::VERSION)
                })
                .filter(|kx_group| {
                    suite.usable_for_kx_algorithm(kx_group.name().key_exchange_algorithm())
                })
                .map(|group| OfferedKxGroup {
                    group,
                    has_key_share: T::VERSION == ProtocolVersion::TLSv1_3
                        && client_shares
                            .iter()
                            .any(|share| share.group == group.name()),
                })
        };

        let selected = self
            .config
            .kx_selector
            .select_key_exchange(&mut offered(), &self.config.provider.kx_groups)
            .filter(|chosen| offered().any(|offer| offer.group.name() == chosen.name()));

        match selected {
            Some(skxg) => Ok((suite, skxg)),
            // For TLS1.2, the server can unilaterally choose a DHE group if it has one and
            // there was no better option.
            None if T::VERSION == ProtocolVersion::TLSv1_2
                && offered().next().is_none()
                && suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::DHE) =>
            {
                first_supported_dhe_kxg
                    .map(|skxg| (suite, *skxg))
                    .ok_or_else(|| PeerIncompatible::NoKxGroupsInCommon.into())
            }
            None => Err(PeerIncompatible::NoKxGroupsInCommon.into()),
        }
    }

    pub(super) fn randoms(&self, input: &ClientHelloInput<'_>) -> Result<ConnectionRandoms, Error> {
        Ok(ConnectionRandoms::new(
            input.client_hello.random,
            Random::new(self.config.provider.secure_random)?,
        ))
    }
}

impl ExpectClientHello {
    pub(crate) fn handle<'m>(
        mut self,
        input: Input<'m>,
        output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error> {
        let input = ClientHelloInput::from_input(&input)?;
        match self.previous_hello.take() {
            Some(retry) => handle_retried_client_hello(*retry, input, self, output),
            None => self.with_input(input, output),
        }
    }

    fn set_resumption_data(&mut self, resumption_data: &[u8]) -> Result<(), Error> {
        self.resumption_data = resumption_data.to_vec();
        Ok(())
    }
}

impl From<Box<ExpectClientHello>> for ServerState {
    fn from(value: Box<ExpectClientHello>) -> Self {
        Self::ClientHello(value)
    }
}

pub(crate) trait ServerHandler<T>: fmt::Debug + Sealed + Send + Sync {
    fn handle_client_hello(
        &self,
        suite: &'static T,
        kx_group: &'static dyn SupportedKxGroup,
        credentials: SelectedCredential,
        input: ClientHelloInput<'_>,
        st: ExpectClientHello,
        output: &mut dyn Output<'_>,
    ) -> Result<ServerState, Error>;
}

pub(crate) struct ClientHelloInput<'a> {
    pub(super) message: &'a Message<'a>,
    pub(super) client_hello: &'a ClientHelloPayload,
    pub(super) sig_schemes: &'a [SignatureScheme],
    pub(super) proof: HandshakeAlignedProof,
}

impl<'a> ClientHelloInput<'a> {
    /// Configuration-independent validation of a `ClientHello` message.
    ///
    /// This represents the first part of the `ClientHello` handling, where we do all validation that
    /// doesn't depend on a `ServerConfig` being available and extract everything needed to build a
    /// [`ClientHello`] value for a [`ServerCredentialResolver`].
    ///
    /// [`ServerCredentialResolver`]: crate::server::ServerCredentialResolver
    pub(super) fn from_input(input: &'a Input<'a>) -> Result<Self, Error> {
        let client_hello = require_handshake_msg!(
            input.message,
            HandshakeType::ClientHello,
            HandshakePayload::ClientHello
        )?;
        trace!("we got a clienthello {client_hello:?}");

        if !client_hello
            .compression_methods
            .contains(&Compression::Null)
        {
            return Err(PeerIncompatible::NullCompressionRequired.into());
        }

        // No handshake messages should follow this one in this flight.
        let proof = input.check_aligned_handshake()?;

        let sig_schemes = client_hello
            .signature_schemes
            .as_deref()
            .ok_or(PeerIncompatible::SignatureAlgorithmsExtensionRequired)?;

        Ok(ClientHelloInput {
            message: &input.message,
            client_hello,
            sig_schemes,
            proof,
        })
    }
}

pub(crate) enum HandshakeHashOrBuffer {
    Buffer(HandshakeHashBuffer),
    Hash(HandshakeHash),
}

impl HandshakeHashOrBuffer {
    pub(super) fn start(self, hash: &'static dyn Hash) -> Result<HandshakeHash, Error> {
        match self {
            Self::Buffer(inner) => Ok(inner.start_hash(hash)),
            Self::Hash(inner) if inner.algorithm() == hash.algorithm() => Ok(inner),
            _ => Err(PeerMisbehaved::HandshakeHashVariedAfterRetry.into()),
        }
    }
}
