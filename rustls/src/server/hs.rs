use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use pki_types::DnsName;

use super::server_conn::ServerConnectionData;
#[cfg(feature = "tls12")]
use super::tls12;
use crate::common_state::{
    KxState, Protocol, RawKeyNegotationResult, RawKeyNegotiationParams, State,
};
use crate::conn::ConnectionRandoms;
use crate::crypto::SupportedKxGroup;
use crate::enums::{
    AlertDescription, CipherSuite, HandshakeType, ProtocolVersion, SignatureAlgorithm,
    SignatureScheme,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace};
use crate::msgs::enums::{CertificateType, Compression, ExtensionType, NamedGroup};
#[cfg(feature = "tls12")]
use crate::msgs::handshake::SessionId;
use crate::msgs::handshake::{
    ClientHelloPayload, ConvertProtocolNameList, ConvertServerNameList, HandshakePayload,
    KeyExchangeAlgorithm, Random, ServerExtension,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::common::ActiveCertifiedKey;
use crate::server::{tls13, ClientHello, ServerConfig};
use crate::{suites, SupportedCipherSuite};

pub(super) type NextState<'a> = Box<dyn State<ServerConnectionData> + 'a>;
pub(super) type NextStateOrError<'a> = Result<NextState<'a>, Error>;
pub(super) type ServerContext<'a> = crate::common_state::Context<'a, ServerConnectionData>;

pub(super) fn can_resume(
    suite: SupportedCipherSuite,
    sni: &Option<DnsName<'_>>,
    using_ems: bool,
    resumedata: &persist::ServerSessionValue,
) -> bool {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    //
    // RFC 6066 says "A server that implements this extension MUST NOT accept
    // the request to resume the session if the server_name extension contains
    // a different name. Instead, it proceeds with a full handshake to
    // establish a new session."
    resumedata.cipher_suite == suite.suite()
        && (resumedata.extended_ms == using_ems || (resumedata.extended_ms && !using_ems))
        && &resumedata.sni == sni
}

#[derive(Default)]
pub(super) struct ExtensionProcessing {
    // extensions to reply with
    pub(super) exts: Vec<ServerExtension>,
    #[cfg(feature = "tls12")]
    pub(super) send_ticket: bool,
}

impl ExtensionProcessing {
    pub(super) fn new() -> Self {
        Default::default()
    }

    pub(super) fn process_common(
        &mut self,
        config: &ServerConfig,
        cx: &mut ServerContext<'_>,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        extra_exts: Vec<ServerExtension>,
    ) -> Result<(), Error> {
        // ALPN
        let our_protocols = &config.alpn_protocols;
        let maybe_their_protocols = hello.alpn_extension();
        if let Some(their_protocols) = maybe_their_protocols {
            let their_protocols = their_protocols.to_slices();

            if their_protocols
                .iter()
                .any(|protocol| protocol.is_empty())
            {
                return Err(PeerMisbehaved::OfferedEmptyApplicationProtocol.into());
            }

            cx.common.alpn_protocol = our_protocols
                .iter()
                .find(|protocol| their_protocols.contains(&protocol.as_slice()))
                .cloned();
            if let Some(ref selected_protocol) = cx.common.alpn_protocol {
                debug!("Chosen ALPN protocol {:?}", selected_protocol);
                self.exts
                    .push(ServerExtension::make_alpn(&[selected_protocol]));
            } else if !our_protocols.is_empty() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::NoApplicationProtocol,
                    Error::NoApplicationProtocol,
                ));
            }
        }

        if cx.common.is_quic() {
            // QUIC has strict ALPN, unlike TLS's more backwards-compatible behavior. RFC 9001
            // says: "The server MUST treat the inability to select a compatible application
            // protocol as a connection error of type 0x0178". We judge that ALPN was desired
            // (rather than some out-of-band protocol negotiation mechanism) if and only if any ALPN
            // protocols were configured locally or offered by the client. This helps prevent
            // successful establishment of connections between peers that can't understand
            // each other.
            if cx.common.alpn_protocol.is_none()
                && (!our_protocols.is_empty() || maybe_their_protocols.is_some())
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::NoApplicationProtocol,
                    Error::NoApplicationProtocol,
                ));
            }

            match hello.quic_params_extension() {
                Some(params) => cx.common.quic.params = Some(params),
                None => {
                    return Err(cx
                        .common
                        .missing_extension(PeerMisbehaved::MissingQuicTransportParameters));
                }
            }
        }

        let for_resume = resumedata.is_some();
        // SNI
        if !for_resume && hello.sni_extension().is_some() {
            self.exts
                .push(ServerExtension::ServerNameAck);
        }

        // Send status_request response if we have one.  This is not allowed
        // if we're resuming, and is only triggered if we have an OCSP response
        // to send.
        if !for_resume
            && hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some()
        {
            if ocsp_response.is_some() && !cx.common.is_tls13() {
                // Only TLS1.2 sends confirmation in ServerHello
                self.exts
                    .push(ServerExtension::CertificateStatusAck);
            }
        } else {
            // Throw away any OCSP response so we don't try to send it later.
            ocsp_response.take();
        }

        self.validate_server_cert_type_extension(hello, config, cx)?;
        self.validate_client_cert_type_extension(hello, config, cx)?;

        self.exts.extend(extra_exts);

        Ok(())
    }

    #[cfg(feature = "tls12")]
    pub(super) fn process_tls12(
        &mut self,
        config: &ServerConfig,
        hello: &ClientHelloPayload,
        using_ems: bool,
    ) {
        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        let secure_reneg_offered = hello
            .find_extension(ExtensionType::RenegotiationInfo)
            .is_some()
            || hello
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            self.exts
                .push(ServerExtension::make_empty_renegotiation_info());
        }

        // Tickets:
        // If we get any SessionTicket extension and have tickets enabled,
        // we send an ack.
        if hello
            .find_extension(ExtensionType::SessionTicket)
            .is_some()
            && config.ticketer.enabled()
        {
            self.send_ticket = true;
            self.exts
                .push(ServerExtension::SessionTicketAck);
        }

        // Confirm use of EMS if offered.
        if using_ems {
            self.exts
                .push(ServerExtension::ExtendedMasterSecretAck);
        }
    }

    fn validate_server_cert_type_extension(
        &mut self,
        hello: &ClientHelloPayload,
        config: &ServerConfig,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        let requires_server_rpk = config
            .cert_resolver
            .only_raw_public_keys();
        let client_allows_rpk = hello
            .server_certificate_extension()
            .map(|certificate_types| certificate_types.contains(&CertificateType::RawPublicKey))
            .unwrap_or(false);

        let raw_key_negotation_params = RawKeyNegotiationParams {
            peer_supports_raw_key: client_allows_rpk,
            local_expects_raw_key: requires_server_rpk,
            extension_type: ExtensionType::ServerCertificateType,
        };

        self.process_cert_type_extension(
            raw_key_negotation_params.validate_raw_key_negotiation(),
            cx,
        )
    }

    fn validate_client_cert_type_extension(
        &mut self,
        hello: &ClientHelloPayload,
        config: &ServerConfig,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        let requires_client_rpk = config
            .verifier
            .requires_raw_public_keys();
        let client_offers_rpk = hello
            .client_certificate_extension()
            .map(|certificate_types| certificate_types.contains(&CertificateType::RawPublicKey))
            .unwrap_or(false);

        let raw_key_negotation_params = RawKeyNegotiationParams {
            peer_supports_raw_key: client_offers_rpk,
            local_expects_raw_key: requires_client_rpk,
            extension_type: ExtensionType::ClientCertificateType,
        };
        self.process_cert_type_extension(
            raw_key_negotation_params.validate_raw_key_negotiation(),
            cx,
        )
    }

    fn process_cert_type_extension(
        &mut self,
        raw_key_negotiation_result: RawKeyNegotationResult,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        match raw_key_negotiation_result {
            RawKeyNegotationResult::Negotiated(ExtensionType::ClientCertificateType) => {
                self.exts
                    .push(ServerExtension::ClientCertType(
                        CertificateType::RawPublicKey,
                    ));
            }
            RawKeyNegotationResult::Negotiated(ExtensionType::ServerCertificateType) => {
                self.exts
                    .push(ServerExtension::ServerCertType(
                        CertificateType::RawPublicKey,
                    ));
            }
            RawKeyNegotationResult::Err(err) => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::HandshakeFailure, err));
            }
            RawKeyNegotationResult::NotNegotiated => {}
            RawKeyNegotationResult::Negotiated(_) => unreachable!(
                "The extension type should only ever be ClientCertificateType or ServerCertificateType"
            ),
        }
        Ok(())
    }
}

pub(super) struct ExpectClientHello {
    pub(super) config: Arc<ServerConfig>,
    pub(super) extra_exts: Vec<ServerExtension>,
    pub(super) transcript: HandshakeHashOrBuffer,
    #[cfg(feature = "tls12")]
    pub(super) session_id: SessionId,
    #[cfg(feature = "tls12")]
    pub(super) using_ems: bool,
    pub(super) done_retry: bool,
    pub(super) send_tickets: usize,
}

impl ExpectClientHello {
    pub(super) fn new(config: Arc<ServerConfig>, extra_exts: Vec<ServerExtension>) -> Self {
        let mut transcript_buffer = HandshakeHashBuffer::new();

        if config.verifier.offer_client_auth() {
            transcript_buffer.set_client_auth_enabled();
        }

        Self {
            config,
            extra_exts,
            transcript: HandshakeHashOrBuffer::Buffer(transcript_buffer),
            #[cfg(feature = "tls12")]
            session_id: SessionId::empty(),
            #[cfg(feature = "tls12")]
            using_ems: false,
            done_retry: false,
            send_tickets: 0,
        }
    }

    /// Continues handling of a `ClientHello` message once config and certificate are available.
    pub(super) fn with_certified_key(
        self,
        mut sig_schemes: Vec<SignatureScheme>,
        client_hello: &ClientHelloPayload,
        m: &Message<'_>,
        cx: &mut ServerContext<'_>,
    ) -> NextStateOrError<'static> {
        let tls13_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_3);
        let tls12_enabled = self
            .config
            .supports_version(ProtocolVersion::TLSv1_2);

        // Are we doing TLS1.3?
        let maybe_versions_ext = client_hello.versions_extension();
        let version = if let Some(versions) = maybe_versions_ext {
            if versions.contains(&ProtocolVersion::TLSv1_3) && tls13_enabled {
                ProtocolVersion::TLSv1_3
            } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::ProtocolVersion,
                    PeerIncompatible::Tls12NotOfferedOrEnabled,
                ));
            } else if cx.common.is_quic() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::ProtocolVersion,
                    PeerIncompatible::Tls13RequiredForQuic,
                ));
            } else {
                ProtocolVersion::TLSv1_2
            }
        } else if u16::from(client_hello.client_version) < u16::from(ProtocolVersion::TLSv1_2) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::Tls12NotOffered,
            ));
        } else if !tls12_enabled && tls13_enabled {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::SupportedVersionsExtensionRequired,
            ));
        } else if cx.common.is_quic() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerIncompatible::Tls13RequiredForQuic,
            ));
        } else {
            ProtocolVersion::TLSv1_2
        };

        cx.common.negotiated_version = Some(version);

        // We communicate to the upper layer what kind of key they should choose
        // via the sigschemes value.  Clients tend to treat this extension
        // orthogonally to offered ciphersuites (even though, in TLS1.2 it is not).
        // So: reduce the offered sigschemes to those compatible with the
        // intersection of ciphersuites.
        let client_suites = self
            .config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|scs| {
                client_hello
                    .cipher_suites
                    .contains(&scs.suite())
            })
            .collect::<Vec<_>>();

        sig_schemes
            .retain(|scheme| suites::compatible_sigscheme_for_suites(*scheme, &client_suites));

        // Choose a certificate.
        let certkey = {
            let client_hello = ClientHello::new(
                &cx.data.sni,
                &sig_schemes,
                client_hello.alpn_extension(),
                client_hello.server_certificate_extension(),
                client_hello.client_certificate_extension(),
                &client_hello.cipher_suites,
            );

            let certkey = self
                .config
                .cert_resolver
                .resolve(client_hello);

            certkey.ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::AccessDenied,
                    Error::General("no server certificate chain resolved".to_owned()),
                )
            })?
        };
        let certkey = ActiveCertifiedKey::from_certified_key(&certkey);

        let (suite, skxg) = self
            .choose_suite_and_kx_group(
                version,
                certkey.get_key().algorithm(),
                cx.common.protocol,
                client_hello
                    .namedgroups_extension()
                    .unwrap_or(&[]),
                &client_hello.cipher_suites,
            )
            .map_err(|incompat| {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure, incompat)
            })?;

        debug!("decided upon suite {:?}", suite);
        cx.common.suite = Some(suite);
        cx.common.kx_state = KxState::Start(skxg);

        // Start handshake hash.
        let starting_hash = suite.hash_provider();
        let transcript = match self.transcript {
            HandshakeHashOrBuffer::Buffer(inner) => inner.start_hash(starting_hash),
            HandshakeHashOrBuffer::Hash(inner)
                if inner.algorithm() == starting_hash.algorithm() =>
            {
                inner
            }
            _ => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::HandshakeHashVariedAfterRetry,
                ));
            }
        };

        // Save their Random.
        let randoms = ConnectionRandoms::new(
            client_hello.random,
            Random::new(self.config.provider.secure_random)?,
        );
        match suite {
            SupportedCipherSuite::Tls13(suite) => tls13::CompleteClientHelloHandling {
                config: self.config,
                transcript,
                suite,
                randoms,
                done_retry: self.done_retry,
                send_tickets: self.send_tickets,
                extra_exts: self.extra_exts,
            }
            .handle_client_hello(cx, certkey, m, client_hello, skxg, sig_schemes),
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => tls12::CompleteClientHelloHandling {
                config: self.config,
                transcript,
                session_id: self.session_id,
                suite,
                using_ems: self.using_ems,
                randoms,
                send_ticket: self.send_tickets > 0,
                extra_exts: self.extra_exts,
            }
            .handle_client_hello(
                cx,
                certkey,
                m,
                client_hello,
                skxg,
                sig_schemes,
                tls13_enabled,
            ),
        }
    }

    fn choose_suite_and_kx_group(
        &self,
        selected_version: ProtocolVersion,
        sig_key_algorithm: SignatureAlgorithm,
        protocol: Protocol,
        client_groups: &[NamedGroup],
        client_suites: &[CipherSuite],
    ) -> Result<(SupportedCipherSuite, &'static dyn SupportedKxGroup), PeerIncompatible> {
        // Determine which `KeyExchangeAlgorithm`s are theoretically possible, based
        // on the offered and supported groups.
        let mut ecdhe_possible = false;
        let mut ffdhe_possible = false;
        let mut ffdhe_offered = false;
        let mut supported_groups = Vec::with_capacity(client_groups.len());

        for offered_group in client_groups {
            let supported = self
                .config
                .provider
                .kx_groups
                .iter()
                .find(|skxg| {
                    skxg.usable_for_version(selected_version) && skxg.name() == *offered_group
                });

            match offered_group.key_exchange_algorithm() {
                KeyExchangeAlgorithm::DHE => {
                    ffdhe_possible |= supported.is_some();
                    ffdhe_offered = true;
                }
                KeyExchangeAlgorithm::ECDHE => {
                    ecdhe_possible |= supported.is_some();
                }
            }

            supported_groups.push(supported);
        }

        let first_supported_dhe_kxg = if selected_version == ProtocolVersion::TLSv1_2 {
            // https://datatracker.ietf.org/doc/html/rfc7919#section-4 (paragraph 2)
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
            return Err(PeerIncompatible::NoKxGroupsInCommon);
        }

        let mut suitable_suites_iter = self
            .config
            .provider
            .cipher_suites
            .iter()
            .filter(|suite| {
                // Reduce our supported ciphersuites by the certified key's algorithm.
                suite.usable_for_signature_algorithm(sig_key_algorithm)
                // And version
                && suite.version().version == selected_version
                // And protocol
                && suite.usable_for_protocol(protocol)
                // And support one of key exchange groups
                && (ecdhe_possible && suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::ECDHE)
                || ffdhe_possible && suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::DHE))
            });

        // RFC 7919 (https://datatracker.ietf.org/doc/html/rfc7919#section-4) requires us to send
        // the InsufficientSecurity alert in case we don't recognize client's FFDHE groups (i.e.,
        // `suitable_suites` becomes empty). But that does not make a lot of sense (e.g., client
        // proposes FFDHE4096 and we only support FFDHE2048), so we ignore that requirement here,
        // and continue to send HandshakeFailure.

        let suite = if self.config.ignore_client_order {
            suitable_suites_iter.find(|suite| client_suites.contains(&suite.suite()))
        } else {
            let suitable_suites = suitable_suites_iter.collect::<Vec<_>>();
            client_suites
                .iter()
                .find_map(|client_suite| {
                    suitable_suites
                        .iter()
                        .find(|x| *client_suite == x.suite())
                })
                .copied()
        }
        .ok_or(PeerIncompatible::NoCipherSuitesInCommon)?;

        // Finally, choose a key exchange group that is compatible with the selected cipher
        // suite.
        let maybe_skxg = supported_groups
            .iter()
            .find_map(|maybe_skxg| match maybe_skxg {
                Some(skxg) => suite
                    .usable_for_kx_algorithm(skxg.name().key_exchange_algorithm())
                    .then_some(*skxg),
                None => None,
            });

        if selected_version == ProtocolVersion::TLSv1_3 {
            // This unwrap is structurally guaranteed by the early return for `!ffdhe_possible && !ecdhe_possible`
            return Ok((*suite, *maybe_skxg.unwrap()));
        }

        // For TLS1.2, the server can unilaterally choose a DHE group if it has one and
        // there was no better option.
        match maybe_skxg {
            Some(skxg) => Ok((*suite, *skxg)),
            None if suite.usable_for_kx_algorithm(KeyExchangeAlgorithm::DHE) => {
                // If kx for the selected cipher suite is DHE and no DHE groups are specified in the extension,
                // the server is free to choose DHE params, we choose the first DHE kx group of the provider.
                if let Some(server_selected_ffdhe_skxg) = first_supported_dhe_kxg {
                    Ok((*suite, *server_selected_ffdhe_skxg))
                } else {
                    Err(PeerIncompatible::NoKxGroupsInCommon)
                }
            }
            None => Err(PeerIncompatible::NoKxGroupsInCommon),
        }
    }
}

impl State<ServerConnectionData> for ExpectClientHello {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> NextStateOrError<'m>
    where
        Self: 'm,
    {
        let (client_hello, sig_schemes) = process_client_hello(&m, self.done_retry, cx)?;
        self.with_certified_key(sig_schemes, client_hello, &m, cx)
    }

    fn into_owned(self: Box<Self>) -> NextState<'static> {
        self
    }
}

/// Configuration-independent validation of a `ClientHello` message.
///
/// This represents the first part of the `ClientHello` handling, where we do all validation that
/// doesn't depend on a `ServerConfig` being available and extract everything needed to build a
/// [`ClientHello`] value for a [`ResolvesServerCert`].
///
/// Note that this will modify `data.sni` even if config or certificate resolution fail.
///
/// [`ResolvesServerCert`]: crate::server::ResolvesServerCert
pub(super) fn process_client_hello<'m>(
    m: &'m Message<'m>,
    done_retry: bool,
    cx: &mut ServerContext<'_>,
) -> Result<(&'m ClientHelloPayload, Vec<SignatureScheme>), Error> {
    let client_hello =
        require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
    trace!("we got a clienthello {:?}", client_hello);

    if !client_hello
        .compression_methods
        .contains(&Compression::Null)
    {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerIncompatible::NullCompressionRequired,
        ));
    }

    if client_hello.has_duplicate_extension() {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::DecodeError,
            PeerMisbehaved::DuplicateClientHelloExtensions,
        ));
    }

    // No handshake messages should follow this one in this flight.
    cx.common.check_aligned_handshake()?;

    // Extract and validate the SNI DNS name, if any, before giving it to
    // the cert resolver. In particular, if it is invalid then we should
    // send an Illegal Parameter alert instead of the Internal Error alert
    // (or whatever) that we'd send if this were checked later or in a
    // different way.
    let sni: Option<DnsName<'_>> = match client_hello.sni_extension() {
        Some(sni) => {
            if sni.has_duplicate_names_for_type() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::DecodeError,
                    PeerMisbehaved::DuplicateServerNameTypes,
                ));
            }

            if let Some(hostname) = sni.single_hostname() {
                Some(hostname.to_lowercase_owned())
            } else {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ServerNameMustContainOneHostName,
                ));
            }
        }
        None => None,
    };

    // save only the first SNI
    if let (Some(sni), false) = (&sni, done_retry) {
        // Save the SNI into the session.
        // The SNI hostname is immutable once set.
        assert!(cx.data.sni.is_none());
        cx.data.sni = Some(sni.clone());
    } else if cx.data.sni != sni {
        return Err(PeerMisbehaved::ServerNameDifferedOnRetry.into());
    }

    let sig_schemes = client_hello
        .sigalgs_extension()
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::SignatureAlgorithmsExtensionRequired,
            )
        })?;

    Ok((client_hello, sig_schemes.to_owned()))
}

pub(crate) enum HandshakeHashOrBuffer {
    Buffer(HandshakeHashBuffer),
    Hash(HandshakeHash),
}
