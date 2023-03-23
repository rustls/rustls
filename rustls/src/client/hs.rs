#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::inappropriate_handshake_message;
use crate::common_state::{CommonState, State};
use crate::conn::ConnectionRandoms;
use crate::enums::{AlertDescription, CipherSuite, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::enums::{Compression, ExtensionType};
use crate::msgs::enums::{ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::handshake::{CertificateStatusRequest, ClientSessionTicket, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::{Random, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::ticketer::TimeBase;
use crate::tls13::key_schedule::KeyScheduleEarly;
use crate::SupportedCipherSuite;

#[cfg(feature = "tls12")]
use super::tls12;
use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::{tls13, ClientConfig, ServerName};

use std::ops::Deref;
use std::sync::Arc;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = crate::common_state::Context<'a, ClientConnectionData>;

fn find_session(
    server_name: &ServerName,
    config: &ClientConfig,
    #[cfg(feature = "quic")] cx: &mut ClientContext<'_>,
) -> Option<persist::Retrieved<ClientSessionValue>> {
    #[allow(clippy::let_and_return)]
    let found = config
        .session_storage
        .take_tls13_ticket(server_name)
        .map(ClientSessionValue::Tls13)
        .or_else(|| {
            #[cfg(feature = "tls12")]
            {
                config
                    .session_storage
                    .tls12_session(server_name)
                    .map(ClientSessionValue::Tls12)
            }

            #[cfg(not(feature = "tls12"))]
            None
        })
        .and_then(|resuming| {
            let retrieved = persist::Retrieved::new(resuming, TimeBase::now().ok()?);
            match retrieved.has_expired() {
                false => Some(retrieved),
                true => None,
            }
        })
        .or_else(|| {
            debug!("No cached session for {:?}", server_name);
            None
        });

    #[cfg(feature = "quic")]
    if let Some(resuming) = &found {
        if cx.common.is_quic() {
            cx.common.quic.params = resuming
                .tls13()
                .map(|v| v.quic_params());
        }
    }

    found
}

pub(super) fn start_handshake(
    server_name: ServerName,
    extra_exts: Vec<ClientExtension>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config
        .client_auth_cert_resolver
        .has_certs()
    {
        transcript_buffer.set_client_auth_enabled();
    }

    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut session_id: Option<SessionID> = None;
    let mut resuming_session = find_session(
        &server_name,
        &config,
        #[cfg(feature = "quic")]
        cx,
    );

    let key_share = if support_tls13 {
        Some(tls13::initial_key_share(&config, &server_name)?)
    } else {
        None
    };

    if let Some(_resuming) = &mut resuming_session {
        #[cfg(feature = "tls12")]
        if let ClientSessionValue::Tls12(inner) = &mut _resuming.value {
            // If we have a ticket, we use the sessionid as a signal that
            // we're  doing an abbreviated handshake.  See section 3.4 in
            // RFC5077.
            if !inner.ticket().is_empty() {
                inner.session_id = SessionID::random()?;
            }
            session_id = Some(inner.session_id);
        }

        debug!("Resuming session");
    } else {
        debug!("Not resuming any session");
    }

    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
    if session_id.is_none() && !cx.common.is_quic() {
        session_id = Some(SessionID::random()?);
    }

    let random = Random::new()?;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    Ok(emit_client_hello_for_retry(
        config,
        cx,
        resuming_session,
        random,
        false,
        transcript_buffer,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        None,
        server_name,
        key_share,
        extra_exts,
        may_send_sct_list,
        None,
    ))
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Retrieved<ClientSessionValue>>,
    server_name: ServerName,
    random: Random,
    using_ems: bool,
    transcript_buffer: HandshakeHashBuffer,
    early_key_schedule: Option<KeyScheduleEarly>,
    hello: ClientHelloDetails,
    offered_key_share: Option<kx::KeyExchange>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<SupportedCipherSuite>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    resuming_session: Option<persist::Retrieved<ClientSessionValue>>,
    random: Random,
    using_ems: bool,
    mut transcript_buffer: HandshakeHashBuffer,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: Option<SessionID>,
    retryreq: Option<&HelloRetryRequest>,
    server_name: ServerName,
    key_share: Option<kx::KeyExchange>,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
    suite: Option<SupportedCipherSuite>,
) -> NextState {
    // Do we have a SessionID or ticket cached for this host?
    let (ticket, resume_version) = if let Some(resuming) = &resuming_session {
        match &resuming.value {
            ClientSessionValue::Tls13(inner) => (inner.ticket().to_vec(), ProtocolVersion::TLSv1_3),
            #[cfg(feature = "tls12")]
            ClientSessionValue::Tls12(inner) => (inner.ticket().to_vec(), ProtocolVersion::TLSv1_2),
        }
    } else {
        (Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2) && !cx.common.is_quic();
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    // should be unreachable thanks to config builder
    assert!(!supported_versions.is_empty());

    let mut exts = vec![
        ClientExtension::SupportedVersions(supported_versions),
        ClientExtension::ECPointFormats(ECPointFormatList::supported()),
        ClientExtension::NamedGroups(
            config
                .kx_groups
                .iter()
                .map(|skxg| skxg.name)
                .collect(),
        ),
        ClientExtension::SignatureAlgorithms(
            config
                .verifier
                .supported_verify_schemes(),
        ),
        ClientExtension::ExtendedMasterSecretRequest,
        ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
    ];

    if let (Some(sni_name), true) = (server_name.for_sni(), config.enable_sni) {
        exts.push(ClientExtension::make_sni(sni_name));
    }

    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if let Some(key_share) = &key_share {
        debug_assert!(support_tls13);
        let key_share = KeyShareEntry::new(key_share.group(), key_share.pubkey.as_ref());
        exts.push(ClientExtension::KeyShare(vec![key_share]));
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(extra_exts.iter().cloned());

    let tls13_session = if support_tls13
        && config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        resuming_session
            .as_ref()
            .and_then(|resuming| match (suite, resuming.map(|csv| csv.tls13())) {
                (Some(suite), Some(resuming)) => {
                    suite
                        .tls13()?
                        .can_resume_from(resuming.suite())?;
                    Some(resuming)
                }
                (None, Some(resuming)) => Some(resuming),
                _ => None,
            })
            .map(|resuming| {
                tls13::prepare_resumption(&config, cx, &resuming, &mut exts, retryreq.is_some());
                resuming
            })
    } else if config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Request));
        } else {
            exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
                Payload::new(ticket),
            )));
        }
        None
    } else {
        None
    };

    // Note what extensions we sent.
    hello.sent_extensions = exts
        .iter()
        .map(ClientExtension::get_type)
        .collect();

    let session_id = session_id.unwrap_or_else(SessionID::empty);
    let mut cipher_suites: Vec<_> = config
        .cipher_suites
        .iter()
        .map(|cs| cs.suite())
        .collect();
    // We don't do renegotiation at all, in fact.
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites,
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    let early_key_schedule = if let Some(resuming) = tls13_session {
        let schedule = tls13::fill_in_psk_binder(&resuming, &transcript_buffer, &mut chp);
        Some((resuming.suite(), schedule))
    } else {
        None
    };

    let ch = Message {
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_key_schedule = early_key_schedule.map(|(resuming_suite, schedule)| {
        if !cx.data.early_data.is_enabled() {
            return schedule;
        }

        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            resuming_suite,
            &schedule,
            &mut sent_tls13_fake_ccs,
            &transcript_buffer,
            &random.0,
        );
        schedule
    });

    let next = ExpectServerHello {
        config,
        resuming_session,
        server_name,
        random,
        using_ems,
        transcript_buffer,
        early_key_schedule,
        hello,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next, extra_exts })
    } else {
        Box::new(next)
    }
}

pub(super) fn process_alpn_protocol(
    common: &mut CommonState,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.alpn_protocol {
        if !config
            .alpn_protocols
            .contains(alpn_protocol)
        {
            return Err(common.illegal_param(PeerMisbehaved::SelectedUnofferedApplicationProtocol));
        }
    }

    #[cfg(feature = "quic")]
    {
        // RFC 9001 says: "While ALPN only specifies that servers use this alert, QUIC clients MUST
        // use error 0x0178 to terminate a connection when ALPN negotiation fails." We judge that
        // the user intended to use ALPN (rather than some out-of-band protocol negotiation
        // mechanism) iff any ALPN protocols were configured. This defends against badly-behaved
        // servers which accept a connection that requires an application-layer protocol they do not
        // understand.
        if common.is_quic() && common.alpn_protocol.is_none() && !config.alpn_protocols.is_empty() {
            common.send_fatal_alert(AlertDescription::NoApplicationProtocol);
            return Err(Error::NoApplicationProtocol);
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(v))
    );
    Ok(())
}

pub(super) fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = self.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if self.config.supports_version(TLSv1_2) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion.into());
                }

                if server_hello
                    .get_supported_versions()
                    .is_some()
                {
                    return Err(cx
                        .common
                        .illegal_param(PeerMisbehaved::SelectedTls12UsingTls13VersionExtension));
                }

                TLSv1_2
            }
            _ => {
                cx.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                let reason = match server_version {
                    TLSv1_2 | TLSv1_3 => PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                    _ => PeerIncompatible::ServerDoesNotSupportTls12Or13,
                };
                return Err(reason.into());
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .common
                .illegal_param(PeerMisbehaved::SelectedUnofferedCompression));
        }

        if server_hello.has_duplicate_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(PeerMisbehaved::DuplicateServerHelloExtensions.into());
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(PeerMisbehaved::UnsolicitedServerHelloExtension.into());
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(cx.common, &self.config, server_hello.get_alpn_protocol())?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints.into());
            }
        }

        let suite = self
            .config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCipherSuite)
            })?;

        if version != suite.version().version {
            return Err(cx
                .common
                .illegal_param(PeerMisbehaved::SelectedUnusableCipherSuiteForVersion));
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .common
                    .illegal_param(PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry));
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_algorithm());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.random, server_hello.random);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        ClientSessionValue::Tls13(inner) => Some(inner),
                        #[cfg(feature = "tls12")]
                        ClientSessionValue::Tls12(_) => None,
                    });

                tls13::handle_server_hello(
                    self.config,
                    cx,
                    server_hello,
                    resuming_session,
                    self.server_name,
                    randoms,
                    suite,
                    transcript,
                    self.early_key_schedule,
                    self.hello,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    self.sent_tls13_fake_ccs,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        ClientSessionValue::Tls12(inner) => Some(inner),
                        ClientSessionValue::Tls13(_) => None,
                    });

                tls12::CompleteServerHelloHandling {
                    config: self.config,
                    resuming_session,
                    server_name: self.server_name,
                    randoms,
                    using_ems: self.using_ems,
                    transcript,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
            }
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        self,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.common.check_aligned_handshake()?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group()) {
            return Err(cx
                .common
                .illegal_param(PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup));
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(cx
                    .common
                    .illegal_param(PeerMisbehaved::IllegalHelloRetryRequestWithEmptyCookie));
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension.into());
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .common
                .illegal_param(PeerMisbehaved::DuplicateHelloRetryRequestExtensions));
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .common
                .illegal_param(PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx.common.illegal_param(
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
                ));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = self
            .next
            .config
            .find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(cx.common.illegal_param(
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite,
                ));
            }
        };

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(cs.hash_algorithm());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let may_send_sct_list = self
            .next
            .hello
            .server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group() => {
                let group = kx::KeyExchange::choose(group, &self.next.config.kx_groups)
                    .ok_or_else(|| {
                        cx.common.illegal_param(
                            PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                        )
                    })?;
                kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes)?
            }
            _ => offered_key_share,
        };

        Ok(emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.resuming_session,
            self.next.random,
            self.next.using_ems,
            transcript_buffer,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            Some(self.next.session_id),
            Some(hrr),
            self.next.server_name,
            Some(key_share),
            self.extra_exts,
            may_send_sct_list,
            Some(cs),
        ))
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        match m.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::ServerHello(..),
                        ..
                    },
                ..
            } => self
                .into_expect_server_hello()
                .handle(cx, m),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::HelloRetryRequest(..),
                        ..
                    },
                ..
            } => self.handle_hello_retry_request(cx, m),
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
            )),
        }
    }
}

enum ClientSessionValue {
    Tls13(persist::Tls13ClientSessionValue),
    #[cfg(feature = "tls12")]
    Tls12(persist::Tls12ClientSessionValue),
}

impl ClientSessionValue {
    fn common(&self) -> &persist::ClientSessionCommon {
        match self {
            Self::Tls13(inner) => &inner.common,
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => &inner.common,
        }
    }

    fn tls13(&self) -> Option<&persist::Tls13ClientSessionValue> {
        match self {
            Self::Tls13(v) => Some(v),
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => None,
        }
    }
}

impl Deref for ClientSessionValue {
    type Target = persist::ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        self.common()
    }
}
