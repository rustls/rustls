use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub(super) use client_hello::CompleteClientHelloHandling;
use pki_types::{CertificateDer, UnixTime};
use subtle::ConstantTimeEq;

use super::hs::{self, HandshakeHashOrBuffer, ServerContext};
use super::server_conn::ServerConnectionData;
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::common_state::{
    CommonState, HandshakeFlightTls13, HandshakeKind, Protocol, Side, State,
};
use crate::conn::ConnectionRandoms;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warn};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::{
    CertificateChain, CertificatePayloadTls13, HandshakeMessagePayload, HandshakePayload,
    NewSessionTicketExtension, NewSessionTicketPayloadTls13, CERTIFICATE_MAX_SIZE_LIMIT,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::ServerConfig;
use crate::suites::PartiallyExtractedSecrets;
use crate::tls13::key_schedule::{
    KeyScheduleTraffic, KeyScheduleTrafficWithClientFinishedPending, ResumptionSecret,
};
use crate::tls13::{
    construct_client_verify_message, construct_server_verify_message, Tls13CipherSuite,
};
use crate::{compress, rand, verify};

mod client_hello {
    use super::*;
    use crate::compress::CertCompressor;
    use crate::crypto::SupportedKxGroup;
    use crate::enums::SignatureScheme;
    use crate::msgs::base::{Payload, PayloadU8};
    use crate::msgs::ccs::ChangeCipherSpecPayload;
    use crate::msgs::enums::{Compression, NamedGroup, PSKKeyExchangeMode};
    use crate::msgs::handshake::{
        CertReqExtension, CertificatePayloadTls13, CertificateRequestPayloadTls13,
        ClientHelloPayload, HelloRetryExtension, HelloRetryRequest, KeyShareEntry, Random,
        ServerExtension, ServerHelloPayload, SessionId,
    };
    use crate::server::common::ActiveCertifiedKey;
    use crate::sign;
    use crate::tls13::key_schedule::{
        KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake,
    };
    use crate::verify::DigitallySignedStruct;

    #[derive(PartialEq)]
    pub(super) enum EarlyDataDecision {
        Disabled,
        RequestedButRejected,
        Accepted,
    }

    pub(in crate::server) struct CompleteClientHelloHandling {
        pub(in crate::server) config: Arc<ServerConfig>,
        pub(in crate::server) transcript: HandshakeHash,
        pub(in crate::server) suite: &'static Tls13CipherSuite,
        pub(in crate::server) randoms: ConnectionRandoms,
        pub(in crate::server) done_retry: bool,
        pub(in crate::server) send_tickets: usize,
        pub(in crate::server) extra_exts: Vec<ServerExtension>,
    }

    fn max_early_data_size(configured: u32) -> usize {
        if configured != 0 {
            configured as usize
        } else {
            // The relevant max_early_data_size may in fact be unknowable: if
            // we (the server) have turned off early_data but the client has
            // a stale ticket from when we allowed early_data: we'll naturally
            // reject early_data but need an upper bound on the amount of data
            // to drop.
            //
            // Use a single maximum-sized message.
            16384
        }
    }

    impl CompleteClientHelloHandling {
        fn check_binder(
            &self,
            suite: &'static Tls13CipherSuite,
            client_hello: &Message<'_>,
            psk: &[u8],
            binder: &[u8],
        ) -> bool {
            let binder_plaintext = match &client_hello.payload {
                MessagePayload::Handshake { parsed, .. } => parsed.encoding_for_binder_signing(),
                _ => unreachable!(),
            };

            let handshake_hash = self
                .transcript
                .hash_given(&binder_plaintext);

            let key_schedule = KeyScheduleEarly::new(suite, psk);
            let real_binder =
                key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

            ConstantTimeEq::ct_eq(real_binder.as_ref(), binder).into()
        }

        fn attempt_tls13_ticket_decryption(
            &mut self,
            ticket: &[u8],
        ) -> Option<persist::ServerSessionValue> {
            if self.config.ticketer.enabled() {
                self.config
                    .ticketer
                    .decrypt(ticket)
                    .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain).ok())
            } else {
                self.config
                    .session_storage
                    .take(ticket)
                    .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain).ok())
            }
        }

        pub(in crate::server) fn handle_client_hello(
            mut self,
            cx: &mut ServerContext<'_>,
            server_key: ActiveCertifiedKey<'_>,
            chm: &Message<'_>,
            client_hello: &ClientHelloPayload,
            selected_kxg: &'static dyn SupportedKxGroup,
            mut sigschemes_ext: Vec<SignatureScheme>,
        ) -> hs::NextStateOrError<'static> {
            if client_hello.compression_methods.len() != 1 {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::OfferedIncorrectCompressions,
                ));
            }

            sigschemes_ext.retain(SignatureScheme::supported_in_tls13);

            let shares_ext = client_hello
                .keyshare_extension()
                .ok_or_else(|| {
                    cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::KeyShareExtensionRequired,
                    )
                })?;

            if client_hello.has_keyshare_extension_with_duplicates() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::OfferedDuplicateKeyShares,
                ));
            }

            if client_hello.has_certificate_compression_extension_with_duplicates() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::OfferedDuplicateCertificateCompressions,
                ));
            }

            let cert_compressor = client_hello
                .certificate_compression_extension()
                .and_then(|offered|
                    // prefer server order when choosing a compression: the client's
                    // extension here does not denote any preference.
                    self.config
                        .cert_compressors
                        .iter()
                        .find(|compressor| offered.contains(&compressor.algorithm()))
                        .cloned());

            let early_data_requested = client_hello.early_data_extension_offered();

            // EarlyData extension is illegal in second ClientHello
            if self.done_retry && early_data_requested {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::EarlyDataAttemptedInSecondClientHello,
                    )
                });
            }

            // See if there is a KeyShare for the selected kx group.
            let chosen_share_and_kxg = shares_ext.iter().find_map(|share| {
                (share.group == selected_kxg.name()).then_some((share, selected_kxg))
            });

            let chosen_share_and_kxg = match chosen_share_and_kxg {
                Some(s) => s,
                None => {
                    // We don't have a suitable key share.  Send a HelloRetryRequest
                    // for the mutually_preferred_group.
                    self.transcript.add_message(chm);

                    if self.done_retry {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::RefusedToFollowHelloRetryRequest,
                        ));
                    }

                    emit_hello_retry_request(
                        &mut self.transcript,
                        self.suite,
                        client_hello.session_id,
                        cx.common,
                        selected_kxg.name(),
                    );
                    emit_fake_ccs(cx.common);

                    let skip_early_data = max_early_data_size(self.config.max_early_data_size);

                    let next = Box::new(hs::ExpectClientHello {
                        config: self.config,
                        transcript: HandshakeHashOrBuffer::Hash(self.transcript),
                        #[cfg(feature = "tls12")]
                        session_id: SessionId::empty(),
                        #[cfg(feature = "tls12")]
                        using_ems: false,
                        done_retry: true,
                        send_tickets: self.send_tickets,
                        extra_exts: self.extra_exts,
                    });

                    return if early_data_requested {
                        Ok(Box::new(ExpectAndSkipRejectedEarlyData {
                            skip_data_left: skip_early_data,
                            next,
                        }))
                    } else {
                        Ok(next)
                    };
                }
            };

            let mut chosen_psk_index = None;
            let mut resumedata = None;

            if let Some(psk_offer) = client_hello.psk() {
                if !client_hello.check_psk_ext_is_last() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::PskExtensionMustBeLast,
                    ));
                }

                // "A client MUST provide a "psk_key_exchange_modes" extension if it
                //  offers a "pre_shared_key" extension. If clients offer
                //  "pre_shared_key" without a "psk_key_exchange_modes" extension,
                //  servers MUST abort the handshake." - RFC8446 4.2.9
                if client_hello.psk_modes().is_none() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::MissingExtension,
                        PeerMisbehaved::MissingPskModesExtension,
                    ));
                }

                if psk_offer.binders.is_empty() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::DecodeError,
                        PeerMisbehaved::MissingBinderInPskExtension,
                    ));
                }

                if psk_offer.binders.len() != psk_offer.identities.len() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders,
                    ));
                }

                for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                    let now = self.config.current_time()?;

                    let resume = match self
                        .attempt_tls13_ticket_decryption(&psk_id.identity.0)
                        .map(|resumedata| {
                            resumedata.set_freshness(psk_id.obfuscated_ticket_age, now)
                        })
                        .filter(|resumedata| {
                            hs::can_resume(self.suite.into(), &cx.data.sni, false, resumedata)
                        }) {
                        Some(resume) => resume,
                        None => continue,
                    };

                    if !self.check_binder(
                        self.suite,
                        chm,
                        &resume.master_secret.0,
                        psk_offer.binders[i].as_ref(),
                    ) {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::DecryptError,
                            PeerMisbehaved::IncorrectBinder,
                        ));
                    }

                    chosen_psk_index = Some(i);
                    resumedata = Some(resume);
                    break;
                }
            }

            if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
                debug!("Client unwilling to resume, DHE_KE not offered");
                self.send_tickets = 0;
                chosen_psk_index = None;
                resumedata = None;
            } else {
                self.send_tickets = self.config.send_tls13_tickets;
            }

            if let Some(ref resume) = resumedata {
                cx.data.received_resumption_data = Some(resume.application_data.0.clone());
                cx.common
                    .peer_certificates
                    .clone_from(&resume.client_cert_chain);
            }

            let full_handshake = resumedata.is_none();
            self.transcript.add_message(chm);
            let key_schedule = emit_server_hello(
                &mut self.transcript,
                &self.randoms,
                self.suite,
                cx,
                &client_hello.session_id,
                chosen_share_and_kxg,
                chosen_psk_index,
                resumedata
                    .as_ref()
                    .map(|x| &x.master_secret.0[..]),
                &self.config,
            )?;
            if !self.done_retry {
                emit_fake_ccs(cx.common);
            }

            if full_handshake {
                cx.common
                    .handshake_kind
                    .get_or_insert(HandshakeKind::Full);
            } else {
                cx.common.handshake_kind = Some(HandshakeKind::Resumed);
            }

            let mut ocsp_response = server_key.get_ocsp();
            let mut flight = HandshakeFlightTls13::new(&mut self.transcript);
            let doing_early_data = emit_encrypted_extensions(
                &mut flight,
                self.suite,
                cx,
                &mut ocsp_response,
                client_hello,
                resumedata.as_ref(),
                self.extra_exts,
                &self.config,
            )?;

            let doing_client_auth = if full_handshake {
                let client_auth = emit_certificate_req_tls13(&mut flight, &self.config)?;

                if let Some(compressor) = cert_compressor {
                    emit_compressed_certificate_tls13(
                        &mut flight,
                        &self.config,
                        server_key.get_cert(),
                        ocsp_response,
                        compressor,
                    );
                } else {
                    emit_certificate_tls13(&mut flight, server_key.get_cert(), ocsp_response);
                }
                emit_certificate_verify_tls13(
                    &mut flight,
                    cx.common,
                    server_key.get_key(),
                    &sigschemes_ext,
                )?;
                client_auth
            } else {
                false
            };

            // If we're not doing early data, then the next messages we receive
            // are encrypted with the handshake keys.
            match doing_early_data {
                EarlyDataDecision::Disabled => {
                    key_schedule.set_handshake_decrypter(None, cx.common);
                    cx.data.early_data.reject();
                }
                EarlyDataDecision::RequestedButRejected => {
                    debug!("Client requested early_data, but not accepted: switching to handshake keys with trial decryption");
                    key_schedule.set_handshake_decrypter(
                        Some(max_early_data_size(self.config.max_early_data_size)),
                        cx.common,
                    );
                    cx.data.early_data.reject();
                }
                EarlyDataDecision::Accepted => {
                    cx.data
                        .early_data
                        .accept(self.config.max_early_data_size as usize);
                }
            }

            cx.common.check_aligned_handshake()?;
            let key_schedule_traffic =
                emit_finished_tls13(flight, &self.randoms, cx, key_schedule, &self.config);

            if !doing_client_auth && self.config.send_half_rtt_data {
                // Application data can be sent immediately after Finished, in one
                // flight.  However, if client auth is enabled, we don't want to send
                // application data to an unauthenticated peer.
                cx.common
                    .start_outgoing_traffic(&mut cx.sendable_plaintext);
            }

            if doing_client_auth {
                if self
                    .config
                    .cert_decompressors
                    .is_empty()
                {
                    Ok(Box::new(ExpectCertificate {
                        config: self.config,
                        transcript: self.transcript,
                        suite: self.suite,
                        key_schedule: key_schedule_traffic,
                        send_tickets: self.send_tickets,
                        message_already_in_transcript: false,
                    }))
                } else {
                    Ok(Box::new(ExpectCertificateOrCompressedCertificate {
                        config: self.config,
                        transcript: self.transcript,
                        suite: self.suite,
                        key_schedule: key_schedule_traffic,
                        send_tickets: self.send_tickets,
                    }))
                }
            } else if doing_early_data == EarlyDataDecision::Accepted && !cx.common.is_quic() {
                // Not used for QUIC: RFC 9001 §8.3: Clients MUST NOT send the EndOfEarlyData
                // message. A server MUST treat receipt of a CRYPTO frame in a 0-RTT packet as a
                // connection error of type PROTOCOL_VIOLATION.
                Ok(Box::new(ExpectEarlyData {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: key_schedule_traffic,
                    send_tickets: self.send_tickets,
                }))
            } else {
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: key_schedule_traffic,
                    send_tickets: self.send_tickets,
                }))
            }
        }
    }

    fn emit_server_hello(
        transcript: &mut HandshakeHash,
        randoms: &ConnectionRandoms,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        session_id: &SessionId,
        share_and_kxgroup: (&KeyShareEntry, &'static dyn SupportedKxGroup),
        chosen_psk_idx: Option<usize>,
        resuming_psk: Option<&[u8]>,
        config: &ServerConfig,
    ) -> Result<KeyScheduleHandshake, Error> {
        let mut extensions = Vec::new();

        // Prepare key exchange; the caller already found the matching SupportedKxGroup
        let (share, kxgroup) = share_and_kxgroup;
        debug_assert_eq!(kxgroup.name(), share.group);
        let ckx = kxgroup
            .start_and_complete(&share.payload.0)
            .map_err(|err| {
                cx.common
                    .send_fatal_alert(AlertDescription::IllegalParameter, err)
            })?;
        cx.common.kx_state.complete();

        extensions.push(ServerExtension::KeyShare(KeyShareEntry::new(
            ckx.group,
            ckx.pub_key,
        )));
        extensions.push(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        if let Some(psk_idx) = chosen_psk_idx {
            extensions.push(ServerExtension::PresharedKey(psk_idx as u16));
        }

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(randoms.server),
                    session_id: *session_id,
                    cipher_suite: suite.common.suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            }),
        };

        cx.common.check_aligned_handshake()?;

        let client_hello_hash = transcript.hash_given(&[]);

        trace!("sending server hello {:?}", sh);
        transcript.add_message(&sh);
        cx.common.send_msg(sh, false);

        // Start key schedule
        let key_schedule_pre_handshake = if let Some(psk) = resuming_psk {
            let early_key_schedule = KeyScheduleEarly::new(suite, psk);
            early_key_schedule.client_early_traffic_secret(
                &client_hello_hash,
                &*config.key_log,
                &randoms.client,
                cx.common,
            );

            KeySchedulePreHandshake::from(early_key_schedule)
        } else {
            KeySchedulePreHandshake::new(suite)
        };

        // Do key exchange
        let key_schedule = key_schedule_pre_handshake.into_handshake(ckx.secret);

        let handshake_hash = transcript.current_hash();
        let key_schedule = key_schedule.derive_server_handshake_secrets(
            handshake_hash,
            &*config.key_log,
            &randoms.client,
            cx.common,
        );

        Ok(key_schedule)
    }

    fn emit_fake_ccs(common: &mut CommonState) {
        if common.is_quic() {
            return;
        }
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };
        common.send_msg(m, false);
    }

    fn emit_hello_retry_request(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        session_id: SessionId,
        common: &mut CommonState,
        group: NamedGroup,
    ) {
        let mut req = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id,
            cipher_suite: suite.common.suite,
            extensions: Vec::new(),
        };

        req.extensions
            .push(HelloRetryExtension::KeyShare(group));
        req.extensions
            .push(HelloRetryExtension::SupportedVersions(
                ProtocolVersion::TLSv1_3,
            ));

        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::HelloRetryRequest,
                payload: HandshakePayload::HelloRetryRequest(req),
            }),
        };

        trace!("Requesting retry {:?}", m);
        transcript.rollup_for_hrr();
        transcript.add_message(&m);
        common.send_msg(m, false);
        common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);
    }

    fn decide_if_early_data_allowed(
        cx: &mut ServerContext<'_>,
        client_hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        suite: &'static Tls13CipherSuite,
        config: &ServerConfig,
    ) -> EarlyDataDecision {
        let early_data_requested = client_hello.early_data_extension_offered();
        let rejected_or_disabled = match early_data_requested {
            true => EarlyDataDecision::RequestedButRejected,
            false => EarlyDataDecision::Disabled,
        };

        let resume = match resumedata {
            Some(resume) => resume,
            None => {
                // never any early data if not resuming.
                return rejected_or_disabled;
            }
        };

        /* Non-zero max_early_data_size controls whether early_data is allowed at all.
         * We also require stateful resumption. */
        let early_data_configured = config.max_early_data_size > 0 && !config.ticketer.enabled();

        /* "For PSKs provisioned via NewSessionTicket, a server MUST validate
         *  that the ticket age for the selected PSK identity (computed by
         *  subtracting ticket_age_add from PskIdentity.obfuscated_ticket_age
         *  modulo 2^32) is within a small tolerance of the time since the ticket
         *  was issued (see Section 8)." -- this is implemented in ServerSessionValue::set_freshness()
         *  and related.
         *
         * "In order to accept early data, the server [...] MUST verify that the
         *  following values are the same as those associated with the
         *  selected PSK:
         *
         *  - The TLS version number
         *  - The selected cipher suite
         *  - The selected ALPN [RFC7301] protocol, if any"
         *
         * (RFC8446, 4.2.10) */
        let early_data_possible = early_data_requested
            && resume.is_fresh()
            && Some(resume.version) == cx.common.negotiated_version
            && resume.cipher_suite == suite.common.suite
            && resume.alpn.as_ref().map(|x| &x.0) == cx.common.alpn_protocol.as_ref();

        if early_data_configured && early_data_possible && !cx.data.early_data.was_rejected() {
            EarlyDataDecision::Accepted
        } else {
            if cx.common.is_quic() {
                // Clobber value set in tls13::emit_server_hello
                cx.common.quic.early_secret = None;
            }

            rejected_or_disabled
        }
    }

    fn emit_encrypted_extensions(
        flight: &mut HandshakeFlightTls13<'_>,
        suite: &'static Tls13CipherSuite,
        cx: &mut ServerContext<'_>,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&persist::ServerSessionValue>,
        extra_exts: Vec<ServerExtension>,
        config: &ServerConfig,
    ) -> Result<EarlyDataDecision, Error> {
        let mut ep = hs::ExtensionProcessing::new();
        ep.process_common(config, cx, ocsp_response, hello, resumedata, extra_exts)?;

        let early_data = decide_if_early_data_allowed(cx, hello, resumedata, suite, config);
        if early_data == EarlyDataDecision::Accepted {
            ep.exts.push(ServerExtension::EarlyData);
        }

        let ee = HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(ep.exts),
        };

        trace!("sending encrypted extensions {:?}", ee);
        flight.add(ee);
        Ok(early_data)
    }

    fn emit_certificate_req_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        config: &ServerConfig,
    ) -> Result<bool, Error> {
        if !config.verifier.offer_client_auth() {
            return Ok(false);
        }

        let mut cr = CertificateRequestPayloadTls13 {
            context: PayloadU8::empty(),
            extensions: Vec::new(),
        };

        let schemes = config
            .verifier
            .supported_verify_schemes();
        cr.extensions
            .push(CertReqExtension::SignatureAlgorithms(schemes.to_vec()));

        if !config.cert_decompressors.is_empty() {
            cr.extensions
                .push(CertReqExtension::CertificateCompressionAlgorithms(
                    config
                        .cert_decompressors
                        .iter()
                        .map(|decomp| decomp.algorithm())
                        .collect(),
                ));
        }

        let authorities = config.verifier.root_hint_subjects();
        if !authorities.is_empty() {
            cr.extensions
                .push(CertReqExtension::AuthorityNames(authorities.to_vec()));
        }

        let creq = HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestTls13(cr),
        };

        trace!("Sending CertificateRequest {:?}", creq);
        flight.add(creq);
        Ok(true)
    }

    fn emit_certificate_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        cert_chain: &[CertificateDer<'static>],
        ocsp_response: Option<&[u8]>,
    ) {
        let cert = HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTls13(CertificatePayloadTls13::new(
                cert_chain.iter(),
                ocsp_response,
            )),
        };

        trace!("sending certificate {:?}", cert);
        flight.add(cert);
    }

    fn emit_compressed_certificate_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        config: &ServerConfig,
        cert_chain: &[CertificateDer<'static>],
        ocsp_response: Option<&[u8]>,
        cert_compressor: &'static dyn CertCompressor,
    ) {
        let payload = CertificatePayloadTls13::new(cert_chain.iter(), ocsp_response);

        let entry = match config
            .cert_compression_cache
            .compression_for(cert_compressor, &payload)
        {
            Ok(entry) => entry,
            Err(_) => return emit_certificate_tls13(flight, cert_chain, ocsp_response),
        };

        let c = HandshakeMessagePayload {
            typ: HandshakeType::CompressedCertificate,
            payload: HandshakePayload::CompressedCertificate(entry.compressed_cert_payload()),
        };

        trace!("sending compressed certificate {:?}", c);
        flight.add(c);
    }

    fn emit_certificate_verify_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        common: &mut CommonState,
        signing_key: &dyn sign::SigningKey,
        schemes: &[SignatureScheme],
    ) -> Result<(), Error> {
        let message = construct_server_verify_message(&flight.transcript.current_hash());

        let signer = signing_key
            .choose_scheme(schemes)
            .ok_or_else(|| {
                common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerIncompatible::NoSignatureSchemesInCommon,
                )
            })?;

        let scheme = signer.scheme();
        let sig = signer.sign(message.as_ref())?;

        let cv = DigitallySignedStruct::new(scheme, sig);

        let cv = HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(cv),
        };

        trace!("sending certificate-verify {:?}", cv);
        flight.add(cv);
        Ok(())
    }

    fn emit_finished_tls13(
        mut flight: HandshakeFlightTls13<'_>,
        randoms: &ConnectionRandoms,
        cx: &mut ServerContext<'_>,
        key_schedule: KeyScheduleHandshake,
        config: &ServerConfig,
    ) -> KeyScheduleTrafficWithClientFinishedPending {
        let handshake_hash = flight.transcript.current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data.as_ref());

        let fin = HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        };

        trace!("sending finished {:?}", fin);
        flight.add(fin);
        let hash_at_server_fin = flight.transcript.current_hash();
        flight.finish(cx.common);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        key_schedule.into_traffic_with_client_finished_pending(
            hash_at_server_fin,
            &*config.key_log,
            &randoms.client,
            cx.common,
        )
    }
}

struct ExpectAndSkipRejectedEarlyData {
    skip_data_left: usize,
    next: Box<hs::ExpectClientHello>,
}

impl State<ServerConnectionData> for ExpectAndSkipRejectedEarlyData {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        /* "The server then ignores early data by skipping all records with an external
         *  content type of "application_data" (indicating that they are encrypted),
         *  up to the configured max_early_data_size."
         * (RFC8446, 14.2.10) */
        if let MessagePayload::ApplicationData(ref skip_data) = m.payload {
            if skip_data.bytes().len() <= self.skip_data_left {
                self.skip_data_left -= skip_data.bytes().len();
                return Ok(self);
            }
        }

        self.next.handle(cx, m)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificateOrCompressedCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectCertificateOrCompressedCertificate {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::CertificateTls13(..),
                        ..
                    },
                ..
            } => Box::new(ExpectCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                send_tickets: self.send_tickets,
                message_already_in_transcript: false,
            })
            .handle(cx, m),

            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::CompressedCertificate(..),
                        ..
                    },
                ..
            } => Box::new(ExpectCompressedCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                send_tickets: self.send_tickets,
            })
            .handle(cx, m),

            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::Certificate,
                    HandshakeType::CompressedCertificate,
                ],
            )),
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCompressedCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectCompressedCertificate {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        self.transcript.add_message(&m);
        let compressed_cert = require_handshake_msg_move!(
            m,
            HandshakeType::CompressedCertificate,
            HandshakePayload::CompressedCertificate
        )?;

        let decompressor = match self
            .config
            .cert_decompressors
            .iter()
            .find(|item| item.algorithm() == compressed_cert.alg)
        {
            Some(dec) => dec,
            None => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::BadCertificate,
                    PeerMisbehaved::SelectedUnofferedCertCompression,
                ));
            }
        };

        if compressed_cert.uncompressed_len as usize > CERTIFICATE_MAX_SIZE_LIMIT {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                InvalidMessage::MessageTooLarge,
            ));
        }

        let mut decompress_buffer = vec![0u8; compressed_cert.uncompressed_len as usize];
        if let Err(compress::DecompressionFailed) =
            decompressor.decompress(compressed_cert.compressed.0.bytes(), &mut decompress_buffer)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::InvalidCertCompression,
            ));
        }

        let cert_payload =
            match CertificatePayloadTls13::read(&mut Reader::init(&decompress_buffer)) {
                Ok(cm) => cm,
                Err(err) => {
                    return Err(cx
                        .common
                        .send_fatal_alert(AlertDescription::BadCertificate, err));
                }
            };
        trace!(
            "Client certificate decompressed using {:?} ({} bytes -> {})",
            compressed_cert.alg,
            compressed_cert
                .compressed
                .0
                .bytes()
                .len(),
            compressed_cert.uncompressed_len,
        );

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::CertificateTls13(cert_payload.into_owned()),
            }),
        };

        Box::new(ExpectCertificate {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            send_tickets: self.send_tickets,
            message_already_in_transcript: true,
        })
        .handle(cx, m)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
    message_already_in_transcript: bool,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        if !self.message_already_in_transcript {
            self.transcript.add_message(&m);
        }
        let certp = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?;

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(PeerMisbehaved::UnsolicitedCertExtension.into());
        }

        let client_cert = certp.into_certificate_chain();

        let mandatory = self
            .config
            .verifier
            .client_auth_mandatory();

        let (end_entity, intermediates) = match client_cert.split_first() {
            None => {
                if !mandatory {
                    debug!("client auth requested but no certificate supplied");
                    self.transcript.abandon_client_auth();
                    return Ok(Box::new(ExpectFinished {
                        config: self.config,
                        suite: self.suite,
                        key_schedule: self.key_schedule,
                        transcript: self.transcript,
                        send_tickets: self.send_tickets,
                    }));
                }

                return Err(cx.common.send_fatal_alert(
                    AlertDescription::CertificateRequired,
                    Error::NoCertificatesPresented,
                ));
            }
            Some(chain) => chain,
        };

        let now = self.config.current_time()?;

        self.config
            .verifier
            .verify_client_cert(end_entity, intermediates, now)
            .map_err(|err| {
                cx.common
                    .send_cert_verify_error_alert(err)
            })?;

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_cert: client_cert.into_owned(),
            send_tickets: self.send_tickets,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    client_cert: CertificateChain<'static>,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let rc = {
            let sig = require_handshake_msg!(
                m,
                HandshakeType::CertificateVerify,
                HandshakePayload::CertificateVerify
            )?;
            let handshake_hash = self.transcript.current_hash();
            self.transcript.abandon_client_auth();
            let certs = &self.client_cert;
            let msg = construct_client_verify_message(&handshake_hash);

            self.config
                .verifier
                .verify_tls13_signature(msg.as_ref(), &certs[0], sig)
        };

        if let Err(e) = rc {
            return Err(cx
                .common
                .send_cert_verify_error_alert(e));
        }

        trace!("client CertificateVerify OK");
        cx.common.peer_certificates = Some(self.client_cert);

        self.transcript.add_message(&m);
        Ok(Box::new(ExpectFinished {
            config: self.config,
            suite: self.suite,
            key_schedule: self.key_schedule,
            transcript: self.transcript,
            send_tickets: self.send_tickets,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// --- Process (any number of) early ApplicationData messages,
//     followed by a terminating handshake EndOfEarlyData message ---

struct ExpectEarlyData {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectEarlyData {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::ApplicationData(payload) => {
                match cx
                    .data
                    .early_data
                    .take_received_plaintext(payload)
                {
                    true => Ok(self),
                    false => Err(cx.common.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::TooMuchEarlyDataReceived,
                    )),
                }
            }
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        typ: HandshakeType::EndOfEarlyData,
                        payload: HandshakePayload::EndOfEarlyData,
                    },
                ..
            } => {
                self.key_schedule
                    .update_decrypter(cx.common);
                self.transcript.add_message(&m);
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    suite: self.suite,
                    key_schedule: self.key_schedule,
                    transcript: self.transcript,
                    send_tickets: self.send_tickets,
                }))
            }
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::EndOfEarlyData],
            )),
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// --- Process client's Finished ---
fn get_server_session_value(
    suite: &'static Tls13CipherSuite,
    secret: &ResumptionSecret<'_>,
    cx: &ServerContext<'_>,
    nonce: &[u8],
    time_now: UnixTime,
    age_obfuscation_offset: u32,
) -> persist::ServerSessionValue {
    let version = ProtocolVersion::TLSv1_3;

    let secret = secret.derive_ticket_psk(nonce);

    persist::ServerSessionValue::new(
        cx.data.sni.as_ref(),
        version,
        suite.common.suite,
        secret.as_ref(),
        cx.common.peer_certificates.clone(),
        cx.common.alpn_protocol.clone(),
        cx.data.resumption_data.clone(),
        time_now,
        age_obfuscation_offset,
    )
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
}

impl ExpectFinished {
    fn emit_ticket(
        flight: &mut HandshakeFlightTls13<'_>,
        suite: &'static Tls13CipherSuite,
        cx: &ServerContext<'_>,
        secret: &ResumptionSecret<'_>,
        config: &ServerConfig,
    ) -> Result<(), Error> {
        let secure_random = config.provider.secure_random;
        let nonce = rand::random_vec(secure_random, 32)?;
        let age_add = rand::random_u32(secure_random)?;

        let now = config.current_time()?;

        let plain =
            get_server_session_value(suite, secret, cx, &nonce, now, age_add).get_encoding();

        let stateless = config.ticketer.enabled();
        let (ticket, lifetime) = if stateless {
            let ticket = match config.ticketer.encrypt(&plain) {
                Some(t) => t,
                None => return Ok(()),
            };
            (ticket, config.ticketer.lifetime())
        } else {
            let id = rand::random_vec(secure_random, 32)?;
            let stored = config
                .session_storage
                .put(id.clone(), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
            (id, stateful_lifetime)
        };

        let mut payload = NewSessionTicketPayloadTls13::new(lifetime, age_add, nonce, ticket);

        if config.max_early_data_size > 0 {
            if !stateless {
                payload
                    .exts
                    .push(NewSessionTicketExtension::EarlyData(
                        config.max_early_data_size,
                    ));
            } else {
                // We implement RFC8446 section 8.1: by enforcing that 0-RTT is
                // only possible if using stateful resumption
                warn!("early_data with stateless resumption is not allowed");
            }
        }

        let t = HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTls13(payload),
        };
        trace!("sending new ticket {:?} (stateless: {})", t, stateless);
        flight.add(t);

        Ok(())
    }
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = self.transcript.current_hash();
        let (key_schedule_traffic, expect_verify_data) = self
            .key_schedule
            .sign_client_finish(&handshake_hash, cx.common);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
            }
        };

        // Note: future derivations include Client Finished, but not the
        // main application data keying.
        self.transcript.add_message(&m);

        cx.common.check_aligned_handshake()?;

        let handshake_hash = self.transcript.current_hash();
        let resumption = ResumptionSecret::new(&key_schedule_traffic, &handshake_hash);

        let mut flight = HandshakeFlightTls13::new(&mut self.transcript);
        for _ in 0..self.send_tickets {
            Self::emit_ticket(&mut flight, self.suite, cx, &resumption, &self.config)?;
        }
        flight.finish(cx.common);

        // Application data may now flow, even if we have client auth enabled.
        cx.common
            .start_traffic(&mut cx.sendable_plaintext);

        Ok(match cx.common.is_quic() {
            true => Box::new(ExpectQuicTraffic {
                key_schedule: key_schedule_traffic,
                _fin_verified: fin,
            }),
            false => Box::new(ExpectTraffic {
                key_schedule: key_schedule_traffic,
                _fin_verified: fin,
            }),
        })
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// --- Process traffic ---
struct ExpectTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_key_update(
        &mut self,
        common: &mut CommonState,
        key_update_request: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        if let Protocol::Quic = common.protocol {
            return Err(common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::KeyUpdateReceivedInQuicConnection,
            ));
        }

        common.check_aligned_handshake()?;

        if common.should_update_key(key_update_request)? {
            self.key_schedule
                .update_encrypter_and_notify(common);
        }

        // Update our read-side keys.
        self.key_schedule
            .update_decrypter(common);
        Ok(())
    }
}

impl State<ServerConnectionData> for ExpectTraffic {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::KeyUpdate(key_update),
                        ..
                    },
                ..
            } => self.handle_key_update(cx.common, &key_update)?,
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::KeyUpdate],
                ));
            }
        }

        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.key_schedule
            .export_keying_material(output, label, context)
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.key_schedule
            .extract_secrets(Side::Server)
    }

    fn send_key_update_request(&mut self, common: &mut CommonState) -> Result<(), Error> {
        self.key_schedule
            .request_key_update_and_update_encrypter(common)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectQuicTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: verify::FinishedMessageVerified,
}

impl State<ServerConnectionData> for ExpectQuicTraffic {
    fn handle<'m>(
        self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        // reject all messages
        Err(inappropriate_message(&m.payload, &[]))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.key_schedule
            .export_keying_material(output, label, context)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}
