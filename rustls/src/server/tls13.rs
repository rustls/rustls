use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

pub(crate) use client_hello::TLS13_HANDLER;
use pki_types::{DnsName, UnixTime};
use subtle::ConstantTimeEq;

use super::connection::ServerConnectionData;
use super::hs::{self, HandshakeHashOrBuffer, ServerContext};
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::common_state::{
    Event, HandshakeFlightTls13, HandshakeKind, Input, Output, Side, State, TrafficTemperCounters,
};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::{Direction, KernelState};
use crate::crypto::kx::NamedGroup;
use crate::crypto::{Identity, rand};
use crate::enums::{
    ApplicationProtocol, CertificateType, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warn};
use crate::msgs::{
    CERTIFICATE_MAX_SIZE_LIMIT, CertificatePayloadTls13, Codec, CommonServerSessionValue,
    HandshakeMessagePayload, HandshakePayload, KeyUpdateRequest, Message, MessagePayload,
    NewSessionTicketPayloadTls13, Reader, ServerSessionValue, Tls13ServerSessionValue,
};
use crate::server::ServerConfig;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::key_schedule::{
    KeyScheduleResumption, KeyScheduleTraffic, KeyScheduleTrafficWithClientFinishedPending,
};
use crate::tls13::{
    Tls13CipherSuite, construct_client_verify_message, construct_server_verify_message,
};
use crate::verify::ClientIdentity;
use crate::{ConnectionTrafficSecrets, compress, verify};

mod client_hello {
    use super::*;
    use crate::common_state::{EarlyDataEvent, Protocol};
    use crate::compress::CertCompressor;
    use crate::crypto::cipher::Payload;
    use crate::crypto::kx::SupportedKxGroup;
    use crate::crypto::{SelectedCredential, Signer};
    use crate::enums::ApplicationProtocol;
    use crate::msgs::{
        CertificatePayloadTls13, CertificateRequestExtensions, CertificateRequestPayloadTls13,
        ChangeCipherSpecPayload, ClientHelloPayload, Compression, HandshakeAlignedProof,
        HelloRetryRequest, HelloRetryRequestExtensions, KeyShareEntry, Random, ServerExtensions,
        ServerExtensionsInput, ServerHelloPayload, ServerSessionValue, SessionId, SizedPayload,
        Tls13ServerSessionValue,
    };
    use crate::sealed::Sealed;
    use crate::server::hs::{CertificateTypes, ClientHelloInput, ExpectClientHello, ServerHandler};
    use crate::tls13::key_schedule::{
        KeyScheduleEarlyServer, KeyScheduleHandshake, KeySchedulePreHandshake,
    };
    use crate::verify::DigitallySignedStruct;

    pub(crate) static TLS13_HANDLER: &'static dyn ServerHandler<Tls13CipherSuite> = &Handler;

    #[derive(Debug)]
    struct Handler;

    impl ServerHandler<Tls13CipherSuite> for Handler {
        fn handle_client_hello(
            &self,
            suite: &'static Tls13CipherSuite,
            kx_group: &'static dyn SupportedKxGroup,
            signer: SelectedCredential,
            input: ClientHelloInput<'_>,
            mut st: ExpectClientHello,
            cx: &mut ServerContext<'_>,
        ) -> hs::NextStateOrError {
            let randoms = st.randoms(&input)?;
            let mut transcript = st
                .transcript
                .start(suite.common.hash_provider)?;

            if input
                .client_hello
                .compression_methods
                .len()
                != 1
            {
                return Err(PeerMisbehaved::OfferedIncorrectCompressions.into());
            }

            let shares_ext = input
                .client_hello
                .key_shares
                .as_ref()
                .ok_or(PeerIncompatible::KeyShareExtensionRequired)?;

            if input
                .client_hello
                .has_keyshare_extension_with_duplicates()
            {
                return Err(PeerMisbehaved::OfferedDuplicateKeyShares.into());
            }

            if input
                .client_hello
                .has_certificate_compression_extension_with_duplicates()
            {
                return Err(PeerMisbehaved::OfferedDuplicateCertificateCompressions.into());
            }

            let cert_compressor = input
                .client_hello
                .certificate_compression_algorithms
                .as_ref()
                .and_then(|offered|
                    // prefer server order when choosing a compression: the client's
                    // extension here does not denote any preference.
                    st.config
                        .cert_compressors
                        .iter()
                        .find(|compressor| offered.contains(&compressor.algorithm()))
                        .copied());

            let early_data_requested = input
                .client_hello
                .early_data_request
                .is_some();

            // EarlyData extension is illegal in second ClientHello
            if st.done_retry && early_data_requested {
                return Err(PeerMisbehaved::EarlyDataAttemptedInSecondClientHello.into());
            }

            // See if there is a KeyShare for the selected kx group.
            let chosen_share_and_kxg = shares_ext
                .iter()
                .find_map(|share| (share.group == kx_group.name()).then_some((share, kx_group)));

            let Some(chosen_share_and_kxg) = chosen_share_and_kxg else {
                // We don't have a suitable key share.  Send a HelloRetryRequest
                // for the mutually_preferred_group.
                transcript.add_message(input.message);

                if st.done_retry {
                    return Err(PeerMisbehaved::RefusedToFollowHelloRetryRequest.into());
                }

                emit_hello_retry_request(
                    &mut transcript,
                    suite,
                    input.client_hello.session_id,
                    cx,
                    kx_group.name(),
                );
                if !st.protocol.is_quic() {
                    emit_fake_ccs(cx);
                }

                let skip_early_data = max_early_data_size(st.config.max_early_data_size);

                let next = Box::new(ExpectClientHello {
                    transcript: HandshakeHashOrBuffer::Hash(transcript),
                    session_id: SessionId::empty(),
                    using_ems: false,
                    done_retry: true,
                    ..st
                });
                return if early_data_requested {
                    Ok(Box::new(ExpectAndSkipRejectedEarlyData {
                        skip_data_left: skip_early_data,
                        next,
                    }))
                } else {
                    Ok(next)
                };
            };

            let mut chosen_psk_index = None;
            let mut resumedata = None;

            if let Some(psk_offer) = &input.client_hello.preshared_key_offer {
                // "A client MUST provide a "psk_key_exchange_modes" extension if it
                //  offers a "pre_shared_key" extension. If clients offer
                //  "pre_shared_key" without a "psk_key_exchange_modes" extension,
                //  servers MUST abort the handshake." - RFC8446 4.2.9
                if input
                    .client_hello
                    .preshared_key_modes
                    .is_none()
                {
                    return Err(PeerMisbehaved::MissingPskModesExtension.into());
                }

                if psk_offer.binders.is_empty() {
                    return Err(PeerMisbehaved::MissingBinderInPskExtension.into());
                }

                if psk_offer.binders.len() != psk_offer.identities.len() {
                    return Err(PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders.into());
                }

                let now = st.config.current_time()?;

                for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                    let maybe_resume_data =
                        attempt_tls13_ticket_decryption(psk_id.identity.bytes(), &st.config)
                            .map(|resumedata| {
                                resumedata.set_freshness(psk_id.obfuscated_ticket_age, now)
                            })
                            .filter(|resumedata| {
                                resumedata
                                    .common
                                    .can_resume(suite.common.suite, st.sni.as_ref())
                            });

                    let Some(resume) = maybe_resume_data else {
                        continue;
                    };

                    if !check_binder(
                        &transcript,
                        &KeyScheduleEarlyServer::new(st.protocol, suite, resume.secret.bytes()),
                        input.message,
                        psk_offer.binders[i].as_ref(),
                    ) {
                        return Err(PeerMisbehaved::IncorrectBinder.into());
                    }

                    chosen_psk_index = Some(i);
                    resumedata = Some(resume);
                    break;
                }
            }

            if !input
                .client_hello
                .preshared_key_modes
                .as_ref()
                .map(|offer| offer.psk_dhe)
                .unwrap_or_default()
            {
                debug!("Client unwilling to resume, PSK_DHE_KE not offered");
                st.send_tickets = 0;
                chosen_psk_index = None;
                resumedata = None;
            } else {
                st.send_tickets = st.config.send_tls13_tickets;
            }

            if let Some(resume) = &resumedata {
                cx.emit(Event::ResumptionData(
                    resume
                        .common
                        .application_data
                        .bytes()
                        .to_vec(),
                ));
            }

            let full_handshake = resumedata.is_none();
            transcript.add_message(input.message);
            let key_schedule = emit_server_hello(
                &mut transcript,
                &randoms,
                suite,
                st.protocol,
                cx,
                &input.client_hello.session_id,
                chosen_share_and_kxg,
                chosen_psk_index,
                resumedata
                    .as_ref()
                    .map(|x| x.secret.bytes()),
                &input.proof,
                &st.config,
            )?;
            if !st.done_retry && !st.protocol.is_quic() {
                emit_fake_ccs(cx);
            }

            cx.emit(Event::HandshakeKind(
                match (full_handshake, st.done_retry) {
                    (true, true) => HandshakeKind::FullWithHelloRetryRequest,
                    (true, false) => HandshakeKind::Full,
                    (false, true) => HandshakeKind::ResumedWithHelloRetryRequest,
                    (false, false) => HandshakeKind::Resumed,
                },
            ));

            let mut ocsp_response = signer.ocsp.as_deref();
            let mut flight = HandshakeFlightTls13::new(&mut transcript);
            let (cert_types, doing_early_data, alpn_protocol) = emit_encrypted_extensions(
                &mut flight,
                suite,
                st.protocol,
                cx,
                &mut ocsp_response,
                input.client_hello,
                resumedata.as_ref(),
                st.extra_exts,
                &st.config,
            )?;

            let doing_client_auth = if full_handshake {
                let client_auth = emit_certificate_req_tls13(&mut flight, &st.config)?;

                if let Some(compressor) = cert_compressor {
                    emit_compressed_certificate_tls13(
                        &mut flight,
                        &st.config,
                        &signer,
                        ocsp_response,
                        compressor,
                    );
                } else {
                    emit_certificate_tls13(
                        &mut flight,
                        CertificatePayloadTls13::new(
                            signer.identity.as_certificates(),
                            ocsp_response,
                        ),
                    );
                }
                emit_certificate_verify_tls13(&mut flight, signer.signer)?;
                client_auth
            } else {
                false
            };

            // If we're not doing early data, then the next messages we receive
            // are encrypted with the handshake keys.
            match doing_early_data {
                EarlyDataDecision::Disabled => {
                    key_schedule.set_handshake_decrypter(None, cx, &input.proof);
                }
                EarlyDataDecision::RequestedButRejected => {
                    debug!(
                        "Client requested early_data, but not accepted: switching to handshake keys with trial decryption"
                    );
                    key_schedule.set_handshake_decrypter(
                        Some(max_early_data_size(st.config.max_early_data_size)),
                        cx,
                        &input.proof,
                    );
                }
                EarlyDataDecision::Accepted { .. } => {
                    cx.emit(Event::EarlyData(EarlyDataEvent::Accepted));
                }
            }

            let key_schedule_traffic =
                emit_finished_tls13(flight, &randoms, cx, key_schedule, &st.config, &input.proof);

            if !doing_client_auth && st.config.send_half_rtt_data {
                // Application data can be sent immediately after Finished, in one
                // flight.  However, if client auth is enabled, we don't want to send
                // application data to an unauthenticated peer.
                cx.emit(Event::StartOutgoingTraffic);
            }

            if doing_client_auth {
                if st.config.cert_decompressors.is_empty() {
                    Ok(Box::new(ExpectCertificate {
                        config: st.config,
                        transcript,
                        suite,
                        key_schedule: key_schedule_traffic,
                        alpn_protocol,
                        sni: st.sni,
                        resumption_data: st.resumption_data,
                        send_tickets: st.send_tickets,
                        expected_certificate_type: cert_types.client,
                    }))
                } else {
                    Ok(Box::new(ExpectCertificateOrCompressedCertificate {
                        config: st.config,
                        transcript,
                        suite,
                        key_schedule: key_schedule_traffic,
                        alpn_protocol,
                        sni: st.sni,
                        resumption_data: st.resumption_data,
                        send_tickets: st.send_tickets,
                        expected_certificate_type: cert_types.client,
                    }))
                }
            } else if matches!(doing_early_data, EarlyDataDecision::Accepted { .. })
                && !st.protocol.is_quic()
            {
                let EarlyDataDecision::Accepted { max_length } = doing_early_data else {
                    unreachable!();
                };
                // Not used for QUIC: RFC 9001 §8.3: Clients MUST NOT send the EndOfEarlyData
                // message. A server MUST treat receipt of a CRYPTO frame in a 0-RTT packet as a
                // connection error of type PROTOCOL_VIOLATION.
                Ok(Box::new(ExpectEarlyData {
                    config: st.config,
                    transcript,
                    suite,
                    key_schedule: key_schedule_traffic,
                    alpn_protocol,
                    sni: st.sni,
                    peer_identity: resumedata.and_then(|r| r.common.peer_identity),
                    resumption_data: st.resumption_data,
                    send_tickets: st.send_tickets,
                    remaining_length: max_length as usize,
                }))
            } else {
                Ok(Box::new(ExpectFinished {
                    config: st.config,
                    transcript,
                    suite,
                    key_schedule: key_schedule_traffic,
                    alpn_protocol,
                    sni: st.sni,
                    peer_identity: resumedata.and_then(|r| r.common.peer_identity),
                    resumption_data: st.resumption_data,
                    send_tickets: st.send_tickets,
                }))
            }
        }
    }

    impl Sealed for Handler {}

    #[derive(PartialEq)]
    pub(super) enum EarlyDataDecision {
        Disabled,
        RequestedButRejected,
        Accepted { max_length: u32 },
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

    fn check_binder(
        transcript: &HandshakeHash,
        key_schedule: &KeyScheduleEarlyServer,
        client_hello: &Message<'_>,
        binder: &[u8],
    ) -> bool {
        let binder_plaintext = match &client_hello.payload {
            MessagePayload::Handshake { parsed, encoded } => {
                &encoded.bytes()[..encoded.bytes().len() - parsed.total_binder_length()]
            }
            _ => unreachable!(),
        };

        let handshake_hash = transcript.hash_given(binder_plaintext);

        let real_binder =
            key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

        ConstantTimeEq::ct_eq(real_binder.as_ref(), binder).into()
    }

    fn attempt_tls13_ticket_decryption(
        ticket: &[u8],
        config: &ServerConfig,
    ) -> Option<Tls13ServerSessionValue> {
        let plain = match config.ticketer.as_deref() {
            Some(ticketer) => ticketer.decrypt(ticket)?,
            None => config.session_storage.take(ticket)?,
        };

        match ServerSessionValue::read_bytes(&plain).ok()? {
            ServerSessionValue::Tls13(tls13) => Some(tls13),
            _ => None,
        }
    }

    fn emit_server_hello(
        transcript: &mut HandshakeHash,
        randoms: &ConnectionRandoms,
        suite: &'static Tls13CipherSuite,
        protocol: Protocol,
        cx: &mut ServerContext<'_>,
        session_id: &SessionId,
        share_and_kxgroup: (&KeyShareEntry, &'static dyn SupportedKxGroup),
        chosen_psk_idx: Option<usize>,
        resuming_psk: Option<&[u8]>,
        proof: &HandshakeAlignedProof,
        config: &ServerConfig,
    ) -> Result<KeyScheduleHandshake, Error> {
        // Prepare key exchange; the caller already found the matching SupportedKxGroup
        let (share, kxgroup) = share_and_kxgroup;
        debug_assert_eq!(kxgroup.name(), share.group);
        let ckx = kxgroup.start_and_complete(share.payload.bytes())?;
        cx.emit(Event::KeyExchangeGroup(kxgroup));

        let extensions = Box::new(ServerExtensions {
            key_share: Some(KeyShareEntry::new(ckx.group, ckx.pub_key)),
            preshared_key: chosen_psk_idx.map(|idx| idx as u16),
            selected_version: Some(ProtocolVersion::TLSv1_3),
            ..Default::default()
        });

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(randoms.server),
                    session_id: *session_id,
                    cipher_suite: suite.common.suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            )),
        };

        let client_hello_hash = transcript.hash_given(&[]);

        trace!("sending server hello {sh:?}");
        transcript.add_message(&sh);
        cx.emit(Event::PlainMessage(sh));

        // Start key schedule
        let key_schedule_pre_handshake = if let Some(psk) = resuming_psk {
            let early_key_schedule = KeyScheduleEarlyServer::new(protocol, suite, psk);
            early_key_schedule.client_early_traffic_secret(
                &client_hello_hash,
                &*config.key_log,
                &randoms.client,
                cx,
                proof,
            );

            if config.max_early_data_size > 0 {
                cx.emit(Event::EarlyExporter(early_key_schedule.early_exporter(
                    &client_hello_hash,
                    &*config.key_log,
                    &randoms.client,
                )));
            }

            KeySchedulePreHandshake::from(early_key_schedule)
        } else {
            KeySchedulePreHandshake::new(Side::Server, protocol, suite)
        };

        // Do key exchange
        let key_schedule = key_schedule_pre_handshake.into_handshake(ckx.secret);

        let handshake_hash = transcript.current_hash();
        let key_schedule = key_schedule.derive_server_handshake_secrets(
            handshake_hash,
            &*config.key_log,
            &randoms.client,
            cx,
        );

        Ok(key_schedule)
    }

    fn emit_fake_ccs(output: &mut dyn Output) {
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };
        output.emit(Event::PlainMessage(m));
    }

    fn emit_hello_retry_request(
        transcript: &mut HandshakeHash,
        suite: &'static Tls13CipherSuite,
        session_id: SessionId,
        output: &mut dyn Output,
        group: NamedGroup,
    ) {
        let req = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id,
            cipher_suite: suite.common.suite,
            extensions: HelloRetryRequestExtensions {
                key_share: Some(group),
                supported_versions: Some(ProtocolVersion::TLSv1_3),
                ..Default::default()
            },
        };

        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(req),
            )),
        };

        trace!("Requesting retry {m:?}");
        transcript.rollup_for_hrr();
        transcript.add_message(&m);
        output.emit(Event::PlainMessage(m));
    }

    fn decide_if_early_data_allowed(
        cx: &mut ServerContext<'_>,
        client_hello: &ClientHelloPayload,
        resumedata: Option<&Tls13ServerSessionValue>,
        chosen_alpn_protocol: Option<&ApplicationProtocol<'_>>,
        suite: &'static Tls13CipherSuite,
        protocol: Protocol,
        config: &ServerConfig,
    ) -> EarlyDataDecision {
        let early_data_requested = client_hello
            .early_data_request
            .is_some();
        let rejected_or_disabled = match early_data_requested {
            true => EarlyDataDecision::RequestedButRejected,
            false => EarlyDataDecision::Disabled,
        };

        let Some(resume) = resumedata else {
            // never any early data if not resuming.
            return rejected_or_disabled;
        };

        /* Non-zero max_early_data_size controls whether early_data is allowed at all.
         * We also require stateful resumption. */
        let early_data_configured = config.max_early_data_size > 0 && config.ticketer.is_none();

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
            && resume.common.cipher_suite == suite.common.suite
            && resume.common.alpn.as_ref() == chosen_alpn_protocol;

        if early_data_configured && early_data_possible {
            EarlyDataDecision::Accepted {
                max_length: config.max_early_data_size,
            }
        } else {
            if protocol.is_quic() {
                cx.emit(Event::QuicEarlySecret(None));
            }

            rejected_or_disabled
        }
    }

    fn emit_encrypted_extensions(
        flight: &mut HandshakeFlightTls13<'_>,
        suite: &'static Tls13CipherSuite,
        protocol: Protocol,
        cx: &mut ServerContext<'_>,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&Tls13ServerSessionValue>,
        extra_exts: ServerExtensionsInput,
        config: &ServerConfig,
    ) -> Result<
        (
            CertificateTypes,
            EarlyDataDecision,
            Option<ApplicationProtocol<'static>>,
        ),
        Error,
    > {
        let mut ep = hs::ExtensionProcessing::new(extra_exts, protocol, hello, config);
        let (cert_types, alpn_protocol) =
            ep.process_common(cx, ocsp_response, resumedata.map(|r| &r.common))?;

        let early_data = decide_if_early_data_allowed(
            cx,
            hello,
            resumedata,
            alpn_protocol.as_ref(),
            suite,
            protocol,
            config,
        );
        if let EarlyDataDecision::Accepted { .. } = early_data {
            ep.extensions.early_data_ack = Some(());
        }

        let ee = HandshakeMessagePayload(HandshakePayload::EncryptedExtensions(ep.extensions));

        trace!("sending encrypted extensions {ee:?}");
        flight.add(ee);
        Ok((cert_types, early_data, alpn_protocol))
    }

    fn emit_certificate_req_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        config: &ServerConfig,
    ) -> Result<bool, Error> {
        if !config.verifier.offer_client_auth() {
            return Ok(false);
        }

        let cr = CertificateRequestPayloadTls13 {
            context: SizedPayload::from(Payload::Borrowed(&[])),
            extensions: CertificateRequestExtensions {
                signature_algorithms: Some(
                    config
                        .verifier
                        .supported_verify_schemes(),
                ),
                authority_names: match config
                    .verifier
                    .root_hint_subjects()
                    .as_ref()
                {
                    [] => None,
                    authorities => Some(authorities.to_vec()),
                },
                certificate_compression_algorithms: match config.cert_decompressors.as_slice() {
                    &[] => None,
                    decomps => Some(
                        decomps
                            .iter()
                            .map(|decomp| decomp.algorithm())
                            .collect(),
                    ),
                },
            },
        };

        let creq = HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(cr));

        trace!("Sending CertificateRequest {creq:?}");
        flight.add(creq);
        Ok(true)
    }

    fn emit_certificate_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        payload: CertificatePayloadTls13<'_>,
    ) {
        let cert = HandshakeMessagePayload(HandshakePayload::CertificateTls13(payload));
        trace!("sending certificate {cert:?}");
        flight.add(cert);
    }

    fn emit_compressed_certificate_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        config: &ServerConfig,
        signer: &SelectedCredential,
        ocsp_response: Option<&[u8]>,
        cert_compressor: &'static dyn CertCompressor,
    ) {
        let payload =
            CertificatePayloadTls13::new(signer.identity.as_certificates(), ocsp_response);
        let Ok(entry) = config
            .cert_compression_cache
            .compression_for(cert_compressor, &payload)
        else {
            return emit_certificate_tls13(flight, payload);
        };

        let c = HandshakeMessagePayload(HandshakePayload::CompressedCertificate(
            entry.compressed_cert_payload(),
        ));

        trace!("sending compressed certificate {c:?}");
        flight.add(c);
    }

    fn emit_certificate_verify_tls13(
        flight: &mut HandshakeFlightTls13<'_>,
        signer: Box<dyn Signer>,
    ) -> Result<(), Error> {
        let message = construct_server_verify_message(&flight.transcript.current_hash());
        let scheme = signer.scheme();
        let sig = signer.sign(message.as_ref())?;

        let cv = DigitallySignedStruct::new(scheme, sig);

        let cv = HandshakeMessagePayload(HandshakePayload::CertificateVerify(cv));

        trace!("sending certificate-verify {cv:?}");
        flight.add(cv);
        Ok(())
    }

    fn emit_finished_tls13(
        mut flight: HandshakeFlightTls13<'_>,
        randoms: &ConnectionRandoms,
        cx: &mut ServerContext<'_>,
        key_schedule: KeyScheduleHandshake,
        config: &ServerConfig,
        proof: &HandshakeAlignedProof,
    ) -> KeyScheduleTrafficWithClientFinishedPending {
        let handshake_hash = flight.transcript.current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash, proof);
        let verify_data_payload = Payload::new(verify_data.as_ref());

        let fin = HandshakeMessagePayload(HandshakePayload::Finished(verify_data_payload));

        trace!("sending finished {fin:?}");
        flight.add(fin);
        let hash_at_server_fin = flight.transcript.current_hash();
        flight.finish(cx);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        key_schedule.into_traffic_with_client_finished_pending(
            hash_at_server_fin,
            &*config.key_log,
            &randoms.client,
            cx,
        )
    }
}

struct ExpectAndSkipRejectedEarlyData {
    skip_data_left: usize,
    next: Box<hs::ExpectClientHello>,
}

impl State<ServerConnectionData> for ExpectAndSkipRejectedEarlyData {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        /* "The server then ignores early data by skipping all records with an external
         *  content type of "application_data" (indicating that they are encrypted),
         *  up to the configured max_early_data_size."
         * (RFC8446, 14.2.10) */
        if let MessagePayload::ApplicationData(skip_data) = &input.message.payload {
            if skip_data.bytes().len() <= self.skip_data_left {
                self.skip_data_left -= skip_data.bytes().len();
                return Ok(self);
            }
        }

        self.next.handle(cx, input)
    }
}

struct ExpectCertificateOrCompressedCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
    expected_certificate_type: CertificateType,
}

impl State<ServerConnectionData> for ExpectCertificateOrCompressedCertificate {
    fn handle(
        self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        match input.message.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(..)),
                ..
            } => ExpectCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                alpn_protocol: self.alpn_protocol,
                sni: self.sni,
                resumption_data: self.resumption_data,
                send_tickets: self.send_tickets,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => ExpectCompressedCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                alpn_protocol: self.alpn_protocol,
                sni: self.sni,
                resumption_data: self.resumption_data,
                send_tickets: self.send_tickets,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

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
}

struct ExpectCompressedCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
    expected_certificate_type: CertificateType,
}

impl ExpectCompressedCertificate {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> hs::NextStateOrError {
        self.transcript.add_message(&message);
        let compressed_cert = require_handshake_msg_move!(
            message,
            HandshakeType::CompressedCertificate,
            HandshakePayload::CompressedCertificate
        )?;

        let selected_decompressor = self
            .config
            .cert_decompressors
            .iter()
            .find(|item| item.algorithm() == compressed_cert.alg);

        let Some(decompressor) = selected_decompressor else {
            return Err(PeerMisbehaved::SelectedUnofferedCertCompression.into());
        };

        if compressed_cert.uncompressed_len as usize > CERTIFICATE_MAX_SIZE_LIMIT {
            return Err(InvalidMessage::CertificatePayloadTooLarge.into());
        }

        let mut decompress_buffer = vec![0u8; compressed_cert.uncompressed_len as usize];
        if let Err(compress::DecompressionFailed) =
            decompressor.decompress(compressed_cert.compressed.bytes(), &mut decompress_buffer)
        {
            return Err(PeerMisbehaved::InvalidCertCompression.into());
        }

        let cert_payload = CertificatePayloadTls13::read(&mut Reader::init(&decompress_buffer))?;
        trace!(
            "Client certificate decompressed using {:?} ({} bytes -> {})",
            compressed_cert.alg,
            compressed_cert.compressed.bytes().len(),
            compressed_cert.uncompressed_len,
        );

        ExpectCertificate {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            alpn_protocol: self.alpn_protocol,
            sni: self.sni,
            resumption_data: self.resumption_data,
            send_tickets: self.send_tickets,
            expected_certificate_type: self.expected_certificate_type,
        }
        .handle_certificate(cert_payload)
    }
}

struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
    expected_certificate_type: CertificateType,
}

impl ExpectCertificate {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> hs::NextStateOrError {
        self.transcript.add_message(&message);
        self.handle_certificate(require_handshake_msg_move!(
            message,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?)
    }

    fn handle_certificate(mut self, certp: CertificatePayloadTls13<'_>) -> hs::NextStateOrError {
        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp
            .entries
            .iter()
            .any(|e| !e.extensions.only_contains(&[]))
        {
            return Err(PeerMisbehaved::UnsolicitedCertExtension.into());
        }

        let client_cert = certp.into_certificate_chain();

        let mandatory = self
            .config
            .verifier
            .client_auth_mandatory();

        let peer_identity = Identity::from_peer(client_cert.0, self.expected_certificate_type)?;

        let Some(peer_identity) = peer_identity else {
            if !mandatory {
                debug!("client auth requested but no certificate supplied");
                self.transcript.abandon_client_auth();
                return Ok(Box::new(ExpectFinished {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: self.key_schedule,
                    peer_identity: None,
                    sni: self.sni,
                    alpn_protocol: self.alpn_protocol,
                    resumption_data: self.resumption_data,
                    send_tickets: self.send_tickets,
                }));
            }

            return Err(PeerMisbehaved::NoCertificatesPresented.into());
        };

        self.config
            .verifier
            .verify_identity(&ClientIdentity {
                identity: &peer_identity,
                now: self.config.current_time()?,
            })?;

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            alpn_protocol: self.alpn_protocol,
            sni: self.sni,
            peer_identity: peer_identity.into_owned(),
            resumption_data: self.resumption_data,
            send_tickets: self.send_tickets,
        }))
    }
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        self.handle_input(input)
    }
}

struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    peer_identity: Identity<'static>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        let signature = require_handshake_msg!(
            message,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;
        let handshake_hash = self.transcript.current_hash();
        self.transcript.abandon_client_auth();

        self.config
            .verifier
            .verify_tls13_signature(&verify::SignatureVerificationInput {
                message: construct_client_verify_message(&handshake_hash).as_ref(),
                signer: &self.peer_identity.as_signer(),
                signature,
            })?;

        trace!("client CertificateVerify OK");

        self.transcript.add_message(&message);
        Ok(Box::new(ExpectFinished {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            alpn_protocol: self.alpn_protocol,
            sni: self.sni,
            peer_identity: Some(self.peer_identity),
            resumption_data: self.resumption_data,
            send_tickets: self.send_tickets,
        }))
    }
}

// --- Process (any number of) early ApplicationData messages,
//     followed by a terminating handshake EndOfEarlyData message ---

struct ExpectEarlyData {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    peer_identity: Option<Identity<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
    remaining_length: usize,
}

impl State<ServerConnectionData> for ExpectEarlyData {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        match input.message.payload {
            MessagePayload::ApplicationData(payload) => {
                self.remaining_length = match self
                    .remaining_length
                    .checked_sub(payload.bytes().len())
                {
                    Some(sub) => sub,
                    None => return Err(PeerMisbehaved::TooMuchEarlyDataReceived.into()),
                };

                cx.emit(Event::EarlyApplicationData(payload));
                Ok(self)
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::EndOfEarlyData),
                ..
            } => {
                let proof = input.check_aligned_handshake()?;
                self.key_schedule
                    .update_decrypter(cx, &proof);
                self.transcript
                    .add_message(&input.message);
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    transcript: self.transcript,
                    suite: self.suite,
                    key_schedule: self.key_schedule,
                    alpn_protocol: self.alpn_protocol,
                    sni: self.sni,
                    peer_identity: self.peer_identity,
                    resumption_data: self.resumption_data,
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
}

// --- Process client's Finished ---
fn get_server_session_value(
    suite: &'static Tls13CipherSuite,
    resumption: &KeyScheduleResumption,
    peer_identity: Option<Identity<'static>>,
    chosen_alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: &[u8],
    nonce: &[u8],
    time_now: UnixTime,
    age_obfuscation_offset: u32,
) -> ServerSessionValue {
    let secret = resumption.derive_ticket_psk(nonce);

    Tls13ServerSessionValue::new(
        CommonServerSessionValue::new(
            sni.as_ref(),
            suite.common.suite,
            peer_identity,
            chosen_alpn_protocol,
            resumption_data.to_vec(),
            time_now,
        ),
        secret.as_ref(),
        age_obfuscation_offset,
    )
    .into()
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    peer_identity: Option<Identity<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
}

impl ExpectFinished {
    fn emit_ticket(
        flight: &mut HandshakeFlightTls13<'_>,
        suite: &'static Tls13CipherSuite,
        peer_identity: Option<Identity<'static>>,
        chosen_alpn_protocol: Option<ApplicationProtocol<'static>>,
        sni: Option<DnsName<'static>>,
        resumption_data: &[u8],
        resumption: &KeyScheduleResumption,
        config: &ServerConfig,
    ) -> Result<(), Error> {
        let secure_random = config.provider.secure_random;
        let nonce = rand::random_array(secure_random)?;
        let age_add = rand::random_u32(secure_random)?;

        let now = config.current_time()?;

        let plain = get_server_session_value(
            suite,
            resumption,
            peer_identity,
            chosen_alpn_protocol,
            sni,
            resumption_data,
            &nonce,
            now,
            age_add,
        )
        .get_encoding();

        let ticketer = config.ticketer.as_deref();
        let (ticket, lifetime) = if let Some(ticketer) = ticketer {
            let Some(ticket) = ticketer.encrypt(&plain) else {
                return Ok(());
            };
            (ticket, ticketer.lifetime())
        } else {
            let id = rand::random_array::<32>(secure_random)?.to_vec();
            let stored = config
                .session_storage
                .put(id.clone(), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = Duration::from_secs(24 * 60 * 60); // this is a bit of a punt
            (id, stateful_lifetime)
        };

        let mut payload = NewSessionTicketPayloadTls13::new(lifetime, age_add, nonce, ticket);

        if config.max_early_data_size > 0 {
            if ticketer.is_none() {
                payload.extensions.max_early_data_size = Some(config.max_early_data_size);
            } else {
                // We implement RFC8446 section 8.1: by enforcing that 0-RTT is
                // only possible if using stateful resumption
                warn!("early_data with stateless resumption is not allowed");
            }
        }

        let t = HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(payload));
        trace!(
            "sending new ticket {t:?} (stateless: {})",
            ticketer.is_some()
        );
        flight.add(t);

        Ok(())
    }
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let handshake_hash = self.transcript.current_hash();
        let proof = input.check_aligned_handshake()?;
        let (key_schedule_before_finished, expect_verify_data) = self
            .key_schedule
            .sign_client_finish(&handshake_hash, cx, &proof);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => return Err(PeerMisbehaved::IncorrectFinished.into()),
        };

        // Note: future derivations include Client Finished, but not the
        // main application data keying.
        self.transcript
            .add_message(&input.message);

        let (key_schedule_traffic, exporter, resumption) =
            key_schedule_before_finished.into_traffic(self.transcript.current_hash());

        let mut flight = HandshakeFlightTls13::new(&mut self.transcript);
        for _ in 0..self.send_tickets {
            Self::emit_ticket(
                &mut flight,
                self.suite,
                self.peer_identity.clone(),
                self.alpn_protocol.clone(),
                self.sni.clone(),
                &self.resumption_data,
                &resumption,
                &self.config,
            )?;
        }
        flight.finish(cx);

        // Application data may now flow, even if we have client auth enabled.
        if let Some(identity) = self.peer_identity {
            cx.emit(Event::PeerIdentity(identity));
        }
        cx.emit(Event::Exporter(Box::new(exporter)));
        cx.emit(Event::StartTraffic);

        Ok(
            match key_schedule_traffic
                .protocol()
                .is_quic()
            {
                true => Box::new(ExpectQuicTraffic { _fin_verified: fin }),
                false => Box::new(ExpectTraffic {
                    config: self.config,
                    counters: TrafficTemperCounters::default(),
                    key_schedule: key_schedule_traffic,
                    _fin_verified: fin,
                }),
            },
        )
    }
}

// --- Process traffic ---
struct ExpectTraffic {
    config: Arc<ServerConfig>,
    key_schedule: KeyScheduleTraffic,
    counters: TrafficTemperCounters,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_key_update(
        &mut self,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
        key_update_request: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        if self.key_schedule.protocol().is_quic() {
            return Err(PeerMisbehaved::KeyUpdateReceivedInQuicConnection.into());
        }

        let proof = input.check_aligned_handshake()?;

        self.counters
            .received_key_update_request()?;

        match key_update_request {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                cx.emit(Event::MaybeKeyUpdateRequest(&mut self.key_schedule))
            }
            _ => return Err(InvalidMessage::InvalidKeyUpdate.into()),
        }

        // Update our read-side keys.
        self.key_schedule
            .update_decrypter(cx, &proof);
        Ok(())
    }
}

impl State<ServerConnectionData> for ExpectTraffic {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ServerContext<'_>,
        input: Input<'_>,
    ) -> hs::NextStateOrError {
        match input.message.payload {
            MessagePayload::ApplicationData(payload) => {
                self.counters.received_app_data();
                cx.emit(Event::ApplicationData(payload));
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(key_update)),
                ..
            } => self.handle_key_update(cx, input, &key_update)?,
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

    fn send_key_update_request(&mut self, output: &mut dyn Output) -> Result<(), Error> {
        self.key_schedule
            .request_key_update_and_update_encrypter(output)
    }

    fn into_external_state(
        self: Box<Self>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        if !self.config.enable_secret_extraction {
            return Err(ApiMisuse::SecretExtractionRequiresPriorOptIn.into());
        }
        Ok((
            self.key_schedule
                .extract_secrets(Side::Server)?,
            self,
        ))
    }
}

impl KernelState for ExpectTraffic {
    fn update_secrets(&mut self, dir: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        self.key_schedule
            .refresh_traffic_secret(match dir {
                Direction::Transmit => Side::Server,
                Direction::Receive => Side::Client,
            })
    }

    fn handle_new_session_ticket(
        &self,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        unreachable!(
            "server connections should never have handle_new_session_ticket called on them"
        )
    }
}

struct ExpectQuicTraffic {
    _fin_verified: verify::FinishedMessageVerified,
}

impl State<ServerConnectionData> for ExpectQuicTraffic {
    fn handle(
        self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        Input { message, .. }: Input<'_>,
    ) -> hs::NextStateOrError {
        // reject all messages
        Err(inappropriate_message(&message.payload, &[]))
    }
}

impl KernelState for ExpectQuicTraffic {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn update_secrets(&mut self, _: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        Err(Error::Unreachable(
            "QUIC connections do not support key updates",
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_new_session_ticket(
        &self,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        unreachable!("handle_new_session_ticket should not be called for server-side connections")
    }
}
