use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

pub(crate) use client_hello::TLS13_HANDLER;
use pki_types::{DnsName, UnixTime};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::config::ServerConfig;
use super::hs::{self, HandshakeHashOrBuffer};
use super::{CommonServerSessionValue, ServerSessionKey, ServerSessionValue};
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::common_state::{
    Event, HandshakeFlightTls13, HandshakeKind, Input, Output, Side, State, TrafficTemperCounters,
};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::KernelState;
use crate::crypto::cipher::Payload;
use crate::crypto::kx::NamedGroup;
use crate::crypto::{Identity, rand};
use crate::enums::{
    ApplicationProtocol, CertificateType, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warn};
use crate::msgs::{
    CERTIFICATE_MAX_SIZE_LIMIT, CertificatePayloadTls13, Codec, HandshakeMessagePayload,
    HandshakePayload, KeyUpdateRequest, Message, MessagePayload, NewSessionTicketPayloadTls13,
    PresharedKeyIdentity, Reader, SizedPayload,
};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::key_schedule::{
    KeyScheduleResumption, KeyScheduleTrafficReceive, KeyScheduleTrafficSend,
    KeyScheduleTrafficWithClientFinishedPending,
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
        ServerExtensionsInput, ServerHelloPayload, SessionId, SizedPayload,
    };
    use crate::sealed::Sealed;
    use crate::server::Tls13ServerSessionValue;
    use crate::server::hs::{ClientHelloInput, ExpectClientHello, ServerHandler, Tls13Extensions};
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
            output: &mut dyn Output,
        ) -> Result<Box<dyn State>, Error> {
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
                    output,
                    kx_group.name(),
                );
                if !st.protocol.is_quic() {
                    emit_fake_ccs(output);
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

            let mut resuming = handle_psk_offer(
                &input,
                &transcript,
                st.sni.as_ref(),
                suite,
                st.protocol,
                &st.config,
            )?;

            if !input
                .client_hello
                .preshared_key_modes
                .as_ref()
                .map(|offer| offer.psk_dhe)
                .unwrap_or_default()
            {
                debug!("Client unwilling to resume, PSK_DHE_KE not offered");
                st.send_tickets = 0;
                resuming = None;
            } else {
                st.send_tickets = st.config.send_tls13_tickets;
            }

            if let Some((_, session)) = &resuming {
                output.emit(Event::ResumptionData(
                    session
                        .common
                        .application_data
                        .bytes()
                        .to_vec(),
                ));
            }

            let full_handshake = resuming.is_none();
            transcript.add_message(input.message);
            let key_schedule = emit_server_hello(
                &mut transcript,
                &randoms,
                suite,
                st.protocol,
                output,
                &input.client_hello.session_id,
                chosen_share_and_kxg,
                resuming.as_ref(),
                &input.proof,
                &st.config,
            )?;
            if !st.done_retry && !st.protocol.is_quic() {
                emit_fake_ccs(output);
            }

            output.emit(Event::HandshakeKind(
                match (full_handshake, st.done_retry) {
                    (true, true) => HandshakeKind::FullWithHelloRetryRequest,
                    (true, false) => HandshakeKind::Full,
                    (false, true) => HandshakeKind::ResumedWithHelloRetryRequest,
                    (false, false) => HandshakeKind::Resumed,
                },
            ));

            let mut ocsp_response = signer.ocsp.as_deref();
            let mut flight = HandshakeFlightTls13::new(&mut transcript);
            let (
                Tls13Extensions {
                    certificate_types,
                    alpn_protocol,
                },
                doing_early_data,
            ) = emit_encrypted_extensions(
                &mut flight,
                suite,
                output,
                &mut ocsp_response,
                input.client_hello,
                resuming
                    .as_ref()
                    .map(|(_, session)| session),
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
                    key_schedule.set_handshake_decrypter(None, output, &input.proof);
                }
                EarlyDataDecision::RequestedButRejected => {
                    debug!(
                        "Client requested early_data, but not accepted: switching to handshake keys with trial decryption"
                    );
                    key_schedule.set_handshake_decrypter(
                        Some(max_early_data_size(st.config.max_early_data_size)),
                        output,
                        &input.proof,
                    );
                }
                EarlyDataDecision::Accepted { .. } => {
                    output.emit(Event::EarlyData(EarlyDataEvent::Accepted));
                }
            }

            let key_schedule_traffic = emit_finished_tls13(
                flight,
                &randoms,
                output,
                key_schedule,
                &st.config,
                &input.proof,
            );

            if !doing_client_auth && st.config.send_half_rtt_data {
                // Application data can be sent immediately after Finished, in one
                // flight.  However, if client auth is enabled, we don't want to send
                // application data to an unauthenticated peer.
                output.send().start_outgoing_traffic();
            }

            let hs = HandshakeState {
                config: st.config,
                transcript,
                suite,
                alpn_protocol,
                sni: st.sni,
                resumption_data: st.resumption_data,
                send_tickets: st.send_tickets,
            };

            if doing_client_auth {
                if hs.config.cert_decompressors.is_empty() {
                    Ok(Box::new(ExpectCertificate {
                        hs,
                        key_schedule: key_schedule_traffic,
                        expected_certificate_type: certificate_types.client,
                    }))
                } else {
                    Ok(Box::new(ExpectCertificateOrCompressedCertificate {
                        hs,
                        key_schedule: key_schedule_traffic,
                        expected_certificate_type: certificate_types.client,
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
                    hs,
                    key_schedule: key_schedule_traffic,
                    peer_identity: resuming.and_then(|(_, session)| session.common.peer_identity),
                    remaining_length: max_length as usize,
                }))
            } else {
                Ok(Box::new(ExpectFinished {
                    hs,
                    key_schedule: key_schedule_traffic,
                    peer_identity: resuming.and_then(|(_, session)| session.common.peer_identity),
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

    fn handle_psk_offer(
        input: &ClientHelloInput<'_>,
        transcript: &HandshakeHash,
        sni: Option<&DnsName<'_>>,
        suite: &'static Tls13CipherSuite,
        protocol: Protocol,
        config: &ServerConfig,
    ) -> Result<Option<(usize, Tls13ServerSessionValue<'static>)>, Error> {
        let Some(psk_offer) = &input.client_hello.preshared_key_offer else {
            return Ok(None);
        };

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

        let now = config.current_time()?;
        for (i, psk_id) in psk_offer.identities.iter().enumerate() {
            let Some(mut session) = Tls13ServerSessionValue::from_ticket(psk_id, config) else {
                continue;
            };

            session.set_freshness(psk_id.obfuscated_ticket_age, now);
            if !session
                .common
                .can_resume(suite.common.suite, sni)
            {
                continue;
            }

            if !check_binder(
                transcript,
                &KeyScheduleEarlyServer::new(protocol, suite, session.secret.bytes()),
                input.message,
                psk_offer.binders[i].as_ref(),
            ) {
                return Err(PeerMisbehaved::IncorrectBinder.into());
            }

            return Ok(Some((i, session.into_owned())));
        }

        Ok(None)
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

    fn emit_server_hello(
        transcript: &mut HandshakeHash,
        randoms: &ConnectionRandoms,
        suite: &'static Tls13CipherSuite,
        protocol: Protocol,
        output: &mut dyn Output,
        session_id: &SessionId,
        share_and_kxgroup: (&KeyShareEntry, &'static dyn SupportedKxGroup),
        resuming: Option<&(usize, Tls13ServerSessionValue<'_>)>,
        proof: &HandshakeAlignedProof,
        config: &ServerConfig,
    ) -> Result<KeyScheduleHandshake, Error> {
        // Prepare key exchange; the caller already found the matching SupportedKxGroup
        let (share, kxgroup) = share_and_kxgroup;
        debug_assert_eq!(kxgroup.name(), share.group);
        let ckx = kxgroup.start_and_complete(share.payload.bytes())?;
        output.emit(Event::KeyExchangeGroup(kxgroup));

        let extensions = Box::new(ServerExtensions {
            key_share: Some(KeyShareEntry::new(ckx.group, ckx.pub_key)),
            preshared_key: resuming.map(|&(idx, _)| idx as u16),
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
        output.send_msg(sh, false);

        // Start key schedule
        let key_schedule_pre_handshake = if let Some((_, psk)) = resuming {
            let early_key_schedule =
                KeyScheduleEarlyServer::new(protocol, suite, psk.secret.bytes());
            early_key_schedule.client_early_traffic_secret(
                &client_hello_hash,
                &*config.key_log,
                &randoms.client,
                output,
                proof,
            );

            if config.max_early_data_size > 0 {
                output.emit(Event::EarlyExporter(early_key_schedule.early_exporter(
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
            output,
        );

        Ok(key_schedule)
    }

    fn emit_fake_ccs(output: &mut dyn Output) {
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };
        output.send_msg(m, false);
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
        output.send_msg(m, false);
    }

    fn decide_if_early_data_allowed(
        output: &mut dyn Output,
        client_hello: &ClientHelloPayload,
        resumedata: Option<&Tls13ServerSessionValue<'_>>,
        chosen_alpn_protocol: Option<&ApplicationProtocol<'_>>,
        suite: &'static Tls13CipherSuite,
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
            if let Some(quic) = output.quic() {
                quic.early_secret = None;
            }

            rejected_or_disabled
        }
    }

    fn emit_encrypted_extensions(
        flight: &mut HandshakeFlightTls13<'_>,
        suite: &'static Tls13CipherSuite,
        output: &mut dyn Output,
        ocsp_response: &mut Option<&[u8]>,
        hello: &ClientHelloPayload,
        resumedata: Option<&Tls13ServerSessionValue<'_>>,
        extra_exts: ServerExtensionsInput,
        config: &ServerConfig,
    ) -> Result<(Tls13Extensions, EarlyDataDecision), Error> {
        let (out, mut extensions) = Tls13Extensions::new(
            extra_exts,
            ocsp_response,
            resumedata.map(|r| &r.common),
            hello,
            output,
            config,
        )?;

        let early_data = decide_if_early_data_allowed(
            output,
            hello,
            resumedata,
            out.alpn_protocol.as_ref(),
            suite,
            config,
        );
        if let EarlyDataDecision::Accepted { .. } = early_data {
            extensions.early_data_ack = Some(());
        }

        let ee = HandshakeMessagePayload(HandshakePayload::EncryptedExtensions(extensions));

        trace!("sending encrypted extensions {ee:?}");
        flight.add(ee);
        Ok((out, early_data))
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
        output: &mut dyn Output,
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
        flight.finish(output);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        key_schedule.into_traffic_with_client_finished_pending(
            hash_at_server_fin,
            &*config.key_log,
            &randoms.client,
            output,
        )
    }
}

struct ExpectAndSkipRejectedEarlyData {
    skip_data_left: usize,
    next: Box<hs::ExpectClientHello>,
}

impl State for ExpectAndSkipRejectedEarlyData {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
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

        self.next.handle(input, output)
    }
}

struct ExpectCertificateOrCompressedCertificate {
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    expected_certificate_type: CertificateType,
}

impl State for ExpectCertificateOrCompressedCertificate {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(..)),
                ..
            } => ExpectCertificate {
                hs: self.hs,
                key_schedule: self.key_schedule,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => ExpectCompressedCertificate {
                hs: self.hs,
                key_schedule: self.key_schedule,
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
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    expected_certificate_type: CertificateType,
}

impl ExpectCompressedCertificate {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);
        let compressed_cert = require_handshake_msg_move!(
            message,
            HandshakeType::CompressedCertificate,
            HandshakePayload::CompressedCertificate
        )?;

        let selected_decompressor = self
            .hs
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

        let cert_payload = CertificatePayloadTls13::read(&mut Reader::new(&decompress_buffer))?;
        trace!(
            "Client certificate decompressed using {:?} ({} bytes -> {})",
            compressed_cert.alg,
            compressed_cert.compressed.bytes().len(),
            compressed_cert.uncompressed_len,
        );

        ExpectCertificate {
            hs: self.hs,
            key_schedule: self.key_schedule,
            expected_certificate_type: self.expected_certificate_type,
        }
        .handle_certificate(cert_payload)
    }
}

struct ExpectCertificate {
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    expected_certificate_type: CertificateType,
}

impl ExpectCertificate {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);
        self.handle_certificate(require_handshake_msg_move!(
            message,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?)
    }

    fn handle_certificate(
        mut self,
        certp: CertificatePayloadTls13<'_>,
    ) -> Result<Box<dyn State>, Error> {
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
            .hs
            .config
            .verifier
            .client_auth_mandatory();

        let peer_identity = Identity::from_peer(client_cert.0, self.expected_certificate_type)?;

        let Some(peer_identity) = peer_identity else {
            if !mandatory {
                debug!("client auth requested but no certificate supplied");
                self.hs.transcript.abandon_client_auth();
                return Ok(Box::new(ExpectFinished {
                    hs: self.hs,
                    key_schedule: self.key_schedule,
                    peer_identity: None,
                }));
            }

            return Err(PeerMisbehaved::NoCertificatesPresented.into());
        };

        self.hs
            .config
            .verifier
            .verify_identity(&ClientIdentity {
                identity: &peer_identity,
                now: self.hs.config.current_time()?,
            })?;

        Ok(Box::new(ExpectCertificateVerify {
            hs: self.hs,
            key_schedule: self.key_schedule,
            peer_identity: peer_identity.into_owned(),
        }))
    }
}

impl State for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        self.handle_input(input)
    }
}

struct ExpectCertificateVerify {
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    peer_identity: Identity<'static>,
}

impl State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let signature = require_handshake_msg!(
            message,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;
        let handshake_hash = self.hs.transcript.current_hash();
        self.hs.transcript.abandon_client_auth();

        self.hs
            .config
            .verifier
            .verify_tls13_signature(&verify::SignatureVerificationInput {
                message: construct_client_verify_message(&handshake_hash).as_ref(),
                signer: &self.peer_identity.as_signer(),
                signature,
            })?;

        trace!("client CertificateVerify OK");

        self.hs.transcript.add_message(&message);
        Ok(Box::new(ExpectFinished {
            hs: self.hs,
            key_schedule: self.key_schedule,
            peer_identity: Some(self.peer_identity),
        }))
    }
}

// --- Process (any number of) early ApplicationData messages,
//     followed by a terminating handshake EndOfEarlyData message ---

struct ExpectEarlyData {
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    peer_identity: Option<Identity<'static>>,
    remaining_length: usize,
}

impl State for ExpectEarlyData {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::ApplicationData(payload) => {
                self.remaining_length = match self
                    .remaining_length
                    .checked_sub(payload.bytes().len())
                {
                    Some(sub) => sub,
                    None => return Err(PeerMisbehaved::TooMuchEarlyDataReceived.into()),
                };

                output.emit(Event::EarlyApplicationData(payload));
                Ok(self)
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::EndOfEarlyData),
                ..
            } => {
                let proof = input.check_aligned_handshake()?;
                self.key_schedule
                    .update_decrypter(output, &proof);
                self.hs
                    .transcript
                    .add_message(&input.message);
                Ok(Box::new(ExpectFinished {
                    hs: self.hs,
                    key_schedule: self.key_schedule,
                    peer_identity: self.peer_identity,
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

#[derive(Debug)]
pub(crate) struct Tls13ServerSessionValue<'a> {
    common: CommonServerSessionValue<'a>,
    secret: ZeroizingCow<'a>,
    age_obfuscation_offset: u32,

    // not encoded vv
    freshness: Option<bool>,
}

impl<'a> Tls13ServerSessionValue<'a> {
    fn from_ticket(
        id: &PresharedKeyIdentity,
        config: &ServerConfig,
    ) -> Option<Tls13ServerSessionValue<'static>> {
        let plain = match config.ticketer.as_deref() {
            Some(ticketer) => ticketer.decrypt(id.identity.bytes())?,
            None => config
                .session_storage
                .take(ServerSessionKey::new(id.identity.bytes()))?,
        };

        let Ok(ServerSessionValue::Tls13(tls13)) = ServerSessionValue::read_bytes(&plain) else {
            return None;
        };

        Some(tls13.into_owned())
    }

    pub(super) fn new(
        common: CommonServerSessionValue<'a>,
        secret: &'a [u8],
        age_obfuscation_offset: u32,
    ) -> Self {
        Self {
            common,
            secret: ZeroizingCow::Borrowed(SizedPayload::from(Payload::Borrowed(secret))),
            age_obfuscation_offset,
            freshness: None,
        }
    }

    fn into_owned(self) -> Tls13ServerSessionValue<'static> {
        Tls13ServerSessionValue {
            common: self.common.into_owned(),
            secret: ZeroizingCow::Owned(match self.secret {
                ZeroizingCow::Borrowed(b) => Zeroizing::from(b.into_owned()),
                ZeroizingCow::Owned(o) => o,
            }),
            age_obfuscation_offset: self.age_obfuscation_offset,
            freshness: self.freshness,
        }
    }

    fn set_freshness(&mut self, obfuscated_client_age_ms: u32, time_now: UnixTime) {
        let client_age_ms = obfuscated_client_age_ms.wrapping_sub(self.age_obfuscation_offset);
        let server_age_ms = (time_now
            .as_secs()
            .saturating_sub(self.common.creation_time_sec) as u32)
            .saturating_mul(1000);

        let age_difference = server_age_ms.abs_diff(client_age_ms);
        self.freshness = Some(age_difference <= MAX_FRESHNESS_SKEW_MS);
    }

    fn is_fresh(&self) -> bool {
        self.freshness.unwrap_or_default()
    }
}

impl<'a> Codec<'a> for Tls13ServerSessionValue<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        self.secret.encode(bytes);
        self.age_obfuscation_offset
            .encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            secret: ZeroizingCow::read(r)?,
            age_obfuscation_offset: u32::read(r)?,
            freshness: None,
        })
    }
}

impl<'a> From<Tls13ServerSessionValue<'a>> for ServerSessionValue<'a> {
    fn from(value: Tls13ServerSessionValue<'a>) -> Self {
        Self::Tls13(value)
    }
}

#[derive(Debug)]
enum ZeroizingCow<'a> {
    Borrowed(SizedPayload<'a, u8>),
    Owned(Zeroizing<SizedPayload<'static, u8>>),
}

impl<'a> ZeroizingCow<'a> {
    fn bytes(&self) -> &[u8] {
        match self {
            ZeroizingCow::Borrowed(b) => b.bytes(),
            ZeroizingCow::Owned(o) => o.bytes(),
        }
    }
}

impl<'a> Codec<'a> for ZeroizingCow<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ZeroizingCow::Borrowed(b) => b.encode(bytes),
            ZeroizingCow::Owned(o) => o.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(ZeroizingCow::Borrowed(SizedPayload::read(r)?))
    }
}

struct ExpectFinished {
    hs: HandshakeState,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    peer_identity: Option<Identity<'static>>,
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
        let secret = resumption.derive_ticket_psk(&nonce);
        let plain = ServerSessionValue::from(Tls13ServerSessionValue::new(
            CommonServerSessionValue::new(
                sni.as_ref(),
                suite.common.suite,
                peer_identity,
                chosen_alpn_protocol,
                resumption_data.to_vec(),
                now,
            ),
            secret.as_ref(),
            age_add,
        ))
        .get_encoding();

        let ticketer = config.ticketer.as_deref();
        let (ticket, lifetime) = if let Some(ticketer) = ticketer {
            let Some(ticket) = ticketer.encrypt(&plain) else {
                return Ok(());
            };
            (ticket, ticketer.lifetime())
        } else {
            let id = rand::random_array::<32>(secure_random)?;
            let stored = config
                .session_storage
                .put(ServerSessionKey::new(&id), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = Duration::from_secs(24 * 60 * 60); // this is a bit of a punt
            (id.to_vec(), stateful_lifetime)
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

impl State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let handshake_hash = self.hs.transcript.current_hash();
        let proof = input.check_aligned_handshake()?;
        let (key_schedule_before_finished, expect_verify_data) = self
            .key_schedule
            .sign_client_finish(&handshake_hash, output, &proof);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => return Err(PeerMisbehaved::IncorrectFinished.into()),
        };

        // Note: future derivations include Client Finished, but not the
        // main application data keying.
        self.hs
            .transcript
            .add_message(&input.message);

        let (key_schedule_traffic, exporter, resumption) =
            key_schedule_before_finished.into_traffic(self.hs.transcript.current_hash());

        let mut flight = HandshakeFlightTls13::new(&mut self.hs.transcript);
        for _ in 0..self.hs.send_tickets {
            Self::emit_ticket(
                &mut flight,
                self.hs.suite,
                self.peer_identity.clone(),
                self.hs.alpn_protocol.clone(),
                self.hs.sni.clone(),
                &self.hs.resumption_data,
                &resumption,
                &self.hs.config,
            )?;
        }
        flight.finish(output);

        let (key_schedule_send, key_schedule_recv) = key_schedule_traffic.split();

        // Application data may now flow, even if we have client auth enabled.
        if let Some(identity) = self.peer_identity {
            output.emit(Event::PeerIdentity(identity));
        }
        output.emit(Event::Exporter(Box::new(exporter)));
        output.send().tls13_key_schedule = Some(Box::new(key_schedule_send));
        output.start_traffic();

        Ok(match key_schedule_recv.protocol().is_quic() {
            true => Box::new(ExpectQuicTraffic { _fin_verified: fin }),
            false => Box::new(ExpectTraffic {
                config: self.hs.config,
                counters: TrafficTemperCounters::default(),
                key_schedule_recv,
                _fin_verified: fin,
            }),
        })
    }
}

struct HandshakeState {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    sni: Option<DnsName<'static>>,
    resumption_data: Vec<u8>,
    send_tickets: usize,
}

// --- Process traffic ---
struct ExpectTraffic {
    config: Arc<ServerConfig>,
    key_schedule_recv: KeyScheduleTrafficReceive,
    counters: TrafficTemperCounters,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_key_update(
        &mut self,
        input: Input<'_>,
        output: &mut dyn Output,
        key_update_request: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        if self
            .key_schedule_recv
            .protocol()
            .is_quic()
        {
            return Err(PeerMisbehaved::KeyUpdateReceivedInQuicConnection.into());
        }

        let proof = input.check_aligned_handshake()?;

        self.counters
            .received_key_update_request()?;

        match key_update_request {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => output.send().ensure_key_update_queued(),
            _ => return Err(InvalidMessage::InvalidKeyUpdate.into()),
        }

        // Update our read-side keys.
        self.key_schedule_recv
            .update_decrypter(output, &proof);
        Ok(())
    }
}

impl State for ExpectTraffic {
    fn handle(
        mut self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        match input.message.payload {
            MessagePayload::ApplicationData(payload) => {
                self.counters.received_app_data();
                output.received_plaintext(payload);
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(key_update)),
                ..
            } => self.handle_key_update(input, output, &key_update)?,
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

    fn into_external_state(
        self: Box<Self>,
        send_keys: &Option<Box<KeyScheduleTrafficSend>>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        if !self.config.enable_secret_extraction {
            return Err(ApiMisuse::SecretExtractionRequiresPriorOptIn.into());
        }
        let Some(send_keys) = send_keys else {
            return Err(Error::Unreachable(
                "send_keys required for TLS1.3 into_external_state",
            ));
        };
        Ok((
            PartiallyExtractedSecrets {
                tx: send_keys.extract()?,
                rx: self.key_schedule_recv.extract()?,
            },
            self,
        ))
    }
}

impl KernelState for ExpectTraffic {
    fn update_rx_secret(&mut self) -> Result<ConnectionTrafficSecrets, Error> {
        self.key_schedule_recv
            .refresh_traffic_secret()
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

impl State for ExpectQuicTraffic {
    fn handle(
        self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        // reject all messages
        Err(inappropriate_message(&message.payload, &[]))
    }
}

impl KernelState for ExpectQuicTraffic {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn update_rx_secret(&mut self) -> Result<ConnectionTrafficSecrets, Error> {
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

/// This is the maximum allowed skew between server and client clocks, over
/// the maximum ticket lifetime period.  This encompasses TCP retransmission
/// times in case packet loss occurs when the client sends the ClientHello
/// or receives the NewSessionTicket, _and_ actual clock skew over this period.
static MAX_FRESHNESS_SKEW_MS: u32 = 60 * 1000;
