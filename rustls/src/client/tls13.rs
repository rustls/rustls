use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::config::{ClientConfig, ClientSessionKey, ClientSessionStore};
use super::ech::EchStatus;
use super::hs::{
    self, ClientHandler, ClientHelloInput, ClientSessionValue, ExpectServerHello, GroupAndKeyShare,
};
use super::{
    ClientAuthDetails, ClientHelloDetails, Retrieved, ServerCertDetails, Tls13ClientSessionInput,
    Tls13Session,
};
use crate::check::inappropriate_handshake_message;
use crate::common_state::{
    EarlyDataEvent, Event, HandshakeFlightTls13, HandshakeKind, Input, Output, Side, State,
    TrafficTemperCounters,
};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::KernelState;
use crate::crypto::cipher::Payload;
use crate::crypto::hash::Hash;
use crate::crypto::kx::{ActiveKeyExchange, HybridKeyExchange, SharedSecret, StartedKeyExchange};
use crate::crypto::{Identity, SelectedCredential, SignatureScheme, Signer};
use crate::enums::{CertificateType, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{
    ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved, RejectedEch,
};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warn};
use crate::msgs::{
    CERTIFICATE_MAX_SIZE_LIMIT, CertificatePayloadTls13, ChangeCipherSpecPayload, ClientExtensions,
    Codec, EchConfigPayload, ExtensionType, HandshakeMessagePayload, HandshakePayload,
    KeyShareEntry, KeyUpdateRequest, MaybeEmpty, Message, MessagePayload,
    NewSessionTicketPayloadTls13, PresharedKeyBinder, PresharedKeyIdentity, PresharedKeyOffer,
    Reader, ServerExtensions, ServerHelloPayload, SizedPayload,
};
use crate::sealed::Sealed;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::key_schedule::{
    KeyScheduleEarlyClient, KeyScheduleHandshake, KeySchedulePreHandshake, KeyScheduleResumption,
    KeyScheduleTrafficReceive, KeyScheduleTrafficSend,
};
use crate::tls13::{
    Tls13CipherSuite, construct_client_verify_message, construct_server_verify_message,
};
use crate::verify::{self, DigitallySignedStruct, ServerIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, KeyLog, compress, crypto};

pub(crate) static TLS13_HANDLER: &dyn ClientHandler<Tls13CipherSuite> = &Handler;

#[derive(Debug)]
struct Handler;

impl ClientHandler<Tls13CipherSuite> for Handler {
    /// `early_data_key_schedule` is `Some` if we sent the
    /// "early_data" extension to the server.
    fn handle_server_hello(
        &self,
        suite: &'static Tls13CipherSuite,
        server_hello: &ServerHelloPayload,
        input: &Input<'_>,
        mut st: ExpectServerHello,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        // Start our handshake hash, and input the server-hello.
        let mut transcript = st
            .transcript_buffer
            .start_hash(suite.common.hash_provider);
        transcript.add_message(&input.message);

        let mut randoms = ConnectionRandoms::new(st.input.random, server_hello.random);

        if !server_hello.only_contains(ALLOWED_PLAINTEXT_EXTS) {
            return Err(PeerMisbehaved::UnexpectedCleartextExtension.into());
        }

        let their_key_share = server_hello
            .key_share
            .as_ref()
            .ok_or(PeerMisbehaved::MissingKeyShare)?;

        let ClientHelloInput {
            config,
            resuming,
            mut sent_tls13_fake_ccs,
            mut hello,
            session_key,
            protocol,
            ..
        } = st.input;

        let mut resuming_session = match resuming {
            Some(Retrieved {
                value: ClientSessionValue::Tls13(value),
                ..
            }) => Some(value),
            _ => None,
        };

        // We always send a key share when TLS 1.3 is enabled.
        let our_key_share = st.offered_key_share.unwrap();
        let our_key_share = KeyExchangeChoice::new(&config, output, our_key_share, their_key_share)
            .map_err(|_| PeerMisbehaved::WrongGroupForKeyShare)?;

        let (key_schedule_pre_handshake, in_early_traffic) =
            match (server_hello.preshared_key, st.early_data_key_schedule) {
                (Some(selected_psk), Some((early_key_schedule, in_early_traffic))) => {
                    match &resuming_session {
                        Some(resuming) => {
                            let Some(resuming_suite) = suite.can_resume_from(resuming.suite) else {
                                return Err(
                                    PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite
                                        .into(),
                                );
                            };

                            // If the server varies the suite here, we will have encrypted early data with
                            // the wrong suite.
                            if in_early_traffic && resuming_suite != suite {
                                return Err(
                                    PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite.into()
                                );
                            }

                            if selected_psk != 0 {
                                return Err(PeerMisbehaved::SelectedInvalidPsk.into());
                            }

                            debug!("Resuming using PSK");
                            // The key schedule has been initialized and set in fill_in_psk_binder()
                        }
                        _ => {
                            return Err(PeerMisbehaved::SelectedUnofferedPsk.into());
                        }
                    }
                    (
                        KeySchedulePreHandshake::from(early_key_schedule),
                        in_early_traffic,
                    )
                }
                _ => {
                    debug!("Not resuming");
                    // Discard the early data key schedule.
                    output.emit(Event::EarlyData(EarlyDataEvent::Rejected));
                    resuming_session.take();
                    (
                        KeySchedulePreHandshake::new(Side::Client, protocol, suite),
                        false,
                    )
                }
            };

        let shared_secret = our_key_share.complete(their_key_share.payload.bytes())?;
        let key_schedule = key_schedule_pre_handshake.into_handshake(shared_secret);

        // If we have ECH state, check that the server accepted our offer.
        if let Some(ech_state) = st.ech_state {
            let Message {
                payload:
                    MessagePayload::Handshake {
                        encoded: server_hello_encoded,
                        ..
                    },
                ..
            } = &input.message
            else {
                unreachable!("ServerHello is a handshake message");
            };
            st.ech_status = match ech_state.confirm_acceptance(
                &key_schedule,
                server_hello,
                server_hello_encoded,
                suite.common.hash_provider,
            )? {
                // The server accepted our ECH offer, so complete the inner transcript with the
                // server hello message, and switch the relevant state to the copies for the
                // inner client hello.
                Some(mut accepted) => {
                    accepted
                        .transcript
                        .add_message(&input.message);
                    transcript = accepted.transcript;
                    randoms.client = accepted.random.0;
                    hello.sent_extensions = accepted.sent_extensions;
                    EchStatus::Accepted
                }
                // The server rejected our ECH offer.
                None => EchStatus::Rejected,
            };
            output.emit(Event::EchStatus(st.ech_status));
        }

        // Remember what KX group the server liked for next time.
        config
            .resumption
            .store
            .set_kx_hint(session_key.clone(), their_key_share.group);

        // If we change keying when a subsequent handshake message is being joined,
        // the two halves will have different record layer protections.  Disallow this.
        let proof = input.check_aligned_handshake()?;

        let hash_at_client_recvd_server_hello = transcript.current_hash();
        let key_schedule = key_schedule.derive_client_handshake_secrets(
            in_early_traffic,
            hash_at_client_recvd_server_hello,
            suite,
            &*config.key_log,
            &randoms.client,
            output,
            &proof,
        );

        if !key_schedule.protocol().is_quic() {
            emit_fake_ccs(&mut sent_tls13_fake_ccs, output);
        }

        output.emit(Event::HandshakeKind(
            match (&resuming_session, st.done_retry) {
                (Some(_), true) => HandshakeKind::ResumedWithHelloRetryRequest,
                (None, true) => HandshakeKind::FullWithHelloRetryRequest,
                (Some(_), false) => HandshakeKind::Resumed,
                (None, false) => HandshakeKind::Full,
            },
        ));

        Ok(Box::new(ExpectEncryptedExtensions {
            hs: HandshakeState {
                config,
                session_key,
                randoms,
                transcript,
                key_schedule,
            },
            resuming_session,
            suite,
            hello,
            ech_status: st.ech_status,
            in_early_traffic,
        }))
    }
}

impl Sealed for Handler {}

enum KeyExchangeChoice {
    Whole(Box<dyn ActiveKeyExchange>),
    Component(Box<dyn HybridKeyExchange>),
}

impl KeyExchangeChoice {
    /// Decide between `our_key_share` or `our_key_share.hybrid_component()`
    /// based on the selection of the server expressed in `their_key_share`.
    fn new(
        config: &Arc<ClientConfig>,
        output: &mut dyn Output,
        our_key_share: GroupAndKeyShare,
        their_key_share: &KeyShareEntry,
    ) -> Result<Self, ()> {
        if our_key_share.share.group() == their_key_share.group {
            output.emit(Event::KeyExchangeGroup(our_key_share.group));
            return Ok(Self::Whole(our_key_share.share.into_single()));
        }

        let (hybrid_key_share, actual_skxg) = our_key_share
            .share
            .as_hybrid_checked(&config.provider().kx_groups, ProtocolVersion::TLSv1_3)
            .ok_or(())?;

        if hybrid_key_share.component().0 != their_key_share.group {
            return Err(());
        }

        let StartedKeyExchange::Hybrid(hybrid_key_share) = our_key_share.share else {
            return Err(()); // unreachable due to `as_hybrid_checked`
        };

        // correct the record for the benefit of accuracy of
        // `negotiated_key_exchange_group()`
        output.emit(Event::KeyExchangeGroup(actual_skxg));

        Ok(Self::Component(hybrid_key_share))
    }

    fn complete(self, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        match self {
            Self::Whole(akx) => akx.complete(peer_pub_key),
            Self::Component(akx) => akx.complete_component(peer_pub_key),
        }
    }
}

pub(super) fn initial_key_share(
    config: &ClientConfig,
    session_key: &ClientSessionKey<'_>,
) -> Result<GroupAndKeyShare, Error> {
    let group = config
        .resumption
        .store
        .kx_hint(session_key)
        .and_then(|group_name| {
            config
                .provider()
                .find_kx_group(group_name, ProtocolVersion::TLSv1_3)
        })
        .unwrap_or_else(|| {
            config
                .provider()
                .kx_groups
                .iter()
                .copied()
                .next()
                .expect("No kx groups configured")
        });

    GroupAndKeyShare::new(group)
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub(super) fn fill_in_psk_binder(
    key_schedule: &KeyScheduleEarlyClient,
    transcript: &HandshakeHashBuffer,
    hmp: &mut HandshakeMessagePayload<'_>,
) {
    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.encoding_for_binder_signing();
    let handshake_hash = transcript.hash_given(key_schedule.hash(), &binder_plaintext);

    // Run a fake key_schedule to simulate what the server will do if it chooses
    // to resume.
    let real_binder = key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

    if let HandshakePayload::ClientHello(ch) = &mut hmp.0 {
        if let Some(PresharedKeyOffer {
            binders,
            identities,
        }) = &mut ch.preshared_key_offer
        {
            // the caller of this function must have set up the desired identity, and a
            // matching (dummy) binder; or else the binder we compute here will be incorrect.
            // See `prepare_resumption()`.
            debug_assert_eq!(identities.len(), 1);
            debug_assert_eq!(binders.len(), 1);
            debug_assert_eq!(binders[0].as_ref().len(), real_binder.as_ref().len());
            binders[0] = PresharedKeyBinder::from(real_binder.as_ref().to_vec());
        }
    };
}

pub(super) fn prepare_resumption(
    config: &ClientConfig,
    output: &mut dyn Output,
    resuming_session: &Retrieved<&Tls13Session>,
    exts: &mut ClientExtensions<'_>,
    doing_retry: bool,
) -> bool {
    let resuming_suite = resuming_session.suite;
    output.emit(Event::CipherSuite(resuming_suite.into()));
    // The EarlyData extension MUST be supplied together with the
    // PreSharedKey extension.
    let max_early_data_size = resuming_session.max_early_data_size;
    let early_data_enabled = if config.enable_early_data && max_early_data_size > 0 && !doing_retry
    {
        output.emit(Event::EarlyData(EarlyDataEvent::Enable(
            max_early_data_size as usize,
        )));
        exts.early_data_request = Some(());
        true
    } else {
        false
    };

    // Finally, and only for TLS1.3 with a ticket resumption, include a binder
    // for our ticket.  This must go last.
    //
    // Include an empty binder. It gets filled in below because it depends on
    // the message it's contained in (!!!).
    let obfuscated_ticket_age = resuming_session.obfuscated_ticket_age();

    let binder_len = resuming_suite
        .common
        .hash_provider
        .output_len();
    let binder = vec![0u8; binder_len];

    let psk_identity =
        PresharedKeyIdentity::new(resuming_session.ticket().to_vec(), obfuscated_ticket_age);
    let psk_offer = PresharedKeyOffer::new(psk_identity, binder);
    exts.preshared_key_offer = Some(psk_offer);
    early_data_enabled
}

pub(super) fn derive_early_traffic_secret(
    key_log: &dyn KeyLog,
    output: &mut dyn Output,
    hash_alg: &'static dyn Hash,
    early_key_schedule: &KeyScheduleEarlyClient,
    sent_tls13_fake_ccs: &mut bool,
    transcript_buffer: &HandshakeHashBuffer,
    client_random: &[u8; 32],
) {
    if !early_key_schedule.protocol().is_quic() {
        // For middlebox compatibility
        emit_fake_ccs(sent_tls13_fake_ccs, output);
    }

    let client_hello_hash = transcript_buffer.hash_given(hash_alg, &[]);
    early_key_schedule.client_early_traffic_secret(
        &client_hello_hash,
        key_log,
        client_random,
        output,
    );

    output.emit(Event::EarlyExporter(early_key_schedule.early_exporter(
        &client_hello_hash,
        key_log,
        client_random,
    )));

    // Now the client can send encrypted early data
    output.emit(Event::EarlyData(EarlyDataEvent::Start));
    trace!("Starting early data traffic");
}

pub(super) fn emit_fake_ccs(sent_tls13_fake_ccs: &mut bool, output: &mut dyn Output) {
    if core::mem::replace(sent_tls13_fake_ccs, true) {
        return;
    }

    output.send_msg(
        Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        },
        false,
    );
}

fn validate_encrypted_extensions(
    hello: &ClientHelloDetails,
    exts: &ServerExtensions<'_>,
) -> Result<(), Error> {
    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        return Err(PeerMisbehaved::UnsolicitedEncryptedExtension.into());
    }

    if exts.contains_any(ALLOWED_PLAINTEXT_EXTS) || exts.contains_any(DISALLOWED_TLS13_EXTS) {
        return Err(PeerMisbehaved::DisallowedEncryptedExtension.into());
    }

    Ok(())
}

struct ExpectEncryptedExtensions {
    hs: HandshakeState,
    resuming_session: Option<Tls13Session>,
    suite: &'static Tls13CipherSuite,
    hello: ClientHelloDetails,
    ech_status: EchStatus,
    in_early_traffic: bool,
}

impl State for ExpectEncryptedExtensions {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let exts = require_handshake_msg!(
            message,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {exts:?}");
        self.hs.transcript.add_message(&message);

        validate_encrypted_extensions(&self.hello, exts)?;

        let selected_alpn = exts
            .selected_protocol
            .as_ref()
            .map(|protocol| protocol.as_ref());
        hs::process_alpn_protocol(output, &self.hello.alpn_protocols, selected_alpn)?;

        // RFC 9001 says: "While ALPN only specifies that servers use this alert, QUIC clients MUST
        // use error 0x0178 to terminate a connection when ALPN negotiation fails." We judge that
        // the user intended to use ALPN (rather than some out-of-band protocol negotiation
        // mechanism) if and only if any ALPN protocols were configured. This defends against badly-behaved
        // servers which accept a connection that requires an application-layer protocol they do not
        // understand.
        if self
            .hs
            .key_schedule
            .protocol()
            .is_quic()
            && selected_alpn.is_none()
            && !self.hello.alpn_protocols.is_empty()
        {
            return Err(Error::NoApplicationProtocol);
        }

        check_cert_type(
            self.hs
                .config
                .resolver()
                .supported_certificate_types(),
            exts.client_certificate_type,
        )?;

        check_cert_type(
            self.hs
                .config
                .verifier()
                .supported_certificate_types(),
            exts.server_certificate_type,
        )?;

        let ech_retry_configs = match (self.ech_status, &exts.encrypted_client_hello_ack) {
            // If we didn't offer ECH, or ECH was accepted, but the server sent an ECH encrypted
            // extension with retry configs, we must error.
            (EchStatus::NotOffered | EchStatus::Accepted, Some(_)) => {
                return Err(PeerMisbehaved::UnsolicitedEchExtension.into());
            }
            // If we offered ECH, and it was rejected, store the retry configs (if any) from
            // the server's ECH extension. We will return them in an error produced at the end
            // of the handshake.
            (EchStatus::Rejected, ext) => ext
                .as_ref()
                .map(|ext| ext.retry_configs.to_vec()),
            _ => None,
        };

        let ech = Ech {
            retry_configs: ech_retry_configs,
            status: self.ech_status,
        };

        // QUIC transport parameters
        let quic_params = if let Some(quic) = output.quic() {
            let Some(quic_params) = exts.transport_parameters.as_ref() else {
                return Err(PeerMisbehaved::MissingQuicTransportParameters.into());
            };

            quic.params = Some(quic_params.clone().into_vec());
            Some(SizedPayload::from(Payload::new(
                quic_params.clone().into_vec(),
            )))
        } else {
            None
        };

        match self.resuming_session {
            Some(resuming_session) => {
                if self.in_early_traffic {
                    match exts.early_data_ack {
                        Some(()) => output.emit(Event::EarlyData(EarlyDataEvent::Accepted)),
                        None => {
                            output.emit(Event::EarlyData(EarlyDataEvent::Rejected));
                            // If no early traffic, set the encryption key for handshakes
                            self.hs
                                .key_schedule
                                .set_handshake_encrypter(output);
                            self.in_early_traffic = false;
                        }
                    }
                }

                // We *don't* reverify the certificate chain here: resumption is a
                // continuation of the previous session in terms of security policy.
                let cert_verified = verify::PeerVerified::assertion();
                let sig_verified = verify::HandshakeSignatureValid::assertion();
                Ok(Box::new(ExpectFinished {
                    hs: self.hs,
                    session_input: Tls13ClientSessionInput {
                        suite: self.suite,
                        peer_identity: resuming_session.peer_identity().clone(),
                        quic_params,
                    },
                    client_auth: None,
                    cert_verified,
                    sig_verified,
                    ech,
                    in_early_traffic: self.in_early_traffic,
                }))
            }
            _ => {
                if exts.early_data_ack.is_some() {
                    return Err(PeerMisbehaved::EarlyDataExtensionWithoutResumption.into());
                }

                let expected_certificate_type = exts
                    .server_certificate_type
                    .unwrap_or_default();
                Ok(if self.hello.offered_cert_compression {
                    Box::new(ExpectCertificateOrCompressedCertificateOrCertReq {
                        hs: self.hs,
                        suite: self.suite,
                        quic_params,
                        ech,
                        expected_certificate_type,
                        negotiated_client_type: exts.client_certificate_type,
                    })
                } else {
                    Box::new(ExpectCertificateOrCertReq {
                        hs: self.hs,
                        suite: self.suite,
                        quic_params,
                        ech,
                        expected_certificate_type,
                        negotiated_client_type: exts.client_certificate_type,
                    })
                })
            }
        }
    }
}

fn check_cert_type(
    client_supported: &[CertificateType],
    server_negotiated: Option<CertificateType>,
) -> Result<(), Error> {
    match server_negotiated {
        None if client_supported.is_empty()
            || client_supported.contains(&CertificateType::X509) =>
        {
            Ok(())
        }
        Some(ct) if client_supported.contains(&ct) => Ok(()),
        _ => Err(Error::PeerIncompatible(
            PeerIncompatible::IncorrectCertificateTypeExtension,
        )),
    }
}

struct ExpectCertificateOrCompressedCertificateOrCertReq {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    ech: Ech,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl State for ExpectCertificateOrCompressedCertificateOrCertReq {
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
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: None,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => ExpectCompressedCertificate {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: None,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(..)),
                ..
            } => ExpectCertificateRequest {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                offered_cert_compression: true,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
                negotiated_client_type: self.negotiated_client_type,
            }
            .handle_input(input),

            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::Certificate,
                    HandshakeType::CertificateRequest,
                    HandshakeType::CompressedCertificate,
                ],
            )),
        }
    }
}

struct ExpectCertificateOrCompressedCertificate {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    client_auth: Option<ClientAuthDetails>,
    ech: Ech,
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
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: self.client_auth,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => ExpectCompressedCertificate {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: self.client_auth,
                ech: self.ech,
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

struct ExpectCertificateOrCertReq {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    ech: Ech,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl State for ExpectCertificateOrCertReq {
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
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: None,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            }
            .handle_input(input),

            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(..)),
                ..
            } => ExpectCertificateRequest {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                offered_cert_compression: false,
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
                negotiated_client_type: self.negotiated_client_type,
            }
            .handle_input(input),

            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::Certificate,
                    HandshakeType::CertificateRequest,
                ],
            )),
        }
    }
}

// TLS1.3 version of CertificateRequest handling.  We then move to expecting the server
// Certificate. Unfortunately the CertificateRequest type changed in an annoying way
// in TLS1.3.
struct ExpectCertificateRequest {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    offered_cert_compression: bool,
    ech: Ech,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl ExpectCertificateRequest {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        let certreq = &require_handshake_msg!(
            message,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTls13
        )?;
        self.hs.transcript.add_message(&message);
        debug!("Got CertificateRequest {certreq:?}");

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.is_empty() {
            warn!("Server sent non-empty certreq context");
            return Err(InvalidMessage::InvalidCertRequest.into());
        }

        let compat_sigschemes = certreq
            .extensions
            .signature_algorithms
            .as_deref()
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(SignatureScheme::supported_in_tls13)
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            return Err(PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon.into());
        }

        let compat_compressor = certreq
            .extensions
            .certificate_compression_algorithms
            .as_deref()
            .and_then(|offered| {
                self.hs
                    .config
                    .cert_compressors
                    .iter()
                    .find(|compressor| offered.contains(&compressor.algorithm()))
            })
            .copied();

        let client_auth = ClientAuthDetails::resolve(
            self.negotiated_client_type
                .unwrap_or(CertificateType::X509),
            self.hs.config.resolver().as_ref(),
            certreq
                .extensions
                .authority_names
                .as_deref(),
            &compat_sigschemes,
            Some(certreq.context.to_vec()),
            compat_compressor,
        );

        Ok(if self.offered_cert_compression {
            Box::new(ExpectCertificateOrCompressedCertificate {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: Some(client_auth),
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            })
        } else {
            Box::new(ExpectCertificate {
                hs: self.hs,
                suite: self.suite,
                quic_params: self.quic_params,
                client_auth: Some(client_auth),
                ech: self.ech,
                expected_certificate_type: self.expected_certificate_type,
            })
        })
    }
}

struct ExpectCompressedCertificate {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    client_auth: Option<ClientAuthDetails>,
    ech: Ech,
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
            "Server certificate decompressed using {:?} ({} bytes -> {})",
            compressed_cert.alg,
            compressed_cert.compressed.bytes().len(),
            compressed_cert.uncompressed_len,
        );

        ExpectCertificate {
            hs: self.hs,
            suite: self.suite,
            quic_params: self.quic_params,
            client_auth: self.client_auth,
            ech: self.ech,
            expected_certificate_type: self.expected_certificate_type,
        }
        .handle_cert_payload(cert_payload)
    }
}

struct ExpectCertificate {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    client_auth: Option<ClientAuthDetails>,
    ech: Ech,
    expected_certificate_type: CertificateType,
}

impl ExpectCertificate {
    fn handle_input(mut self, Input { message, .. }: Input<'_>) -> Result<Box<dyn State>, Error> {
        self.hs.transcript.add_message(&message);

        self.handle_cert_payload(require_handshake_msg_move!(
            message,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?)
    }

    fn handle_cert_payload(
        self,
        cert_chain: CertificatePayloadTls13<'_>,
    ) -> Result<Box<dyn State>, Error> {
        // This is only non-empty for client auth.
        if !cert_chain.context.is_empty() {
            return Err(InvalidMessage::InvalidCertRequest.into());
        }

        let end_entity_ocsp = cert_chain.end_entity_ocsp().to_vec();
        let server_cert = ServerCertDetails::new(
            cert_chain
                .into_certificate_chain()
                .into_owned(),
            end_entity_ocsp,
        );

        Ok(Box::new(ExpectCertificateVerify {
            hs: self.hs,
            suite: self.suite,
            quic_params: self.quic_params,
            server_cert,
            client_auth: self.client_auth,
            ech: self.ech,
            expected_certificate_type: self.expected_certificate_type,
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

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify {
    hs: HandshakeState,
    suite: &'static Tls13CipherSuite,
    quic_params: Option<SizedPayload<'static, u16, MaybeEmpty>>,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
    ech: Ech,
    expected_certificate_type: CertificateType,
}

impl State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        Input { message, .. }: Input<'_>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let cert_verify = require_handshake_msg!(
            message,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        let identity = Identity::from_peer(
            self.server_cert.cert_chain.0,
            self.expected_certificate_type,
        )?
        .ok_or(PeerMisbehaved::NoCertificatesPresented)?;

        let cert_verified = self
            .hs
            .config
            .verifier()
            .verify_identity(&ServerIdentity {
                identity: &identity,
                server_name: &self.hs.session_key.server_name,
                ocsp_response: &self.server_cert.ocsp_response,
                now: self.hs.config.current_time()?,
            })?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.hs.transcript.current_hash();
        let sig_verified = self
            .hs
            .config
            .verifier()
            .verify_tls13_signature(&SignatureVerificationInput {
                message: construct_server_verify_message(&handshake_hash).as_ref(),
                signer: &identity.as_signer(),
                signature: cert_verify,
            })?;

        self.hs.transcript.add_message(&message);

        Ok(Box::new(ExpectFinished {
            hs: self.hs,
            session_input: Tls13ClientSessionInput {
                suite: self.suite,
                peer_identity: identity,
                quic_params: self.quic_params,
            },
            client_auth: self.client_auth,
            cert_verified,
            sig_verified,
            ech: self.ech,
            in_early_traffic: false,
        }))
    }
}

fn emit_compressed_certificate_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    credentials: &SelectedCredential,
    auth_context: Option<Vec<u8>>,
    compressor: &dyn compress::CertCompressor,
    config: &ClientConfig,
) {
    let mut cert_payload =
        CertificatePayloadTls13::new(credentials.identity.as_certificates(), None);
    cert_payload.context = auth_context
        .clone()
        .unwrap_or_default()
        .into();

    let Ok(compressed) = config
        .cert_compression_cache
        .compression_for(compressor, &cert_payload)
    else {
        return emit_certificate_tls13(flight, Some(credentials), auth_context);
    };

    flight.add(HandshakeMessagePayload(
        HandshakePayload::CompressedCertificate(compressed.compressed_cert_payload()),
    ));
}

fn emit_certificate_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    credentials: Option<&SelectedCredential>,
    auth_context: Option<Vec<u8>>,
) {
    let mut cert_payload = match credentials {
        Some(credentials) => {
            CertificatePayloadTls13::new(credentials.identity.as_certificates(), None)
        }
        None => CertificatePayloadTls13::new([].into_iter(), None),
    };

    cert_payload.context = auth_context.unwrap_or_default().into();
    flight.add(HandshakeMessagePayload(HandshakePayload::CertificateTls13(
        cert_payload,
    )));
}

fn emit_certverify_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    signer: Box<dyn Signer>,
) -> Result<(), Error> {
    let message = construct_client_verify_message(&flight.transcript.current_hash());

    let scheme = signer.scheme();
    let sig = signer.sign(message.as_ref())?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    flight.add(HandshakeMessagePayload(
        HandshakePayload::CertificateVerify(dss),
    ));
    Ok(())
}

fn emit_finished_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    verify_data: &crypto::hmac::PublicTag,
) {
    let verify_data_payload = Payload::new(verify_data.as_ref());

    flight.add(HandshakeMessagePayload(HandshakePayload::Finished(
        verify_data_payload,
    )));
}

fn emit_end_of_early_data_tls13(transcript: &mut HandshakeHash, output: &mut dyn Output) {
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EndOfEarlyData,
        )),
    };

    transcript.add_message(&m);
    output.send_msg(m, true);
}

struct ExpectFinished {
    hs: HandshakeState,
    session_input: Tls13ClientSessionInput,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::PeerVerified,
    sig_verified: verify::HandshakeSignatureValid,
    ech: Ech,
    in_early_traffic: bool,
}

impl State for ExpectFinished {
    fn handle(
        self: Box<Self>,
        input: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let mut st = *self;
        let finished = require_handshake_msg!(
            input.message,
            HandshakeType::Finished,
            HandshakePayload::Finished
        )?;

        let proof = input.check_aligned_handshake()?;
        let handshake_hash = st.hs.transcript.current_hash();
        let expect_verify_data = st
            .hs
            .key_schedule
            .sign_server_finish(&handshake_hash, &proof);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => {
                return Err(PeerMisbehaved::IncorrectFinished.into());
            }
        };

        st.hs
            .transcript
            .add_message(&input.message);

        let hash_after_handshake = st.hs.transcript.current_hash();
        /* The EndOfEarlyData message to server is still encrypted with early data keys,
         * but appears in the transcript after the server Finished. */
        if st.in_early_traffic {
            if !st.hs.key_schedule.protocol().is_quic() {
                emit_end_of_early_data_tls13(&mut st.hs.transcript, output);
            }
            output.emit(Event::EarlyData(EarlyDataEvent::Finished));
            st.hs
                .key_schedule
                .set_handshake_encrypter(output);
        }

        let mut flight = HandshakeFlightTls13::new(&mut st.hs.transcript);

        /* Send our authentication/finished messages.  These are still encrypted
         * with our handshake keys. */
        if let Some(client_auth) = st.client_auth {
            match client_auth {
                ClientAuthDetails::Empty {
                    auth_context_tls13: auth_context,
                } => {
                    emit_certificate_tls13(&mut flight, None, auth_context);
                }
                ClientAuthDetails::Verify {
                    auth_context_tls13: auth_context,
                    ..
                } if st.ech.status == EchStatus::Rejected => {
                    // If ECH was offered, and rejected, we MUST respond with
                    // an empty certificate message.
                    emit_certificate_tls13(&mut flight, None, auth_context);
                }
                ClientAuthDetails::Verify {
                    credentials,
                    auth_context_tls13: auth_context,
                    compressor,
                } => {
                    if let Some(compressor) = compressor {
                        emit_compressed_certificate_tls13(
                            &mut flight,
                            &credentials,
                            auth_context,
                            compressor,
                            &st.hs.config,
                        );
                    } else {
                        emit_certificate_tls13(&mut flight, Some(&credentials), auth_context);
                    }
                    emit_certverify_tls13(&mut flight, credentials.signer)?;
                }
            }
        }

        let (key_schedule_pre_finished, verify_data) = st
            .hs
            .key_schedule
            .into_pre_finished_client_traffic(
                hash_after_handshake,
                flight.transcript.current_hash(),
                &*st.hs.config.key_log,
                &st.hs.randoms.client,
            );

        emit_finished_tls13(&mut flight, &verify_data);
        flight.finish(output);

        /* We're now sure this server supports TLS1.3.  But if we run out of TLS1.3 tickets
         * when connecting to it again, we definitely don't want to attempt a TLS1.2 resumption. */
        st.hs
            .config
            .resumption
            .store
            .remove_tls12_session(&st.hs.session_key);

        /* Now move to our application traffic keys. */
        let (key_schedule, exporter, resumption) =
            key_schedule_pre_finished.into_traffic(output, st.hs.transcript.current_hash(), &proof);
        let (key_schedule_send, key_schedule_recv) = key_schedule.split();

        output.emit(Event::PeerIdentity(st.session_input.peer_identity.clone()));
        output.emit(Event::Exporter(Box::new(exporter)));
        output.send().tls13_key_schedule = Some(Box::new(key_schedule_send));
        output.start_traffic();

        // Now that we've reached the end of the normal handshake we must enforce ECH acceptance by
        // sending an alert and returning an error (potentially with retry configs) if the server
        // did not accept our ECH offer.
        if st.ech.status == EchStatus::Rejected {
            return Err(RejectedEch {
                retry_configs: st.ech.retry_configs,
            }
            .into());
        }

        let protocol = key_schedule_recv.protocol();

        let st = ExpectTraffic {
            config: st.hs.config.clone(),
            session_storage: st.hs.config.resumption.store.clone(),
            session_key: st.hs.session_key,
            session_input: st.session_input,
            key_schedule_recv,
            resumption,
            counters: TrafficTemperCounters::default(),
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        };

        Ok(match protocol.is_quic() {
            true => Box::new(ExpectQuicTraffic(st)),
            false => Box::new(st),
        })
    }
}

struct HandshakeState {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, key updates,
// and application data.
struct ExpectTraffic {
    config: Arc<ClientConfig>,
    session_storage: Arc<dyn ClientSessionStore>,
    session_key: ClientSessionKey<'static>,
    session_input: Tls13ClientSessionInput,
    key_schedule_recv: KeyScheduleTrafficReceive,
    resumption: KeyScheduleResumption,
    counters: TrafficTemperCounters,
    _cert_verified: verify::PeerVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_new_ticket_impl(&self, nst: &NewSessionTicketPayloadTls13) -> Result<(), Error> {
        let secret = self
            .resumption
            .derive_ticket_psk(nst.nonce.bytes());

        let now = self.config.current_time()?;

        let value = Tls13Session::new(
            self.session_input.clone(),
            nst.ticket.clone(),
            secret.as_ref(),
            now,
            nst.lifetime,
            nst.age_add,
            nst.extensions
                .max_early_data_size
                .unwrap_or_default(),
        );

        if self
            .key_schedule_recv
            .protocol()
            .is_quic()
        {
            if let Some(sz) = nst.extensions.max_early_data_size {
                if sz != 0 && sz != 0xffff_ffff {
                    return Err(PeerMisbehaved::InvalidMaxEarlyDataSize.into());
                }
            }
        }

        self.session_storage
            .insert_tls13_ticket(self.session_key.clone(), value);
        Ok(())
    }

    fn handle_new_ticket_tls13(
        &self,
        output: &mut dyn Output,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        let received = &mut output.receive().tls13_tickets_received;
        *received = received.saturating_add(1);
        self.handle_new_ticket_impl(nst)
    }

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

        // Mustn't be interleaved with other handshake messages.
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
                parsed: HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(new_ticket)),
                ..
            } => self.handle_new_ticket_tls13(output, &new_ticket)?,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(key_update)),
                ..
            } => self.handle_key_update(input, output, &key_update)?,
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
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
        message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        self.handle_new_ticket_impl(message)
    }
}

struct ExpectQuicTraffic(ExpectTraffic);

impl State for ExpectQuicTraffic {
    fn handle(
        self: Box<Self>,
        Input { message, .. }: Input<'_>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        let nst = require_handshake_msg!(
            message,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicketTls13
        )?;
        self.0
            .handle_new_ticket_tls13(output, nst)?;
        Ok(self)
    }

    fn into_external_state(
        self: Box<Self>,
        send_keys: &Option<Box<KeyScheduleTrafficSend>>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        if !self.0.config.enable_secret_extraction {
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
                rx: self.0.key_schedule_recv.extract()?,
            },
            self,
        ))
    }
}

impl KernelState for ExpectQuicTraffic {
    fn update_rx_secret(&mut self) -> Result<ConnectionTrafficSecrets, Error> {
        Err(Error::Unreachable(
            "KeyUpdate is not supported for QUIC connections",
        ))
    }

    fn handle_new_session_ticket(&self, nst: &NewSessionTicketPayloadTls13) -> Result<(), Error> {
        self.0.handle_new_ticket_impl(nst)
    }
}

struct Ech {
    status: EchStatus,
    retry_configs: Option<Vec<EchConfigPayload>>,
}

// Extensions we expect in plaintext in the ServerHello.
const ALLOWED_PLAINTEXT_EXTS: &[ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
const DISALLOWED_TLS13_EXTS: &[ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];
