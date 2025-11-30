use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::config::{ClientConfig, ClientSessionKey, ClientSessionStore};
use super::connection::ClientConnectionData;
use super::ech::{self, EchStatus};
use super::hs::{
    self, ClientContext, ClientHandler, ClientHelloInput, ClientSessionValue, ExpectServerHello,
};
use super::{ClientAuthDetails, ClientHelloDetails, ServerCertDetails};
use crate::check::inappropriate_handshake_message;
use crate::common_state::{
    CommonState, HandshakeFlightTls13, HandshakeKind, KxState, Protocol, Side, State, TrafficState,
};
use crate::conn::ConnectionRandoms;
use crate::conn::kernel::{Direction, KernelContext, KernelState};
use crate::crypto::cipher::Payload;
use crate::crypto::hash::Hash;
use crate::crypto::kx::{ActiveKeyExchange, HybridKeyExchange, SharedSecret, StartedKeyExchange};
use crate::crypto::{Identity, SelectedCredential, SignatureScheme, Signer};
use crate::enums::{CertificateType, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warn};
use crate::msgs::base::PayloadU8;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{CERTIFICATE_MAX_SIZE_LIMIT, Codec, Reader};
use crate::msgs::enums::{ExtensionType, KeyUpdateRequest};
use crate::msgs::handshake::{
    CertificatePayloadTls13, ClientExtensions, EchConfigPayload, HandshakeMessagePayload,
    HandshakePayload, KeyShareEntry, NewSessionTicketPayloadTls13, PresharedKeyBinder,
    PresharedKeyIdentity, PresharedKeyOffer, ServerExtensions, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::{self, Retrieved};
use crate::sealed::Sealed;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake, KeyScheduleResumption,
    KeyScheduleTraffic,
};
use crate::tls13::{
    Tls13CipherSuite, construct_client_verify_message, construct_server_verify_message,
};
use crate::verify::{self, DigitallySignedStruct, ServerIdentity, SignatureVerificationInput};
use crate::{ConnectionTrafficSecrets, KeyLog, compress, crypto};

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &[ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &[ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

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
        message: &Message<'_>,
        st: ExpectServerHello,
        cx: &mut ClientContext<'_>,
    ) -> hs::NextStateOrError {
        // Start our handshake hash, and input the server-hello.
        let mut transcript = st
            .transcript_buffer
            .start_hash(suite.common.hash_provider);
        transcript.add_message(message);

        let mut randoms = ConnectionRandoms::new(st.input.random, server_hello.random);

        validate_server_hello(cx.common, server_hello)?;

        let their_key_share = server_hello
            .key_share
            .as_ref()
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::MissingExtension,
                    PeerMisbehaved::MissingKeyShare,
                )
            })?;

        let ClientHelloInput {
            config,
            resuming,
            mut sent_tls13_fake_ccs,
            mut hello,
            session_key,
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
        let our_key_share = KeyExchangeChoice::new(&config, cx, our_key_share, their_key_share)
            .map_err(|_| {
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::WrongGroupForKeyShare,
                )
            })?;

        let key_schedule_pre_handshake =
            match (server_hello.preshared_key, st.early_data_key_schedule) {
                (Some(selected_psk), Some(early_key_schedule)) => {
                    match &resuming_session {
                        Some(resuming) => {
                            let Some(resuming_suite) = suite.can_resume_from(resuming.suite())
                            else {
                                return Err({
                                    cx.common.send_fatal_alert(
                                    AlertDescription::IllegalParameter,
                                    PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite,
                                )
                                });
                            };

                            // If the server varies the suite here, we will have encrypted early data with
                            // the wrong suite.
                            if cx.data.early_data.is_enabled() && resuming_suite != suite {
                                return Err({
                                    cx.common.send_fatal_alert(
                                        AlertDescription::IllegalParameter,
                                        PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite,
                                    )
                                });
                            }

                            if selected_psk != 0 {
                                return Err({
                                    cx.common.send_fatal_alert(
                                        AlertDescription::IllegalParameter,
                                        PeerMisbehaved::SelectedInvalidPsk,
                                    )
                                });
                            }

                            debug!("Resuming using PSK");
                            // The key schedule has been initialized and set in fill_in_psk_binder()
                        }
                        _ => {
                            return Err(PeerMisbehaved::SelectedUnofferedPsk.into());
                        }
                    }
                    KeySchedulePreHandshake::from(early_key_schedule)
                }
                _ => {
                    debug!("Not resuming");
                    // Discard the early data key schedule.
                    cx.data.early_data.rejected();
                    cx.common.early_traffic = false;
                    resuming_session.take();
                    KeySchedulePreHandshake::new(suite)
                }
            };

        cx.common.kx_state.complete();
        let shared_secret = our_key_share
            .complete(&their_key_share.payload.0)
            .map_err(|err| {
                cx.common
                    .send_fatal_alert(AlertDescription::IllegalParameter, err)
            })?;

        let mut key_schedule = key_schedule_pre_handshake.into_handshake(shared_secret);

        // If we have ECH state, check that the server accepted our offer.
        if let Some(ech_state) = st.ech_state {
            let Message {
                payload:
                    MessagePayload::Handshake {
                        encoded: server_hello_encoded,
                        ..
                    },
                ..
            } = &message
            else {
                unreachable!("ServerHello is a handshake message");
            };
            cx.data.ech_status = match ech_state.confirm_acceptance(
                &mut key_schedule,
                server_hello,
                server_hello_encoded,
                suite.common.hash_provider,
            )? {
                // The server accepted our ECH offer, so complete the inner transcript with the
                // server hello message, and switch the relevant state to the copies for the
                // inner client hello.
                Some(mut accepted) => {
                    accepted.transcript.add_message(message);
                    transcript = accepted.transcript;
                    randoms.client = accepted.random.0;
                    hello.sent_extensions = accepted.sent_extensions;
                    EchStatus::Accepted
                }
                // The server rejected our ECH offer.
                None => EchStatus::Rejected,
            };
        }

        // Remember what KX group the server liked for next time.
        config
            .resumption
            .store
            .set_kx_hint(session_key.clone(), their_key_share.group);

        // If we change keying when a subsequent handshake message is being joined,
        // the two halves will have different record layer protections.  Disallow this.
        let proof = cx.common.check_aligned_handshake()?;

        let hash_at_client_recvd_server_hello = transcript.current_hash();
        let key_schedule = key_schedule.derive_client_handshake_secrets(
            cx.data.early_data.is_enabled(),
            hash_at_client_recvd_server_hello,
            suite,
            &*config.key_log,
            &randoms.client,
            cx.common,
            &proof,
        );

        emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);

        Ok(Box::new(ExpectEncryptedExtensions {
            config,
            resuming_session,
            session_key,
            randoms,
            suite,
            transcript,
            key_schedule,
            hello,
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
        cx: &mut ClientContext<'_>,
        our_key_share: StartedKeyExchange,
        their_key_share: &KeyShareEntry,
    ) -> Result<Self, ()> {
        if our_key_share.group() == their_key_share.group {
            return Ok(Self::Whole(our_key_share.into_single()));
        }

        let (hybrid_key_share, actual_skxg) = our_key_share
            .as_hybrid_checked(&config.provider().kx_groups, ProtocolVersion::TLSv1_3)
            .ok_or(())?;

        if hybrid_key_share.component().0 != their_key_share.group {
            return Err(());
        }

        let StartedKeyExchange::Hybrid(hybrid_key_share) = our_key_share else {
            return Err(()); // unreachable due to `as_hybrid_checked`
        };

        // correct the record for the benefit of accuracy of
        // `negotiated_key_exchange_group()`
        cx.common.kx_state = KxState::Start(actual_skxg);

        Ok(Self::Component(hybrid_key_share))
    }

    fn complete(self, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        match self {
            Self::Whole(akx) => akx.complete(peer_pub_key),
            Self::Component(akx) => akx.complete_component(peer_pub_key),
        }
    }
}

fn validate_server_hello(
    common: &mut CommonState,
    server_hello: &ServerHelloPayload,
) -> Result<(), Error> {
    if !server_hello.only_contains(ALLOWED_PLAINTEXT_EXTS) {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnexpectedCleartextExtension,
        ));
    }

    Ok(())
}

pub(super) fn initial_key_share(
    config: &ClientConfig,
    session_key: &ClientSessionKey<'_>,
    kx_state: &mut KxState,
) -> Result<StartedKeyExchange, Error> {
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

    *kx_state = KxState::Start(group);
    group.start()
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub(super) fn fill_in_psk_binder(
    resuming: &persist::Tls13ClientSessionValue,
    transcript: &HandshakeHashBuffer,
    hmp: &mut HandshakeMessagePayload<'_>,
) -> KeyScheduleEarly {
    // We need to know the hash function of the suite we're trying to resume into.
    let suite = resuming.suite();
    let suite_hash = suite.common.hash_provider;

    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.encoding_for_binder_signing();
    let handshake_hash = transcript.hash_given(suite_hash, &binder_plaintext);

    // Run a fake key_schedule to simulate what the server will do if it chooses
    // to resume.
    let key_schedule = KeyScheduleEarly::new(suite, resuming.secret());
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

    key_schedule
}

pub(super) fn prepare_resumption(
    config: &ClientConfig,
    cx: &mut ClientContext<'_>,
    resuming_session: &Retrieved<&persist::Tls13ClientSessionValue>,
    exts: &mut ClientExtensions<'_>,
    doing_retry: bool,
) {
    let resuming_suite = resuming_session.suite();
    cx.common.suite = Some(resuming_suite.into());
    // The EarlyData extension MUST be supplied together with the
    // PreSharedKey extension.
    let max_early_data_size = resuming_session.max_early_data_size();
    if config.enable_early_data && max_early_data_size > 0 && !doing_retry {
        cx.data
            .early_data
            .enable(max_early_data_size as usize);
        exts.early_data_request = Some(());
    }

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
}

pub(super) fn derive_early_traffic_secret(
    key_log: &dyn KeyLog,
    cx: &mut ClientContext<'_>,
    hash_alg: &'static dyn Hash,
    early_key_schedule: &KeyScheduleEarly,
    sent_tls13_fake_ccs: &mut bool,
    transcript_buffer: &HandshakeHashBuffer,
    client_random: &[u8; 32],
) {
    // For middlebox compatibility
    emit_fake_ccs(sent_tls13_fake_ccs, cx.common);

    let client_hello_hash = transcript_buffer.hash_given(hash_alg, &[]);
    early_key_schedule.client_early_traffic_secret_for_client(
        &client_hello_hash,
        key_log,
        client_random,
        cx.common,
    );

    cx.common.early_exporter =
        Some(early_key_schedule.early_exporter(&client_hello_hash, key_log, client_random));

    // Now the client can send encrypted early data
    cx.common.early_traffic = true;
    trace!("Starting early data traffic");
}

pub(super) fn emit_fake_ccs(sent_tls13_fake_ccs: &mut bool, common: &mut CommonState) {
    if common.is_quic() {
        return;
    }

    if core::mem::replace(sent_tls13_fake_ccs, true) {
        return;
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };
    common.send_msg(m, false);
}

fn validate_encrypted_extensions(
    common: &mut CommonState,
    hello: &ClientHelloDetails,
    exts: &ServerExtensions<'_>,
) -> Result<(), Error> {
    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedEncryptedExtension,
        ));
    }

    if exts.contains_any(ALLOWED_PLAINTEXT_EXTS) || exts.contains_any(DISALLOWED_TLS13_EXTS) {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::DisallowedEncryptedExtension,
        ));
    }

    Ok(())
}

struct ExpectEncryptedExtensions {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls13ClientSessionValue>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectEncryptedExtensions {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let exts = require_handshake_msg!(
            m,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {exts:?}");
        self.transcript.add_message(&m);

        validate_encrypted_extensions(cx.common, &self.hello, exts)?;
        hs::process_alpn_protocol(
            cx.common,
            &self.hello.alpn_protocols,
            exts.selected_protocol
                .as_ref()
                .map(|protocol| protocol.as_ref()),
        )?;

        check_cert_type(
            cx.common,
            self.config
                .resolver()
                .supported_certificate_types(),
            exts.client_certificate_type,
        )?;

        check_cert_type(
            cx.common,
            self.config
                .verifier()
                .supported_certificate_types(),
            exts.server_certificate_type,
        )?;

        let ech_retry_configs = match (cx.data.ech_status, &exts.encrypted_client_hello_ack) {
            // If we didn't offer ECH, or ECH was accepted, but the server sent an ECH encrypted
            // extension with retry configs, we must error.
            (EchStatus::NotOffered | EchStatus::Accepted, Some(_)) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::UnsolicitedEchExtension,
                ));
            }
            // If we offered ECH, and it was rejected, store the retry configs (if any) from
            // the server's ECH extension. We will return them in an error produced at the end
            // of the handshake.
            (EchStatus::Rejected, ext) => ext
                .as_ref()
                .map(|ext| ext.retry_configs.to_vec()),
            _ => None,
        };

        // QUIC transport parameters
        if cx.common.is_quic() {
            match exts.transport_parameters.as_ref() {
                Some(params) => cx.common.quic.params = Some(params.clone().into_vec()),
                None => {
                    return Err(cx
                        .common
                        .missing_extension(PeerMisbehaved::MissingQuicTransportParameters));
                }
            }
        }

        match self.resuming_session {
            Some(resuming_session) => {
                let was_early_traffic = cx.common.early_traffic;
                if was_early_traffic {
                    match exts.early_data_ack {
                        Some(()) => cx.data.early_data.accepted(),
                        None => {
                            cx.data.early_data.rejected();
                            cx.common.early_traffic = false;
                        }
                    }
                }

                if was_early_traffic && !cx.common.early_traffic {
                    // If no early traffic, set the encryption key for handshakes
                    self.key_schedule
                        .set_handshake_encrypter(cx.common);
                }

                cx.common.peer_identity = Some(resuming_session.peer_identity().clone());
                cx.common.handshake_kind = Some(match cx.common.handshake_kind {
                    Some(HandshakeKind::FullWithHelloRetryRequest) => {
                        HandshakeKind::ResumedWithHelloRetryRequest
                    }
                    _ => HandshakeKind::Resumed,
                });

                // We *don't* reverify the certificate chain here: resumption is a
                // continuation of the previous session in terms of security policy.
                let cert_verified = verify::PeerVerified::assertion();
                let sig_verified = verify::HandshakeSignatureValid::assertion();
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    session_key: self.session_key,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    client_auth: None,
                    cert_verified,
                    sig_verified,
                    ech_retry_configs,
                }))
            }
            _ => {
                if exts.early_data_ack.is_some() {
                    return Err(PeerMisbehaved::EarlyDataExtensionWithoutResumption.into());
                }
                cx.common
                    .handshake_kind
                    .get_or_insert(HandshakeKind::Full);

                let expected_certificate_type = exts
                    .server_certificate_type
                    .unwrap_or_default();
                Ok(if self.hello.offered_cert_compression {
                    Box::new(ExpectCertificateOrCompressedCertificateOrCertReq {
                        config: self.config,
                        session_key: self.session_key,
                        randoms: self.randoms,
                        suite: self.suite,
                        transcript: self.transcript,
                        key_schedule: self.key_schedule,
                        ech_retry_configs,
                        expected_certificate_type,
                        negotiated_client_type: exts.client_certificate_type,
                    })
                } else {
                    Box::new(ExpectCertificateOrCertReq {
                        config: self.config,
                        session_key: self.session_key,
                        randoms: self.randoms,
                        suite: self.suite,
                        transcript: self.transcript,
                        key_schedule: self.key_schedule,
                        ech_retry_configs,
                        expected_certificate_type,
                        negotiated_client_type: exts.client_certificate_type,
                    })
                })
            }
        }
    }
}

fn check_cert_type(
    common: &mut CommonState,
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
        _ => Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Error::PeerIncompatible(PeerIncompatible::IncorrectCertificateTypeExtension),
        )),
    }
}

struct ExpectCertificateOrCompressedCertificateOrCertReq {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCompressedCertificateOrCertReq {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(..)),
                ..
            } => Box::new(ExpectCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => Box::new(ExpectCompressedCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(..)),
                ..
            } => Box::new(ExpectCertificateRequest {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_cert_compression: true,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
                negotiated_client_type: self.negotiated_client_type,
            })
            .handle(cx, m),
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
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
}

impl State<ClientConnectionData> for ExpectCertificateOrCompressedCertificate {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(..)),
                ..
            } => Box::new(ExpectCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: self.client_auth,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => Box::new(ExpectCompressedCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: self.client_auth,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
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
}

struct ExpectCertificateOrCertReq {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCertReq {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(..)),
                ..
            } => Box::new(ExpectCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(..)),
                ..
            } => Box::new(ExpectCertificateRequest {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_cert_compression: false,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
                negotiated_client_type: self.negotiated_client_type,
            })
            .handle(cx, m),
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
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    offered_cert_compression: bool,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
    negotiated_client_type: Option<CertificateType>,
}

impl State<ClientConnectionData> for ExpectCertificateRequest {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let certreq = &require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTls13
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {certreq:?}");

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.0.is_empty() {
            warn!("Server sent non-empty certreq context");
            return Err(cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                InvalidMessage::InvalidCertRequest,
            ));
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
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon,
            ));
        }

        let compat_compressor = certreq
            .extensions
            .certificate_compression_algorithms
            .as_deref()
            .and_then(|offered| {
                self.config
                    .cert_compressors
                    .iter()
                    .find(|compressor| offered.contains(&compressor.algorithm()))
            })
            .copied();

        let client_auth = ClientAuthDetails::resolve(
            self.negotiated_client_type
                .unwrap_or(CertificateType::X509),
            self.config.resolver().as_ref(),
            certreq
                .extensions
                .authority_names
                .as_deref(),
            &compat_sigschemes,
            Some(certreq.context.0.clone()),
            compat_compressor,
        );

        Ok(if self.offered_cert_compression {
            Box::new(ExpectCertificateOrCompressedCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: Some(client_auth),
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
        } else {
            Box::new(ExpectCertificate {
                config: self.config,
                session_key: self.session_key,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: Some(client_auth),
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
                expected_certificate_type: self.expected_certificate_type,
            })
        })
    }
}

struct ExpectCompressedCertificate {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
}

impl State<ClientConnectionData> for ExpectCompressedCertificate {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        self.transcript.add_message(&m);
        let compressed_cert = require_handshake_msg_move!(
            m,
            HandshakeType::CompressedCertificate,
            HandshakePayload::CompressedCertificate
        )?;

        let selected_decompressor = self
            .config
            .cert_decompressors
            .iter()
            .find(|item| item.algorithm() == compressed_cert.alg);

        let Some(decompressor) = selected_decompressor else {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::SelectedUnofferedCertCompression,
            ));
        };

        if compressed_cert.uncompressed_len as usize > CERTIFICATE_MAX_SIZE_LIMIT {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                InvalidMessage::MessageTooLarge,
            ));
        }

        let mut decompress_buffer = vec![0u8; compressed_cert.uncompressed_len as usize];
        if let Err(compress::DecompressionFailed) =
            decompressor.decompress(compressed_cert.compressed.as_ref(), &mut decompress_buffer)
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
            "Server certificate decompressed using {:?} ({} bytes -> {})",
            compressed_cert.alg,
            compressed_cert
                .compressed
                .as_ref()
                .len(),
            compressed_cert.uncompressed_len,
        );

        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CertificateTls13(cert_payload.into_owned()),
            )),
        };

        Box::new(ExpectCertificate {
            config: self.config,
            session_key: self.session_key,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: self.client_auth,
            message_already_in_transcript: true,
            ech_retry_configs: self.ech_retry_configs,
            expected_certificate_type: self.expected_certificate_type,
        })
        .handle(cx, m)
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    message_already_in_transcript: bool,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        if !self.message_already_in_transcript {
            self.transcript.add_message(&m);
        }
        let cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?;

        // This is only non-empty for client auth.
        if !cert_chain.context.0.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                InvalidMessage::InvalidCertRequest,
            ));
        }

        let end_entity_ocsp = cert_chain.end_entity_ocsp().to_vec();
        let server_cert = ServerCertDetails::new(
            cert_chain
                .into_certificate_chain()
                .into_owned(),
            end_entity_ocsp,
        );

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            session_key: self.session_key,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert,
            client_auth: self.client_auth,
            ech_retry_configs: self.ech_retry_configs,
            expected_certificate_type: self.expected_certificate_type,
        }))
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
    expected_certificate_type: CertificateType,
}

impl State<ClientConnectionData> for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let cert_verify = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        let identity = Identity::from_peer(
            self.server_cert.cert_chain.0,
            self.expected_certificate_type,
            cx.common,
        )?
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::NoCertificatesPresented,
            )
        })?;

        let cert_verified = self
            .config
            .verifier()
            .verify_identity(&ServerIdentity {
                identity: &identity,
                server_name: &self.session_key.server_name,
                ocsp_response: &self.server_cert.ocsp_response,
                now: self.config.current_time()?,
            })
            .map_err(|err| {
                cx.common
                    .send_cert_verify_error_alert(err)
            })?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.transcript.current_hash();
        let sig_verified = self
            .config
            .verifier()
            .verify_tls13_signature(&SignatureVerificationInput {
                message: construct_server_verify_message(&handshake_hash).as_ref(),
                signer: &identity.as_signer(),
                signature: cert_verify,
            })
            .map_err(|err| {
                cx.common
                    .send_cert_verify_error_alert(err)
            })?;

        cx.common.peer_identity = Some(identity);
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            config: self.config,
            session_key: self.session_key,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: self.client_auth,
            cert_verified,
            sig_verified,
            ech_retry_configs: self.ech_retry_configs,
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
    cert_payload.context = PayloadU8::new(auth_context.clone().unwrap_or_default());

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

    cert_payload.context = PayloadU8::new(auth_context.unwrap_or_default());
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

fn emit_end_of_early_data_tls13(transcript: &mut HandshakeHash, common: &mut CommonState) {
    if common.is_quic() {
        return;
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EndOfEarlyData,
        )),
    };

    transcript.add_message(&m);
    common.send_msg(m, true);
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    session_key: ClientSessionKey<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::PeerVerified,
    sig_verified: verify::HandshakeSignatureValid,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let proof = cx.common.check_aligned_handshake()?;
        let handshake_hash = st.transcript.current_hash();
        let expect_verify_data = st
            .key_schedule
            .sign_server_finish(&handshake_hash, &proof);

        let fin = match ConstantTimeEq::ct_eq(expect_verify_data.as_ref(), finished.bytes()).into()
        {
            true => verify::FinishedMessageVerified::assertion(),
            false => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
            }
        };

        st.transcript.add_message(&m);

        let hash_after_handshake = st.transcript.current_hash();
        /* The EndOfEarlyData message to server is still encrypted with early data keys,
         * but appears in the transcript after the server Finished. */
        if cx.common.early_traffic {
            emit_end_of_early_data_tls13(&mut st.transcript, cx.common);
            cx.common.early_traffic = false;
            cx.data.early_data.finished();
            st.key_schedule
                .set_handshake_encrypter(cx.common);
        }

        let mut flight = HandshakeFlightTls13::new(&mut st.transcript);

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
                } if cx.data.ech_status == EchStatus::Rejected => {
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
                            &st.config,
                        );
                    } else {
                        emit_certificate_tls13(&mut flight, Some(&credentials), auth_context);
                    }
                    emit_certverify_tls13(&mut flight, credentials.signer)?;
                }
            }
        }

        let (key_schedule_pre_finished, verify_data) = st
            .key_schedule
            .into_pre_finished_client_traffic(
                hash_after_handshake,
                flight.transcript.current_hash(),
                &*st.config.key_log,
                &st.randoms.client,
            );

        emit_finished_tls13(&mut flight, &verify_data);
        flight.finish(cx.common);

        /* We're now sure this server supports TLS1.3.  But if we run out of TLS1.3 tickets
         * when connecting to it again, we definitely don't want to attempt a TLS1.2 resumption. */
        st.config
            .resumption
            .store
            .remove_tls12_session(&st.session_key);

        /* Now move to our application traffic keys. */
        let (key_schedule, exporter, resumption) =
            key_schedule_pre_finished.into_traffic(cx.common, st.transcript.current_hash(), &proof);
        cx.common
            .start_traffic(&mut cx.sendable_plaintext);
        cx.common.exporter = Some(Box::new(exporter));

        // Now that we've reached the end of the normal handshake we must enforce ECH acceptance by
        // sending an alert and returning an error (potentially with retry configs) if the server
        // did not accept our ECH offer.
        if cx.data.ech_status == EchStatus::Rejected {
            return Err(ech::fatal_alert_required(st.ech_retry_configs, cx.common));
        }

        let st = ExpectTraffic {
            config: st.config.clone(),
            session_storage: st.config.resumption.store.clone(),
            session_key: st.session_key,
            suite: st.suite,
            key_schedule,
            resumption,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        };

        Ok(match cx.common.is_quic() {
            true => Box::new(ExpectQuicTraffic(st)),
            false => Box::new(st),
        })
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, key updates,
// and application data.
struct ExpectTraffic {
    config: Arc<ClientConfig>,
    session_storage: Arc<dyn ClientSessionStore>,
    session_key: ClientSessionKey<'static>,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTraffic,
    resumption: KeyScheduleResumption,
    _cert_verified: verify::PeerVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_new_ticket_impl(
        &mut self,
        cx: &mut KernelContext<'_>,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        let secret = self
            .resumption
            .derive_ticket_psk(&nst.nonce.0);

        let now = self.config.current_time()?;

        let mut value = persist::Tls13ClientSessionValue::new(
            self.suite,
            nst.ticket.clone(),
            secret.as_ref(),
            cx.peer_identity
                .unwrap() // should be Some() if we got this far
                .clone(),
            now,
            nst.lifetime,
            nst.age_add,
            nst.extensions
                .max_early_data_size
                .unwrap_or_default(),
        );

        if cx.is_quic() {
            if let Some(sz) = nst.extensions.max_early_data_size {
                if sz != 0 && sz != 0xffff_ffff {
                    return Err(PeerMisbehaved::InvalidMaxEarlyDataSize.into());
                }
            }

            if let Some(quic_params) = &cx.quic.params {
                value.set_quic_params(quic_params);
            }
        }

        self.session_storage
            .insert_tls13_ticket(self.session_key.clone(), value);
        Ok(())
    }

    fn handle_new_ticket_tls13(
        &mut self,
        cx: &mut ClientContext<'_>,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        let mut kcx = KernelContext {
            peer_identity: cx.common.peer_identity.as_ref(),
            protocol: cx.common.protocol,
            quic: &cx.common.quic,
        };
        cx.common.tls13_tickets_received = cx
            .common
            .tls13_tickets_received
            .saturating_add(1);
        self.handle_new_ticket_impl(&mut kcx, nst)
    }

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

        // Mustn't be interleaved with other handshake messages.
        let proof = common.check_aligned_handshake()?;

        if common.should_update_key(key_update_request)? {
            self.key_schedule
                .update_encrypter_and_notify(common);
        }

        // Update our read-side keys.
        self.key_schedule
            .update_decrypter(common, &proof);
        Ok(())
    }
}

impl State<ClientConnectionData> for ExpectTraffic {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.receive_plaintext(payload),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(new_ticket)),
                ..
            } => self.handle_new_ticket_tls13(cx, &new_ticket)?,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(key_update)),
                ..
            } => self.handle_key_update(cx.common, &key_update)?,
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

    fn into_traffic(self: Box<Self>) -> Result<Box<dyn TrafficState>, Error> {
        Ok(self)
    }

    fn send_key_update_request(&mut self, common: &mut CommonState) -> Result<(), Error> {
        self.key_schedule
            .request_key_update_and_update_encrypter(common)
    }

    fn into_external_state(
        self: Box<Self>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        Ok((
            self.key_schedule
                .extract_secrets(Side::Client)?,
            self,
        ))
    }
}

impl TrafficState for ExpectTraffic {
    fn handle_unexpected(&self, payload: &MessagePayload<'_>) -> Error {
        inappropriate_handshake_message(
            payload,
            &[ContentType::ApplicationData, ContentType::Handshake],
            &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
        )
    }

    fn handle_tls13_session_ticket(
        &mut self,
        common_state: &mut CommonState,
        new_ticket: NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        let mut kcx = KernelContext {
            peer_identity: common_state.peer_identity.as_ref(),
            protocol: common_state.protocol,
            quic: &common_state.quic,
        };
        common_state.tls13_tickets_received = common_state
            .tls13_tickets_received
            .saturating_add(1);
        self.handle_new_ticket_impl(&mut kcx, &new_ticket)
    }

    fn handle_key_update(
        &mut self,
        common_state: &mut CommonState,
        key_update: KeyUpdateRequest,
    ) -> Result<(), Error> {
        self.handle_key_update(common_state, &key_update)
    }

    fn send_key_update_request(&mut self, common: &mut CommonState) {
        let _ = self
            .key_schedule
            .request_key_update_and_update_encrypter(common);
    }
}

impl KernelState for ExpectTraffic {
    fn update_secrets(&mut self, dir: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        self.key_schedule
            .refresh_traffic_secret(match dir {
                Direction::Transmit => Side::Client,
                Direction::Receive => Side::Server,
            })
    }

    fn handle_new_session_ticket(
        &mut self,
        cx: &mut KernelContext<'_>,
        message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        self.handle_new_ticket_impl(cx, message)
    }
}

struct ExpectQuicTraffic(ExpectTraffic);

impl State<ClientConnectionData> for ExpectQuicTraffic {
    fn handle(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> hs::NextStateOrError {
        let nst = require_handshake_msg!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicketTls13
        )?;
        self.0
            .handle_new_ticket_tls13(cx, nst)?;
        Ok(self)
    }

    fn into_external_state(
        self: Box<Self>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        Ok((
            self.0
                .key_schedule
                .extract_secrets(Side::Client)?,
            self,
        ))
    }
}

impl KernelState for ExpectQuicTraffic {
    fn update_secrets(&mut self, _: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        Err(Error::Unreachable(
            "KeyUpdate is not supported for QUIC connections",
        ))
    }

    fn handle_new_session_ticket(
        &mut self,
        cx: &mut KernelContext<'_>,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        self.0.handle_new_ticket_impl(cx, nst)
    }
}
