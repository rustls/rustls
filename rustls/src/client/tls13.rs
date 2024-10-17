use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::ServerName;
use subtle::ConstantTimeEq;

use super::client_conn::ClientConnectionData;
use super::hs::ClientContext;
use crate::check::inappropriate_handshake_message;
use crate::client::common::{ClientAuthDetails, ClientHelloDetails, ServerCertDetails};
use crate::client::ech::{self, EchState, EchStatus};
use crate::client::{hs, ClientConfig, ClientSessionStore};
use crate::common_state::{
    CommonState, HandshakeFlightTls13, HandshakeKind, KxState, Protocol, Side, State,
};
use crate::conn::ConnectionRandoms;
use crate::crypto::ActiveKeyExchange;
use crate::enums::{
    AlertDescription, ContentType, HandshakeType, ProtocolVersion, SignatureScheme,
};
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warn};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{ExtensionType, KeyUpdateRequest};
use crate::msgs::handshake::{
    CertificatePayloadTls13, ClientExtension, EchConfigPayload, HandshakeMessagePayload,
    HandshakePayload, HasServerExtensions, NewSessionTicketPayloadTls13, PresharedKeyIdentity,
    PresharedKeyOffer, ServerExtension, ServerHelloPayload, CERTIFICATE_MAX_SIZE_LIMIT,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sign::{CertifiedKey, Signer};
use crate::suites::PartiallyExtractedSecrets;
use crate::tls13::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake, KeyScheduleTraffic,
    ResumptionSecret,
};
use crate::tls13::{
    construct_client_verify_message, construct_server_verify_message, Tls13CipherSuite,
};
use crate::verify::{self, DigitallySignedStruct};
use crate::{compress, crypto, KeyLog};

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

pub(super) fn handle_server_hello(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    server_hello: &ServerHelloPayload,
    mut resuming_session: Option<persist::Tls13ClientSessionValue>,
    server_name: ServerName<'static>,
    mut randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    mut transcript: HandshakeHash,
    early_key_schedule: Option<KeyScheduleEarly>,
    mut hello: ClientHelloDetails,
    our_key_share: Box<dyn ActiveKeyExchange>,
    mut sent_tls13_fake_ccs: bool,
    server_hello_msg: &Message<'_>,
    ech_state: Option<EchState>,
) -> hs::NextStateOrError<'static> {
    validate_server_hello(cx.common, server_hello)?;

    let their_key_share = server_hello
        .key_share()
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerMisbehaved::MissingKeyShare,
            )
        })?;

    if our_key_share.group() != their_key_share.group {
        return Err({
            cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::WrongGroupForKeyShare,
            )
        });
    }

    let key_schedule_pre_handshake = if let (Some(selected_psk), Some(early_key_schedule)) =
        (server_hello.psk_index(), early_key_schedule)
    {
        if let Some(ref resuming) = resuming_session {
            let resuming_suite = match suite.can_resume_from(resuming.suite()) {
                Some(resuming) => resuming,
                None => {
                    return Err({
                        cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite,
                        )
                    });
                }
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
        } else {
            return Err(PeerMisbehaved::SelectedUnofferedPsk.into());
        }
        KeySchedulePreHandshake::from(early_key_schedule)
    } else {
        debug!("Not resuming");
        // Discard the early data key schedule.
        cx.data.early_data.rejected();
        cx.common.early_traffic = false;
        resuming_session.take();
        KeySchedulePreHandshake::new(suite)
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
    if let Some(ech_state) = ech_state {
        cx.data.ech_status = match ech_state.confirm_acceptance(
            &mut key_schedule,
            server_hello,
            suite.common.hash_provider,
        )? {
            // The server accepted our ECH offer, so complete the inner transcript with the
            // server hello message, and switch the relevant state to the copies for the
            // inner client hello.
            Some(mut accepted) => {
                accepted
                    .transcript
                    .add_message(server_hello_msg);
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
        .set_kx_hint(server_name.clone(), their_key_share.group);

    // If we change keying when a subsequent handshake message is being joined,
    // the two halves will have different record layer protections.  Disallow this.
    cx.common.check_aligned_handshake()?;

    let hash_at_client_recvd_server_hello = transcript.current_hash();
    let key_schedule = key_schedule.derive_client_handshake_secrets(
        cx.data.early_data.is_enabled(),
        hash_at_client_recvd_server_hello,
        suite,
        &*config.key_log,
        &randoms.client,
        cx.common,
    );

    emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);

    Ok(Box::new(ExpectEncryptedExtensions {
        config,
        resuming_session,
        server_name,
        randoms,
        suite,
        transcript,
        key_schedule,
        hello,
    }))
}

fn validate_server_hello(
    common: &mut CommonState,
    server_hello: &ServerHelloPayload,
) -> Result<(), Error> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.ext_type()) {
            return Err(common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnexpectedCleartextExtension,
            ));
        }
    }

    Ok(())
}

pub(super) fn initial_key_share(
    config: &ClientConfig,
    server_name: &ServerName<'_>,
    kx_state: &mut KxState,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let group = config
        .resumption
        .store
        .kx_hint(server_name)
        .and_then(|group_name| config.find_kx_group(group_name, ProtocolVersion::TLSv1_3))
        .unwrap_or_else(|| {
            config
                .provider
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

    if let HandshakePayload::ClientHello(ref mut ch) = hmp.payload {
        ch.set_psk_binder(real_binder.as_ref());
    };

    key_schedule
}

pub(super) fn prepare_resumption(
    config: &ClientConfig,
    cx: &mut ClientContext<'_>,
    resuming_session: &persist::Retrieved<&persist::Tls13ClientSessionValue>,
    exts: &mut Vec<ClientExtension>,
    doing_retry: bool,
) {
    let resuming_suite = resuming_session.suite();
    cx.common.suite = Some(resuming_suite.into());
    cx.data.resumption_ciphersuite = Some(resuming_suite.into());
    // The EarlyData extension MUST be supplied together with the
    // PreSharedKey extension.
    let max_early_data_size = resuming_session.max_early_data_size();
    if config.enable_early_data && max_early_data_size > 0 && !doing_retry {
        cx.data
            .early_data
            .enable(max_early_data_size as usize);
        exts.push(ClientExtension::EarlyData);
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
    let psk_ext = PresharedKeyOffer::new(psk_identity, binder);
    exts.push(ClientExtension::PresharedKey(psk_ext));
}

pub(super) fn derive_early_traffic_secret(
    key_log: &dyn KeyLog,
    cx: &mut ClientContext<'_>,
    resuming_suite: &'static Tls13CipherSuite,
    early_key_schedule: &KeyScheduleEarly,
    sent_tls13_fake_ccs: &mut bool,
    transcript_buffer: &HandshakeHashBuffer,
    client_random: &[u8; 32],
) {
    // For middlebox compatibility
    emit_fake_ccs(sent_tls13_fake_ccs, cx.common);

    let client_hello_hash = transcript_buffer.hash_given(resuming_suite.common.hash_provider, &[]);
    early_key_schedule.client_early_traffic_secret(
        &client_hello_hash,
        key_log,
        client_random,
        cx.common,
    );

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
    exts: &Vec<ServerExtension>,
) -> Result<(), Error> {
    if exts.has_duplicate_extension() {
        return Err(common.send_fatal_alert(
            AlertDescription::DecodeError,
            PeerMisbehaved::DuplicateEncryptedExtensions,
        ));
    }

    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedEncryptedExtension,
        ));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.ext_type())
            || DISALLOWED_TLS13_EXTS.contains(&ext.ext_type())
        {
            return Err(common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::DisallowedEncryptedExtension,
            ));
        }
    }

    Ok(())
}

struct ExpectEncryptedExtensions {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls13ClientSessionValue>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectEncryptedExtensions {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let exts = require_handshake_msg!(
            m,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        self.transcript.add_message(&m);

        validate_encrypted_extensions(cx.common, &self.hello, exts)?;
        hs::process_alpn_protocol(cx.common, &self.config, exts.alpn_protocol())?;
        hs::process_client_cert_type_extension(cx.common, &self.config, exts.client_cert_type())?;
        hs::process_server_cert_type_extension(cx.common, &self.config, exts.server_cert_type())?;

        let ech_retry_configs = match (cx.data.ech_status, exts.server_ech_extension()) {
            // If we didn't offer ECH, or ECH was accepted, but the server sent an ECH encrypted
            // extension with retry configs, we must error.
            (EchStatus::NotOffered | EchStatus::Accepted, Some(_)) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::UnsolicitedEchExtension,
                ))
            }
            // If we offered ECH, and it was rejected, store the retry configs (if any) from
            // the server's ECH extension. We will return them in an error produced at the end
            // of the handshake.
            (EchStatus::Rejected, ext) => ext.map(|ext| ext.retry_configs.to_vec()),
            _ => None,
        };

        // QUIC transport parameters
        if cx.common.is_quic() {
            match exts.quic_params_extension() {
                Some(params) => cx.common.quic.params = Some(params),
                None => {
                    return Err(cx
                        .common
                        .missing_extension(PeerMisbehaved::MissingQuicTransportParameters));
                }
            }
        }

        if let Some(resuming_session) = self.resuming_session {
            let was_early_traffic = cx.common.early_traffic;
            if was_early_traffic {
                if exts.early_data_extension_offered() {
                    cx.data.early_data.accepted();
                } else {
                    cx.data.early_data.rejected();
                    cx.common.early_traffic = false;
                }
            }

            if was_early_traffic && !cx.common.early_traffic {
                // If no early traffic, set the encryption key for handshakes
                self.key_schedule
                    .set_handshake_encrypter(cx.common);
            }

            cx.common.peer_certificates = Some(
                resuming_session
                    .server_cert_chain()
                    .clone(),
            );
            cx.common.handshake_kind = Some(HandshakeKind::Resumed);

            // We *don't* reverify the certificate chain here: resumption is a
            // continuation of the previous session in terms of security policy.
            let cert_verified = verify::ServerCertVerified::assertion();
            let sig_verified = verify::HandshakeSignatureValid::assertion();
            Ok(Box::new(ExpectFinished {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                cert_verified,
                sig_verified,
                ech_retry_configs,
            }))
        } else {
            if exts.early_data_extension_offered() {
                return Err(PeerMisbehaved::EarlyDataExtensionWithoutResumption.into());
            }
            cx.common
                .handshake_kind
                .get_or_insert(HandshakeKind::Full);

            Ok(if self.hello.offered_cert_compression {
                Box::new(ExpectCertificateOrCompressedCertificateOrCertReq {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    ech_retry_configs,
                })
            } else {
                Box::new(ExpectCertificateOrCertReq {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    ech_retry_configs,
                })
            })
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificateOrCompressedCertificateOrCertReq {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCompressedCertificateOrCertReq {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
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
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
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
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                ech_retry_configs: self.ech_retry_configs,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::CertificateRequestTls13(..),
                        ..
                    },
                ..
            } => Box::new(ExpectCertificateRequest {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_cert_compression: true,
                ech_retry_configs: self.ech_retry_configs,
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificateOrCompressedCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCompressedCertificate {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
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
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: self.client_auth,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
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
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: self.client_auth,
                ech_retry_configs: self.ech_retry_configs,
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

struct ExpectCertificateOrCertReq {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCertReq {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
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
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::CertificateRequestTls13(..),
                        ..
                    },
                ..
            } => Box::new(ExpectCertificateRequest {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_cert_compression: false,
                ech_retry_configs: self.ech_retry_configs,
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// TLS1.3 version of CertificateRequest handling.  We then move to expecting the server
// Certificate. Unfortunately the CertificateRequest type changed in an annoying way
// in TLS1.3.
struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    offered_cert_compression: bool,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificateRequest {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let certreq = &require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTls13
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

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

        let no_sigschemes = Vec::new();
        let compat_sigschemes = certreq
            .sigalgs_extension()
            .unwrap_or(&no_sigschemes)
            .iter()
            .cloned()
            .filter(SignatureScheme::supported_in_tls13)
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon,
            ));
        }

        let compat_compressor = certreq
            .certificate_compression_extension()
            .and_then(|offered| {
                self.config
                    .cert_compressors
                    .iter()
                    .find(|compressor| offered.contains(&compressor.algorithm()))
            })
            .cloned();

        let client_auth = ClientAuthDetails::resolve(
            self.config
                .client_auth_cert_resolver
                .as_ref(),
            certreq.authorities_extension(),
            &compat_sigschemes,
            Some(certreq.context.0.clone()),
            compat_compressor,
        );

        Ok(if self.offered_cert_compression {
            Box::new(ExpectCertificateOrCompressedCertificate {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: Some(client_auth),
                ech_retry_configs: self.ech_retry_configs,
            })
        } else {
            Box::new(ExpectCertificate {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: Some(client_auth),
                message_already_in_transcript: false,
                ech_retry_configs: self.ech_retry_configs,
            })
        })
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCompressedCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCompressedCertificate {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
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
            "Server certificate decompressed using {:?} ({} bytes -> {})",
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
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: self.client_auth,
            message_already_in_transcript: true,
            ech_retry_configs: self.ech_retry_configs,
        })
        .handle(cx, m)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    message_already_in_transcript: bool,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
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

        if cert_chain.any_entry_has_duplicate_extension()
            || cert_chain.any_entry_has_unknown_extension()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::BadCertChainExtensions,
            ));
        }
        let end_entity_ocsp = cert_chain.end_entity_ocsp();
        let server_cert = ServerCertDetails::new(
            cert_chain
                .into_certificate_chain()
                .into_owned(),
            end_entity_ocsp,
        );

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert,
            client_auth: self.client_auth,
            ech_retry_configs: self.ech_retry_configs,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify<'a> {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    server_cert: ServerCertDetails<'a>,
    client_auth: Option<ClientAuthDetails>,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectCertificateVerify<'_> {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let cert_verify = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        trace!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        let (end_entity, intermediates) = self
            .server_cert
            .cert_chain
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;

        let now = self.config.current_time()?;

        let cert_verified = self
            .config
            .verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &self.server_name,
                &self.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| {
                cx.common
                    .send_cert_verify_error_alert(err)
            })?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.transcript.current_hash();
        let sig_verified = self
            .config
            .verifier
            .verify_tls13_signature(
                construct_server_verify_message(&handshake_hash).as_ref(),
                end_entity,
                cert_verify,
            )
            .map_err(|err| {
                cx.common
                    .send_cert_verify_error_alert(err)
            })?;

        cx.common.peer_certificates = Some(self.server_cert.cert_chain.into_owned());
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            config: self.config,
            server_name: self.server_name,
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

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectCertificateVerify {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert: self.server_cert.into_owned(),
            client_auth: self.client_auth,
            ech_retry_configs: self.ech_retry_configs,
        })
    }
}

fn emit_compressed_certificate_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    certkey: &CertifiedKey,
    auth_context: Option<Vec<u8>>,
    compressor: &dyn compress::CertCompressor,
    config: &ClientConfig,
) {
    let mut cert_payload = CertificatePayloadTls13::new(certkey.cert.iter(), None);
    cert_payload.context = PayloadU8::new(auth_context.clone().unwrap_or_default());

    let compressed = match config
        .cert_compression_cache
        .compression_for(compressor, &cert_payload)
    {
        Ok(compressed) => compressed,
        Err(_) => return emit_certificate_tls13(flight, Some(certkey), auth_context),
    };

    flight.add(HandshakeMessagePayload {
        typ: HandshakeType::CompressedCertificate,
        payload: HandshakePayload::CompressedCertificate(compressed.compressed_cert_payload()),
    });
}

fn emit_certificate_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    certkey: Option<&CertifiedKey>,
    auth_context: Option<Vec<u8>>,
) {
    let certs = certkey
        .map(|ck| ck.cert.as_ref())
        .unwrap_or(&[][..]);
    let mut cert_payload = CertificatePayloadTls13::new(certs.iter(), None);
    cert_payload.context = PayloadU8::new(auth_context.unwrap_or_default());

    flight.add(HandshakeMessagePayload {
        typ: HandshakeType::Certificate,
        payload: HandshakePayload::CertificateTls13(cert_payload),
    });
}

fn emit_certverify_tls13(
    flight: &mut HandshakeFlightTls13<'_>,
    signer: &dyn Signer,
) -> Result<(), Error> {
    let message = construct_client_verify_message(&flight.transcript.current_hash());

    let scheme = signer.scheme();
    let sig = signer.sign(message.as_ref())?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    flight.add(HandshakeMessagePayload {
        typ: HandshakeType::CertificateVerify,
        payload: HandshakePayload::CertificateVerify(dss),
    });
    Ok(())
}

fn emit_finished_tls13(flight: &mut HandshakeFlightTls13<'_>, verify_data: &crypto::hmac::Tag) {
    let verify_data_payload = Payload::new(verify_data.as_ref());

    flight.add(HandshakeMessagePayload {
        typ: HandshakeType::Finished,
        payload: HandshakePayload::Finished(verify_data_payload),
    });
}

fn emit_end_of_early_data_tls13(transcript: &mut HandshakeHash, common: &mut CommonState) {
    if common.is_quic() {
        return;
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload {
            typ: HandshakeType::EndOfEarlyData,
            payload: HandshakePayload::EndOfEarlyData,
        }),
    };

    transcript.add_message(&m);
    common.send_msg(m, true);
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
    ech_retry_configs: Option<Vec<EchConfigPayload>>,
}

impl State<ClientConnectionData> for ExpectFinished {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.current_hash();
        let expect_verify_data = st
            .key_schedule
            .sign_server_finish(&handshake_hash);

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
                    certkey,
                    signer,
                    auth_context_tls13: auth_context,
                    compressor,
                } => {
                    if let Some(compressor) = compressor {
                        emit_compressed_certificate_tls13(
                            &mut flight,
                            &certkey,
                            auth_context,
                            compressor,
                            &st.config,
                        );
                    } else {
                        emit_certificate_tls13(&mut flight, Some(&certkey), auth_context);
                    }
                    emit_certverify_tls13(&mut flight, signer.as_ref())?;
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
            .remove_tls12_session(&st.server_name);

        /* Now move to our application traffic keys. */
        cx.common.check_aligned_handshake()?;
        let key_schedule_traffic = key_schedule_pre_finished.into_traffic(cx.common);
        cx.common
            .start_traffic(&mut cx.sendable_plaintext);

        // Now that we've reached the end of the normal handshake we must enforce ECH acceptance by
        // sending an alert and returning an error (potentially with retry configs) if the server
        // did not accept our ECH offer.
        if cx.data.ech_status == EchStatus::Rejected {
            return Err(ech::fatal_alert_required(st.ech_retry_configs, cx.common));
        }

        let st = ExpectTraffic {
            config: Arc::clone(&st.config),
            session_storage: Arc::clone(&st.config.resumption.store),
            server_name: st.server_name,
            suite: st.suite,
            transcript: st.transcript,
            key_schedule: key_schedule_traffic,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        };

        Ok(match cx.common.is_quic() {
            true => Box::new(ExpectQuicTraffic(st)),
            false => Box::new(st),
        })
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, key updates,
// and application data.
struct ExpectTraffic {
    config: Arc<ClientConfig>,
    session_storage: Arc<dyn ClientSessionStore>,
    server_name: ServerName<'static>,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleTraffic,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_new_ticket_tls13(
        &mut self,
        cx: &mut ClientContext<'_>,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        if nst.has_duplicate_extension() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DuplicateNewSessionTicketExtensions,
            ));
        }

        let handshake_hash = self.transcript.current_hash();
        let secret = ResumptionSecret::new(&self.key_schedule, &handshake_hash)
            .derive_ticket_psk(&nst.nonce.0);

        let now = self.config.current_time()?;

        #[allow(unused_mut)]
        let mut value = persist::Tls13ClientSessionValue::new(
            self.suite,
            Arc::clone(&nst.ticket),
            secret.as_ref(),
            cx.common
                .peer_certificates
                .clone()
                .unwrap_or_default(),
            now,
            nst.lifetime,
            nst.age_add,
            nst.max_early_data_size()
                .unwrap_or_default(),
        );

        if cx.common.is_quic() {
            if let Some(sz) = nst.max_early_data_size() {
                if sz != 0 && sz != 0xffff_ffff {
                    return Err(PeerMisbehaved::InvalidMaxEarlyDataSize.into());
                }
            }

            if let Some(ref quic_params) = &cx.common.quic.params {
                value.set_quic_params(quic_params);
            }
        }

        self.session_storage
            .insert_tls13_ticket(self.server_name.clone(), value);
        Ok(())
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

impl State<ClientConnectionData> for ExpectTraffic {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
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
                        payload: HandshakePayload::NewSessionTicketTls13(ref new_ticket),
                        ..
                    },
                ..
            } => self.handle_new_ticket_tls13(cx, new_ticket)?,
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload {
                        payload: HandshakePayload::KeyUpdate(ref key_update),
                        ..
                    },
                ..
            } => self.handle_key_update(cx.common, key_update)?,
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

    fn send_key_update_request(&mut self, common: &mut CommonState) -> Result<(), Error> {
        self.key_schedule
            .request_key_update_and_update_encrypter(common)
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
            .extract_secrets(Side::Client)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectQuicTraffic(ExpectTraffic);

impl State<ClientConnectionData> for ExpectQuicTraffic {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let nst = require_handshake_msg!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicketTls13
        )?;
        self.0
            .handle_new_ticket_tls13(cx, nst)?;
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.0
            .export_keying_material(output, label, context)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}
