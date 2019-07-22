use crate::msgs::enums::{ContentType, HandshakeType, ExtensionType, SignatureScheme};
use crate::msgs::enums::{ProtocolVersion, AlertDescription, NamedGroup};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::handshake::{HandshakePayload, HandshakeMessagePayload};
use crate::msgs::handshake::{SessionID, ServerHelloPayload, HasServerExtensions};
use crate::msgs::handshake::{ClientExtension, HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::EncryptedExtensions;
use crate::msgs::handshake::{CertificatePayloadTLS13, CertificateEntry};
use crate::msgs::handshake::{PresharedKeyIdentity, PresharedKeyOffer};
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::persist;
use crate::client::ClientSessionImpl;
use crate::key_schedule::{SecretKind, KeySchedule};
use crate::cipher;
use crate::hash_hs;
use crate::verify;
use crate::sign;
use crate::suites;
use crate::ticketer;
#[cfg(feature = "logging")]
use crate::log::{debug, warn};
use crate::error::TLSError;
use crate::handshake::{check_message, check_handshake_message};
#[cfg(feature = "quic")]
use crate::{
    quic,
    msgs::base::PayloadU16,
    session::Protocol
};

use crate::client::common::{ServerCertDetails, HandshakeDetails};
use crate::client::common::{ClientHelloDetails, ClientAuthDetails};
use crate::client::hs;

use ring::constant_time;
use webpki;

// Extensions we expect in plaintext in the ServerHello.
static ALLOWED_PLAINTEXT_EXTS: &'static [ExtensionType] = &[
    ExtensionType::KeyShare,
    ExtensionType::PreSharedKey,
    ExtensionType::SupportedVersions,
];

// Only the intersection of things we offer, and those disallowed
// in TLS1.3
static DISALLOWED_TLS13_EXTS: &'static [ExtensionType] = &[
    ExtensionType::ECPointFormats,
    ExtensionType::SessionTicket,
    ExtensionType::RenegotiationInfo,
    ExtensionType::ExtendedMasterSecret,
];

pub fn validate_server_hello(sess: &mut ClientSessionImpl,
                             server_hello: &ServerHelloPayload) -> Result<(), TLSError> {
    for ext in &server_hello.extensions {
        if !ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError("server sent unexpected cleartext ext"
                                                     .to_string()));
        }
    }

    Ok(())
}

fn find_kx_hint(sess: &mut ClientSessionImpl, dns_name: webpki::DNSNameRef) -> Option<NamedGroup> {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);
    let key_buf = key.get_encoding();

    let maybe_value = sess.config.session_persistence.get(&key_buf);
    maybe_value.and_then(|enc| NamedGroup::read_bytes(&enc))
}

fn save_kx_hint(sess: &mut ClientSessionImpl, dns_name: webpki::DNSNameRef, group: NamedGroup) {
    let key = persist::ClientSessionKey::hint_for_dns_name(dns_name);

    sess.config.session_persistence.put(key.get_encoding(), group.get_encoding());
}

pub fn choose_kx_groups(sess: &mut ClientSessionImpl,
                        exts: &mut Vec<ClientExtension>,
                        hello: &mut ClientHelloDetails,
                        handshake: &mut HandshakeDetails,
                        retryreq: Option<&HelloRetryRequest>) {
    // Choose our groups:
    // - if we've been asked via HelloRetryRequest for a specific
    //   one, do that.
    // - if not, we might have a hint of what the server supports
    // - if not, send just X25519.
    //
    let groups = retryreq.and_then(HelloRetryRequest::get_requested_key_share_group)
        .or_else(|| find_kx_hint(sess, handshake.dns_name.as_ref()))
        .or_else(|| Some(NamedGroup::X25519))
        .map(|grp| vec![ grp ])
        .unwrap();

    let mut key_shares = vec![];

    for group in groups {
        // in reply to HelloRetryRequest, we must not alter any existing key
        // shares
        if let Some(already_offered_share) = hello.find_key_share(group) {
            key_shares.push(KeyShareEntry::new(group, already_offered_share.pubkey.as_ref()));
            hello.offered_key_shares.push(already_offered_share);
            continue;
        }

        if let Some(key_share) = suites::KeyExchange::start_ecdhe(group) {
            key_shares.push(KeyShareEntry::new(group, key_share.pubkey.as_ref()));
            hello.offered_key_shares.push(key_share);
        }
    }

    exts.push(ClientExtension::KeyShare(key_shares));
}

/// This implements the horrifying TLS1.3 hack where PSK binders have a
/// data dependency on the message they are contained within.
pub fn fill_in_psk_binder(sess: &mut ClientSessionImpl,
                          handshake: &mut HandshakeDetails,
                          hmp: &mut HandshakeMessagePayload) {
    // We need to know the hash function of the suite we're trying to resume into.
    let resuming = handshake.resuming_session.as_ref().unwrap();
    let suite = sess.find_cipher_suite(resuming.cipher_suite).unwrap();
    let hkdf_alg = suite.hkdf_algorithm;
    let suite_hash = suite.get_hash();

    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = hmp.get_encoding_for_binder_signing();
    let handshake_hash =
        handshake.transcript.get_hash_given(suite_hash, &binder_plaintext);

    let mut empty_hash_ctx = hash_hs::HandshakeHash::new();
    empty_hash_ctx.start_hash(suite_hash);
    let empty_hash = empty_hash_ctx.get_current_hash();

    // Run a fake key_schedule to simulate what the server will do if it choses
    // to resume.
    let key_schedule = KeySchedule::new(hkdf_alg, &resuming.master_secret.0);
    let base_key = key_schedule.derive(hkdf_alg, SecretKind::ResumptionPSKBinderKey, &empty_hash);
    let real_binder = key_schedule.sign_verify_data(&base_key, &handshake_hash);

    if let HandshakePayload::ClientHello(ref mut ch) = hmp.payload {
        ch.set_psk_binder(real_binder);
    };
    sess.common.set_key_schedule(key_schedule);
}

pub fn start_handshake_traffic(sess: &mut ClientSessionImpl,
                               server_hello: &ServerHelloPayload,
                               handshake: &mut HandshakeDetails,
                               hello: &mut ClientHelloDetails)
                           -> Result<(), TLSError> {
    let suite = sess.common.get_suite_assert();

    if let Some(selected_psk) = server_hello.get_psk_index() {
        if let Some(ref resuming) = handshake.resuming_session {
            let resume_from_suite = sess.find_cipher_suite(resuming.cipher_suite).unwrap();
            if !resume_from_suite.can_resume_to(suite) {
                return Err(TLSError::PeerMisbehavedError("server resuming incompatible suite"
                    .to_string()));
            }

            if selected_psk != 0 {
                return Err(TLSError::PeerMisbehavedError("server selected invalid psk"
                    .to_string()));
            }

            debug!("Resuming using PSK");
            // The key schedule has been initialized and set in fill_in_psk()
            // Server must be using the resumption suite, otherwise set_suite()
            // in ExpectServerHello::handle() would fail.
            // key_schedule.input_secret(&resuming.master_secret.0);
        } else {
            return Err(TLSError::PeerMisbehavedError("server selected unoffered psk".to_string()));
        }
    } else {
        debug!("Not resuming");
        // Discard the early data key schedule.
        sess.early_data.rejected();
        sess.common.early_traffic = false;
        sess.common.set_key_schedule(KeySchedule::new_with_empty_secret(suite.hkdf_algorithm));
        handshake.resuming_session.take();
    }

    let their_key_share = server_hello.get_key_share()
        .ok_or_else(|| {
            sess.common.send_fatal_alert(AlertDescription::MissingExtension);
            TLSError::PeerMisbehavedError("missing key share".to_string())
            })?;

    let our_key_share = hello.find_key_share_and_discard_others(their_key_share.group)
        .ok_or_else(|| hs::illegal_param(sess, "wrong group for key share"))?;
    let shared = our_key_share.complete(&their_key_share.payload.0)
        .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed"
                                                     .to_string()))?;

    save_kx_hint(sess, handshake.dns_name.as_ref(), their_key_share.group);
    sess.common.get_mut_key_schedule().input_secret(&shared.premaster_secret);

    hs::check_aligned_handshake(sess)?;

    handshake.hash_at_client_recvd_server_hello =
        handshake.transcript.get_current_hash();

    if !sess.early_data.is_enabled() {
        // Set the client encryption key for handshakes if early data is not used
        let write_key = sess.common.get_key_schedule()
            .derive_bytes(SecretKind::ClientHandshakeTrafficSecret,
                          &handshake.hash_at_client_recvd_server_hello);
        sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
        sess.config.key_log.log(sess.common.protocol.labels().client_handshake_traffic_secret,
                             &handshake.randoms.client,
                             &write_key);
        sess.common.get_mut_key_schedule().current_client_traffic_secret = write_key;
    }

    let read_key = sess.common.get_key_schedule()
        .derive_bytes(SecretKind::ServerHandshakeTrafficSecret,
                      &handshake.hash_at_client_recvd_server_hello);
    sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
    sess.config.key_log.log(sess.common.protocol.labels().server_handshake_traffic_secret,
                            &handshake.randoms.client,
                            &read_key);
    sess.common.get_mut_key_schedule().current_server_traffic_secret = read_key;

    #[cfg(feature = "quic")] {
        let key_schedule = sess.common.key_schedule.as_ref().unwrap();
        let client = if sess.early_data.is_enabled() {
            // Traffic secret wasn't computed and stored above, so do it here.
            sess.common.get_key_schedule()
                .derive_bytes(SecretKind::ClientHandshakeTrafficSecret,
                              &handshake.hash_at_client_recvd_server_hello)
        } else {
            key_schedule.current_client_traffic_secret.clone()
        };
        sess.common.quic.hs_secrets = Some(quic::Secrets {
            client,
            server: key_schedule.current_server_traffic_secret.clone(),
        });
    }

    Ok(())
}

pub fn prepare_resumption(sess: &mut ClientSessionImpl,
                          ticket: Vec<u8>,
                          handshake: &HandshakeDetails,
                          exts: &mut Vec<ClientExtension>,
                          doing_retry: bool) -> bool {
    let resuming_suite = handshake.resuming_session
        .as_ref()
        .and_then(|resume| sess.find_cipher_suite(resume.cipher_suite));

    if hs::compatible_suite(sess, resuming_suite) {
        sess.resumption_ciphersuite = resuming_suite;
        // The EarlyData extension MUST be supplied together with the
        // PreSharedKey extension.
        let max_early_data_size = handshake
            .resuming_session
            .as_ref()
            .map_or(0, |resume| resume.max_early_data_size);
        if sess.config.enable_early_data && max_early_data_size > 0 && !doing_retry {
            sess.early_data.enable(max_early_data_size as usize);
            exts.push(ClientExtension::EarlyData);
        }

        // Finally, and only for TLS1.3 with a ticket resumption, include a binder
        // for our ticket.  This must go last.
        //
        // Include an empty binder. It gets filled in below because it depends on
        // the message it's contained in (!!!).
        let (obfuscated_ticket_age, suite) = {
            let resuming = handshake.resuming_session
                .as_ref()
                .unwrap();
            (resuming.get_obfuscated_ticket_age(ticketer::timebase()), resuming.cipher_suite)
        };

        let binder_len = sess.find_cipher_suite(suite).unwrap().get_hash().output_len;
        let binder = vec![0u8; binder_len];

        let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);
        let psk_ext = PresharedKeyOffer::new(psk_identity, binder);
        exts.push(ClientExtension::PresharedKey(psk_ext));
        true
    } else {
        false
    }
}

pub fn emit_fake_ccs(hs: &mut HandshakeDetails, sess: &mut ClientSessionImpl) {
    #[cfg(feature = "quic")] {
        if let Protocol::Quic = sess.common.protocol { return; }
    }

    if hs.sent_tls13_fake_ccs {
        return;
    }

    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
    };
    sess.common.send_msg(m, false);
    hs.sent_tls13_fake_ccs = true;
}

fn validate_encrypted_extensions(sess: &mut ClientSessionImpl,
                                 hello: &ClientHelloDetails,
                                 exts: &EncryptedExtensions) -> Result<(), TLSError> {
    if exts.has_duplicate_extension() {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::PeerMisbehavedError("server sent duplicate encrypted extensions"
                                                 .to_string()));
    }

    if hello.server_sent_unsolicited_extensions(exts, &[]) {
        sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
        let msg = "server sent unsolicited encrypted extension".to_string();
        return Err(TLSError::PeerMisbehavedError(msg));
    }

    for ext in exts {
        if ALLOWED_PLAINTEXT_EXTS.contains(&ext.get_type()) ||
           DISALLOWED_TLS13_EXTS.contains(&ext.get_type()) {
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            let msg = "server sent inappropriate encrypted extension".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }
    }

    Ok(())
}

pub struct ExpectEncryptedExtensions {
    pub handshake: HandshakeDetails,
    pub server_cert: ServerCertDetails,
    pub hello: ClientHelloDetails,
}

impl ExpectEncryptedExtensions {
    fn into_expect_finished_resume(self,
                                   certv: verify::ServerCertVerified,
                                   sigv: verify::HandshakeSignatureValid) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            client_auth: None,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_certificate_or_certreq(self) -> hs::NextState {
        Box::new(ExpectCertificateOrCertReq {
            handshake: self.handshake,
            server_cert: self.server_cert,
        })
    }
}

impl hs::State for ExpectEncryptedExtensions {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::EncryptedExtensions])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let exts = extract_handshake!(m, HandshakePayload::EncryptedExtensions).unwrap();
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        self.handshake.transcript.add_message(&m);

        validate_encrypted_extensions(sess, &self.hello, exts)?;
        hs::process_alpn_protocol(sess, exts.get_alpn_protocol())?;

        #[cfg(feature = "quic")] {
            // QUIC transport parameters
            if let Some(params) = exts.get_quic_params_extension() {
                sess.common.quic.params = Some(params);
            }
        }

        if self.handshake.resuming_session.is_some() {
            let was_early_traffic = sess.common.early_traffic;
            if was_early_traffic {
                if exts.early_data_extension_offered() {
                    sess.early_data.accepted();
                } else {
                    sess.early_data.rejected();
                    sess.common.early_traffic = false;
                }
            }

            if was_early_traffic && !sess.common.early_traffic {
                // If no early traffic, set the encryption key for handshakes
                let suite = sess.common.get_suite_assert();
                let write_key = sess.common.get_key_schedule()
                    .derive_bytes(SecretKind::ClientHandshakeTrafficSecret,
                                  &self.handshake.hash_at_client_recvd_server_hello);
                sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
                sess.config.key_log.log(sess.common.protocol.labels().client_handshake_traffic_secret,
                                &self.handshake.randoms.client,
                                &write_key);
                sess.common.get_mut_key_schedule()
                    .current_client_traffic_secret = write_key;
            }
            let certv = verify::ServerCertVerified::assertion();
            let sigv =  verify::HandshakeSignatureValid::assertion();
            Ok(self.into_expect_finished_resume(certv, sigv))
        } else {
            if exts.early_data_extension_offered() {
                let msg = "server sent early data extension without resumption".to_string();
                return Err(TLSError::PeerMisbehavedError(msg));
            }
            Ok(self.into_expect_certificate_or_certreq())
        }
    }
}

struct ExpectCertificate {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
}

impl ExpectCertificate {
    fn into_expect_certificate_verify(self) -> hs::NextState {
        Box::new(ExpectCertificateVerify {
            handshake: self.handshake,
            server_cert: self.server_cert,
            client_auth: self.client_auth,
        })
    }
}

impl hs::State for ExpectCertificate {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
        self.handshake.transcript.add_message(&m);

        // This is only non-empty for client auth.
        if !cert_chain.context.0.is_empty() {
            warn!("certificate with non-empty context during handshake");
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        if cert_chain.any_entry_has_duplicate_extension() ||
            cert_chain.any_entry_has_unknown_extension() {
            warn!("certificate chain contains unsolicited/unknown extension");
            sess.common.send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(TLSError::PeerMisbehavedError("bad cert chain extensions".to_string()));
        }

        self.server_cert.ocsp_response = cert_chain.get_end_entity_ocsp();
        self.server_cert.scts = cert_chain.get_end_entity_scts();
        self.server_cert.cert_chain = cert_chain.convert();

        if let Some(sct_list) = self.server_cert.scts.as_ref() {
            if hs::sct_list_is_invalid(sct_list) {
                let error_msg = "server sent invalid SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }

            if sess.config.ct_logs.is_none() {
                let error_msg = "server sent unsolicited SCT list".to_string();
                return Err(TLSError::PeerMisbehavedError(error_msg));
            }
        }

        Ok(self.into_expect_certificate_verify())
    }
}

struct ExpectCertificateOrCertReq {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
}

impl ExpectCertificateOrCertReq {
    fn into_expect_certificate(self) -> hs::NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            client_auth: None,
        })
    }

    fn into_expect_certificate_req(self) -> hs::NextState {
        Box::new(ExpectCertificateRequest {
            handshake: self.handshake,
            server_cert: self.server_cert,
        })
    }
}

impl hs::State for ExpectCertificateOrCertReq {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m,
                                &[HandshakeType::Certificate,
                                  HandshakeType::CertificateRequest])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        if m.is_handshake_type(HandshakeType::Certificate) {
            self.into_expect_certificate().handle(sess, m)
        } else {
            self.into_expect_certificate_req().handle(sess, m)
        }
    }
}

// --- TLS1.3 CertificateVerify ---
struct ExpectCertificateVerify {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
}

impl ExpectCertificateVerify {
    fn into_expect_finished(self,
                                  certv: verify::ServerCertVerified,
                                  sigv: verify::HandshakeSignatureValid) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            client_auth: self.client_auth,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

fn send_cert_error_alert(sess: &mut ClientSessionImpl, err: TLSError) -> TLSError {
    match err {
        TLSError::WebPKIError(webpki::Error::BadDER) => {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
        }
        TLSError::PeerMisbehavedError(_) => {
            sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            sess.common.send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}

impl hs::State for ExpectCertificateVerify {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateVerify])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let cert_verify = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();

        debug!("Server cert is {:?}", self.server_cert.cert_chain);

        // 1. Verify the certificate chain.
        if self.server_cert.cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        let certv = sess.config
            .get_verifier()
            .verify_server_cert(&sess.config.root_store,
                                &self.server_cert.cert_chain,
                                self.handshake.dns_name.as_ref(),
                                &self.server_cert.ocsp_response)
            .map_err(|err| send_cert_error_alert(sess, err))?;

        // 2. Verify their signature on the handshake.
        let handshake_hash = self.handshake.transcript.get_current_hash();
        let sigv = verify::verify_tls13(&self.server_cert.cert_chain[0],
                                        cert_verify,
                                        &handshake_hash,
                                        b"TLS 1.3, server CertificateVerify\x00")
            .map_err(|err| send_cert_error_alert(sess, err))?;

        // 3. Verify any included SCTs.
        match (self.server_cert.scts.as_ref(), sess.config.ct_logs) {
            (Some(scts), Some(logs)) => {
                verify::verify_scts(&self.server_cert.cert_chain[0],
                                    scts,
                                    logs)?;
            }
            (_, _) => {}
        }

        sess.server_cert_chain = self.server_cert.take_chain();
        self.handshake.transcript.add_message(&m);

        Ok(self.into_expect_finished(certv, sigv))
    }
}

// TLS1.3 version of CertificateRequest handling.  We then move to expecting the server
// Certificate. Unfortunately the CertificateRequest type changed in an annoying way
// in TLS1.3.
struct ExpectCertificateRequest {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
}

impl ExpectCertificateRequest {
    fn into_expect_certificate(self, client_auth: ClientAuthDetails) -> hs::NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            server_cert: self.server_cert,
            client_auth: Some(client_auth),
        })
    }
}

impl hs::State for ExpectCertificateRequest {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let certreq = &extract_handshake!(m, HandshakePayload::CertificateRequestTLS13).unwrap();
        self.handshake.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // Fortunately the problems here in TLS1.2 and prior are corrected in
        // TLS1.3.

        // Must be empty during handshake.
        if !certreq.context.0.is_empty() {
            warn!("Server sent non-empty certreq context");
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        let tls13_sign_schemes = sign::supported_sign_tls13();
        let no_sigschemes = Vec::new();
        let compat_sigschemes = certreq.get_sigalgs_extension()
            .unwrap_or(&no_sigschemes)
            .iter()
            .cloned()
            .filter(|scheme| tls13_sign_schemes.contains(scheme))
            .collect::<Vec<SignatureScheme>>();

        if compat_sigschemes.is_empty() {
            sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
            return Err(TLSError::PeerIncompatibleError("server sent bad certreq schemes".to_string()));
        }

        let no_canames = Vec::new();
        let canames = certreq.get_authorities_extension()
            .unwrap_or(&no_canames)
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey =
            sess.config.client_auth_cert_resolver.resolve(&canames, &compat_sigschemes);

        let mut client_auth = ClientAuthDetails::new();
        if let Some(mut certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey.key.choose_scheme(&compat_sigschemes);
            client_auth.cert = Some(certkey.take_cert());
            client_auth.signer = maybe_signer;
            client_auth.auth_context = Some(certreq.context.0.clone());
        } else {
            debug!("Client auth requested but no cert selected");
        }

        Ok(self.into_expect_certificate(client_auth))
    }
}

fn emit_certificate_tls13(handshake: &mut HandshakeDetails,
                          client_auth: &mut ClientAuthDetails,
                          sess: &mut ClientSessionImpl) {
    let context = client_auth.auth_context
        .take()
        .unwrap_or_else(Vec::new);

    let mut cert_payload = CertificatePayloadTLS13 {
        context: PayloadU8::new(context),
        entries: Vec::new(),
    };

    if let Some(cert_chain) = client_auth.cert.take() {
        for cert in cert_chain {
            cert_payload.entries.push(CertificateEntry::new(cert));
        }
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_payload),
        }),
    };
    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn emit_certverify_tls13(handshake: &mut HandshakeDetails,
                         client_auth: &mut ClientAuthDetails,
                         sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if client_auth.signer.is_none() {
        debug!("Skipping certverify message (no client scheme/key)");
        return Ok(());
    }

    let mut message = Vec::new();
    message.resize(64, 0x20u8);
    message.extend_from_slice(b"TLS 1.3, client CertificateVerify\x00");
    message.extend_from_slice(&handshake.transcript.get_current_hash());

    let signer = client_auth.signer.take().unwrap();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(dss),
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(handshake: &mut HandshakeDetails,
                       sess: &mut ClientSessionImpl) {
    let handshake_hash = handshake.transcript.get_current_hash();
    let verify_data = sess.common
        .get_key_schedule()
        .sign_finish(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
    let verify_data_payload = Payload::new(verify_data);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn emit_end_of_early_data_tls13(handshake: &mut HandshakeDetails,
                                sess: &mut ClientSessionImpl) {
    #[cfg(feature = "quic")]
    {
        if let Protocol::Quic = sess.common.protocol { return; }
    }

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EndOfEarlyData,
            payload: HandshakePayload::EndOfEarlyData,
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

struct ExpectFinished {
    handshake: HandshakeDetails,
    client_auth: Option<ClientAuthDetails>,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    fn into_expect_traffic(self,
                                 fin: verify::FinishedMessageVerified) -> ExpectTraffic {
        ExpectTraffic {
            handshake: self.handshake,
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        }
    }
}

impl hs::State for ExpectFinished {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        let handshake_hash = st.handshake.transcript.get_current_hash();
        let expect_verify_data = sess.common
            .get_key_schedule()
            .sign_finish(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                         sess.common.send_fatal_alert(AlertDescription::DecryptError);
                         TLSError::DecryptError
                    })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        let suite = sess.common.get_suite_assert();
        let maybe_write_key = if sess.common.early_traffic {
            /* Derive the client-to-server encryption key before key schedule update */
            let key = sess.common
                .get_key_schedule()
                .derive_bytes(SecretKind::ClientHandshakeTrafficSecret,
                              &st.handshake.hash_at_client_recvd_server_hello);
            Some(key)
        } else {
            None
        };

        st.handshake.transcript.add_message(&m);

        /* Transition to application data */
        sess.common.get_mut_key_schedule().input_empty();

        /* Traffic from server is now decrypted with application data keys. */
        let handshake_hash = st.handshake.transcript.get_current_hash();
        let read_key = sess.common
            .get_key_schedule()
            .derive_bytes(SecretKind::ServerApplicationTrafficSecret, &handshake_hash);
        sess.config.key_log.log(sess.common.protocol.labels().server_traffic_secret_0,
                                &st.handshake.randoms.client,
                                &read_key);
        sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.common
            .get_mut_key_schedule()
            .current_server_traffic_secret = read_key;

        let exporter_secret = sess.common
            .get_key_schedule()
            .derive_bytes(SecretKind::ExporterMasterSecret, &handshake_hash);
        sess.config.key_log.log(sess.common.protocol.labels().exporter_secret,
                                &st.handshake.randoms.client,
                                &exporter_secret);
        sess.common
            .get_mut_key_schedule()
            .current_exporter_secret = exporter_secret;

        /* The EndOfEarlyData message to server is still encrypted with early data keys,
         * but appears in the transcript after the server Finished. */
        if let Some(write_key) = maybe_write_key {
            emit_end_of_early_data_tls13(&mut st.handshake, sess);
            sess.common.early_traffic = false;
            sess.early_data.finished();
            sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
            sess.config.key_log.log(sess.common.protocol.labels().client_handshake_traffic_secret,
                                &st.handshake.randoms.client,
                                &write_key);
            sess.common.get_mut_key_schedule().current_client_traffic_secret = write_key;
        }

        /* Send our authentication/finished messages.  These are still encrypted
         * with our handshake keys. */
        if st.client_auth.is_some() {
            emit_certificate_tls13(&mut st.handshake,
                                   st.client_auth.as_mut().unwrap(),
                                   sess);
            emit_certverify_tls13(&mut st.handshake,
                                  st.client_auth.as_mut().unwrap(),
                                  sess)?;
        }

        emit_finished_tls13(&mut st.handshake, sess);

        /* Now move to our application traffic keys. */
        hs::check_aligned_handshake(sess)?;
        let write_key = sess.common
            .get_key_schedule()
            .derive_bytes(SecretKind::ClientApplicationTrafficSecret, &handshake_hash);
        sess.config.key_log.log(sess.common.protocol.labels().client_traffic_secret_0,
                                &st.handshake.randoms.client,
                                &write_key);
        sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
        sess.common
            .get_mut_key_schedule()
            .current_client_traffic_secret = write_key;

        sess.common.we_now_encrypting();
        sess.common.start_traffic();

        let st = st.into_expect_traffic(fin);
        #[cfg(feature = "quic")] {
            if sess.common.protocol == Protocol::Quic {
                let key_schedule = sess.common.key_schedule.as_ref().unwrap();
                sess.common.quic.traffic_secrets = Some(quic::Secrets {
                    client: key_schedule.current_client_traffic_secret.clone(),
                    server: key_schedule.current_server_traffic_secret.clone(),
                });
                return Ok(Box::new(ExpectQUICTraffic(st)));
            }
        }

        Ok(Box::new(st))
    }
}

// -- Traffic transit state (TLS1.3) --
// In this state we can be sent tickets, keyupdates,
// and application data.
struct ExpectTraffic {
    handshake: HandshakeDetails,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_new_ticket_tls13(&mut self, sess: &mut ClientSessionImpl, m: Message) -> Result<(), TLSError> {
        let nst = extract_handshake!(m, HandshakePayload::NewSessionTicketTLS13).unwrap();
        let handshake_hash = self.handshake.transcript.get_current_hash();
        let key_schedule = sess.common.get_key_schedule();
        let resumption_master_secret =
            key_schedule.derive(key_schedule.algorithm(), SecretKind::ResumptionMasterSecret, &handshake_hash);
        let secret = sess.common
            .get_key_schedule()
            .derive_ticket_psk(&resumption_master_secret, &nst.nonce.0);

        let mut value = persist::ClientSessionValue::new(ProtocolVersion::TLSv1_3,
                                                         sess.common.get_suite_assert().suite,
                                                         &SessionID::empty(),
                                                         nst.ticket.0.clone(),
                                                         secret);
        value.set_times(ticketer::timebase(),
                        nst.lifetime,
                        nst.age_add);

        if let Some(sz) = nst.get_max_early_data_size() {
            value.set_max_early_data_size(sz);
            #[cfg(feature = "quic")] {
                if sess.common.protocol == Protocol::Quic {
                    if sz != 0 && sz != 0xffff_ffff {
                        return Err(TLSError::PeerMisbehavedError("invalid max_early_data_size".into()));
                    }
                }
            }
        }

        let key = persist::ClientSessionKey::session_for_dns_name(self.handshake.dns_name.as_ref());
        #[allow(unused_mut)]
        let mut ticket = value.get_encoding();

        #[cfg(feature = "quic")] {
            if sess.common.protocol == Protocol::Quic {
                PayloadU16::encode_slice(sess.common.quic.params.as_ref().unwrap(), &mut ticket);
            }
        }

        let worked = sess.config.session_persistence.put(key.get_encoding(),
                                                         ticket);

        if worked {
            debug!("Ticket saved");
        } else {
            debug!("Ticket not saved");
        }
        Ok(())
    }

    fn handle_key_update(&mut self, sess: &mut ClientSessionImpl, m: Message) -> Result<(), TLSError> {
        let kur = extract_handshake!(m, HandshakePayload::KeyUpdate).unwrap();
        sess.common.process_key_update(*kur, SecretKind::ServerApplicationTrafficSecret)
    }
}

impl hs::State for ExpectTraffic {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m,
                      &[ContentType::ApplicationData, ContentType::Handshake],
                      &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, mut m: Message) -> hs::NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
        } else if m.is_handshake_type(HandshakeType::NewSessionTicket) {
            self.handle_new_ticket_tls13(sess, m)?;
        } else if m.is_handshake_type(HandshakeType::KeyUpdate) {
            self.handle_key_update(sess, m)?;
        }

        Ok(self)
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic(ExpectTraffic);

#[cfg(feature = "quic")]
impl hs::State for ExpectQUICTraffic {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_message(m, &[ContentType::Handshake], &[HandshakeType::NewSessionTicket])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        self.0.handle_new_ticket_tls13(sess, m)?;
        Ok(self)
    }
}
