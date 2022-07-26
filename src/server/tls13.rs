use std::prelude::v1::*;
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::enums::{AlertDescription, SignatureScheme, NamedGroup};
use crate::msgs::enums::{Compression, PSKKeyExchangeMode};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::handshake::HandshakePayload;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::handshake::CertificateEntry;
use crate::msgs::handshake::CertificateExtension;
use crate::msgs::handshake::CertificateStatus;
use crate::msgs::handshake::CertificatePayloadTLS13;
use crate::msgs::handshake::CertificateRequestPayloadTLS13;
use crate::msgs::handshake::CertReqExtension;
use crate::msgs::handshake::ClientHelloPayload;
use crate::msgs::handshake::HelloRetryRequest;
use crate::msgs::handshake::HelloRetryExtension;
use crate::msgs::handshake::ServerHelloPayload;
use crate::msgs::handshake::KeyShareEntry;
use crate::msgs::handshake::SessionID;
use crate::msgs::handshake::ServerExtension;
use crate::msgs::handshake::Random;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::persist;
use crate::server::ServerSessionImpl;
use crate::key_schedule::{KeySchedule, SecretKind};
use crate::cipher;
use crate::verify;
use crate::rand;
use crate::sign;
use crate::suites;
use crate::util;
#[cfg(feature = "logging")]
use crate::log::{warn, trace, debug};
use crate::error::TLSError;
use crate::handshake::{check_handshake_message, check_message};
#[cfg(feature = "quic")]
use crate::{
    quic,
    msgs::handshake::NewSessionTicketExtension,
    session::Protocol
};

use crate::server::common::{HandshakeDetails, ClientCertDetails};
use crate::server::hs;

use ring::constant_time;

pub struct CompleteClientHelloHandling {
    pub handshake: HandshakeDetails,
    pub done_retry: bool,
    pub send_cert_status: bool,
    pub send_sct: bool,
    pub send_ticket: bool,
}

impl CompleteClientHelloHandling {
    fn check_binder(&self,
                    sess: &mut ServerSessionImpl,
                    client_hello: &Message,
                    psk: &[u8],
                    binder: &[u8])
                    -> bool {
        let binder_plaintext = match client_hello.payload {
            MessagePayload::Handshake(ref hmp) => hmp.get_encoding_for_binder_signing(),
            _ => unreachable!(),
        };

        let suite = sess.common.get_suite_assert();
        let suite_hash = suite.get_hash();
        let handshake_hash = self.handshake.transcript.get_hash_given(suite_hash, &binder_plaintext);

        let key_schedule = KeySchedule::new(suite.hkdf_algorithm, &psk);
        let base_key = key_schedule.derive_for_empty_hash(SecretKind::ResumptionPSKBinderKey);
        let real_binder = key_schedule.sign_verify_data(&base_key, &handshake_hash);

        constant_time::verify_slices_are_equal(&real_binder, binder).is_ok()
    }

    fn into_expect_retried_client_hello(self) -> hs::NextState {
        Box::new(hs::ExpectClientHello {
            handshake: self.handshake,
            done_retry: true,
            send_cert_status: self.send_cert_status,
            send_sct: self.send_sct,
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_certificate(self) -> hs::NextState {
        Box::new(ExpectCertificate {
            handshake: self.handshake,
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            send_ticket: self.send_ticket,
        })
    }

    fn emit_server_hello(&mut self,
                         sess: &mut ServerSessionImpl,
                         session_id: &SessionID,
                         share: &KeyShareEntry,
                         chosen_psk_idx: Option<usize>,
                         resuming_psk: Option<&[u8]>)
                           -> Result<(), TLSError> {
        let mut extensions = Vec::new();

        // Do key exchange
        let kxr = suites::KeyExchange::start_ecdhe(share.group)
            .and_then(|kx| kx.complete(&share.payload.0))
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;

        let kse = KeyShareEntry::new(share.group, kxr.pubkey.as_ref());
        extensions.push(ServerExtension::KeyShare(kse));
        extensions.push(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        if let Some(psk_idx) = chosen_psk_idx {
            extensions.push(ServerExtension::PresharedKey(psk_idx as u16));
        }

        let sh = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from_slice(&self.handshake.randoms.server),
                    session_id: *session_id,
                    cipher_suite: sess.common.get_suite_assert().suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            }),
        };

        hs::check_aligned_handshake(sess)?;

        #[cfg(feature = "quic")]
        let client_hello_hash = self.handshake.transcript
            .get_hash_given(sess.common.get_suite_assert().get_hash(), &[]);

        trace!("sending server hello {:?}", sh);
        self.handshake.transcript.add_message(&sh);
        sess.common.send_msg(sh, false);

        // Start key schedule
        let suite = sess.common.get_suite_assert();
        let mut key_schedule;
        if let Some(psk) = resuming_psk {
            key_schedule = KeySchedule::new(suite.hkdf_algorithm, psk);

            #[cfg(feature = "quic")] {
                if sess.common.protocol == Protocol::Quic {
                    let client_early_traffic_secret = key_schedule
                        .derive_logged_secret(
                            SecretKind::ClientEarlyTrafficSecret,
                            &client_hello_hash,
                            &*sess.config.key_log,
                            &self.handshake.randoms.client);
                    // If 0-RTT should be rejected, this will be clobbered by ExtensionProcessing
                    // before the application can see.
                    sess.common.quic.early_secret = Some(client_early_traffic_secret);
                }
            }
        } else {
            key_schedule = KeySchedule::new_with_empty_secret(suite.hkdf_algorithm);
        }
        key_schedule.input_secret(&kxr.premaster_secret);

        let handshake_hash = self.handshake.transcript.get_current_hash();
        let write_key = key_schedule.derive_logged_secret(
            SecretKind::ServerHandshakeTrafficSecret,
            &handshake_hash,
            &*sess.config.key_log,
            &self.handshake.randoms.client);
        sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        let read_key = key_schedule.derive_logged_secret(
            SecretKind::ClientHandshakeTrafficSecret,
            &handshake_hash,
            &*sess.config.key_log,
            &self.handshake.randoms.client);
        sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

        #[cfg(feature = "quic")] {
            sess.common.quic.hs_secrets = Some(quic::Secrets {
                client: read_key.clone(),
                server: write_key.clone(),
            });
        }

        key_schedule.current_client_traffic_secret = Some(read_key);
        key_schedule.current_server_traffic_secret = Some(write_key);
        sess.common.set_key_schedule(key_schedule);

        Ok(())
    }

    fn emit_fake_ccs(&mut self,
                     sess: &mut ServerSessionImpl) {
        #[cfg(feature = "quic")] {
            if let Protocol::Quic = sess.common.protocol { return; }
        }
        let m = Message {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
        };
        sess.common.send_msg(m, false);
    }

    fn emit_hello_retry_request(&mut self,
                                sess: &mut ServerSessionImpl,
                                group: NamedGroup) {
        let mut req = HelloRetryRequest {
            legacy_version: ProtocolVersion::TLSv1_2,
            session_id: SessionID::empty(),
            cipher_suite: sess.common.get_suite_assert().suite,
            extensions: Vec::new(),
        };

        req.extensions.push(HelloRetryExtension::KeyShare(group));
        req.extensions.push(HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_3));

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::HelloRetryRequest,
                payload: HandshakePayload::HelloRetryRequest(req),
            }),
        };

        trace!("Requesting retry {:?}", m);
        self.handshake.transcript.rollup_for_hrr();
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, false);
    }

    fn emit_encrypted_extensions(&mut self,
                                 sess: &mut ServerSessionImpl,
                                 server_key: &mut sign::CertifiedKey,
                                 hello: &ClientHelloPayload,
                                 resumedata: Option<&persist::ServerSessionValue>)
                                 -> Result<(), TLSError> {
        let mut ep = hs::ExtensionProcessing::new();
        ep.process_common(sess, Some(server_key), hello, resumedata, &self.handshake)?;

        self.send_cert_status = ep.send_cert_status;
        self.send_sct = ep.send_sct;

        let ee = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::EncryptedExtensions,
                payload: HandshakePayload::EncryptedExtensions(ep.exts),
            }),
        };

        trace!("sending encrypted extensions {:?}", ee);
        self.handshake.transcript.add_message(&ee);
        sess.common.send_msg(ee, true);
        Ok(())
    }

    fn emit_certificate_req_tls13(&mut self, sess: &mut ServerSessionImpl) -> bool {
        if !sess.config.verifier.offer_client_auth() {
            return false;
        }

        let mut cr = CertificateRequestPayloadTLS13 {
            context: PayloadU8::empty(),
            extensions: Vec::new(),
        };

        let schemes = verify::supported_verify_schemes();
        cr.extensions.push(CertReqExtension::SignatureAlgorithms(schemes.to_vec()));

        let names = sess.config.verifier.client_auth_root_subjects();
        if !names.is_empty() {
            cr.extensions.push(CertReqExtension::AuthorityNames(names));
        }

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateRequest,
                payload: HandshakePayload::CertificateRequestTLS13(cr),
            }),
        };

        trace!("Sending CertificateRequest {:?}", m);
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
        true
    }

    fn emit_certificate_tls13(&mut self,
                              sess: &mut ServerSessionImpl,
                              server_key: &mut sign::CertifiedKey) {
        let mut cert_entries = vec![];
        for cert in server_key.take_cert() {
            let entry = CertificateEntry {
                cert,
                exts: Vec::new(),
            };

            cert_entries.push(entry);
        }

        if let Some(end_entity_cert) = cert_entries.first_mut() {
            // Apply OCSP response to first certificate (we don't support OCSP
            // except for leaf certs).
            if self.send_cert_status {
                if let Some(ocsp) = server_key.take_ocsp() {
                    let cst = CertificateStatus::new(ocsp);
                    end_entity_cert.exts.push(CertificateExtension::CertificateStatus(cst));
                }
            }

            // Likewise, SCT
            if self.send_sct {
                if let Some(sct_list) = server_key.take_sct_list() {
                    end_entity_cert.exts.push(CertificateExtension::make_sct(sct_list));
                }
            }
        }

        let cert_body = CertificatePayloadTLS13::new(cert_entries);
        let c = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Certificate,
                payload: HandshakePayload::CertificateTLS13(cert_body),
            }),
        };

        trace!("sending certificate {:?}", c);
        self.handshake.transcript.add_message(&c);
        sess.common.send_msg(c, true);
    }

    fn emit_certificate_verify_tls13(&mut self,
                                     sess: &mut ServerSessionImpl,
                                     server_key: &mut sign::CertifiedKey,
                                     schemes: &[SignatureScheme])
                                     -> Result<(), TLSError> {
        let mut message = Vec::new();
        message.resize(64, 0x20u8);
        message.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        message.extend_from_slice(&self.handshake.transcript.get_current_hash());

        let signing_key = &server_key.key;
        let signer = signing_key.choose_scheme(schemes)
            .ok_or_else(|| hs::incompatible(sess, "no overlapping sigschemes"))?;

        let scheme = signer.get_scheme();
        let sig = signer.sign(&message)?;

        let cv = DigitallySignedStruct::new(scheme, sig);

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::CertificateVerify,
                payload: HandshakePayload::CertificateVerify(cv),
            }),
        };

        trace!("sending certificate-verify {:?}", m);
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
        Ok(())
    }

    fn emit_finished_tls13(&mut self, sess: &mut ServerSessionImpl) {
        let handshake_hash = self.handshake.transcript.get_current_hash();
        let verify_data = sess.common
            .get_key_schedule()
            .sign_finish(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);
        let verify_data_payload = Payload::new(verify_data);

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        trace!("sending finished {:?}", m);
        self.handshake.transcript.add_message(&m);
        self.handshake.hash_at_server_fin = self.handshake.transcript.get_current_hash();
        sess.common.send_msg(m, true);

        // Now move to application data keys.
        sess.common.get_mut_key_schedule().input_empty();
        let write_key = sess.common
            .get_key_schedule()
            .derive_logged_secret(SecretKind::ServerApplicationTrafficSecret,
                                  &self.handshake.hash_at_server_fin,
                                  &*sess.config.key_log,
                                  &self.handshake.randoms.client);
        let suite = sess.common.get_suite_assert();
        sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

        #[cfg(feature = "quic")] {
            let read_key = sess.common.get_key_schedule()
                .derive(sess.common.get_key_schedule().algorithm(),
                        SecretKind::ClientApplicationTrafficSecret,
                        &self.handshake.hash_at_server_fin);
            sess.common.quic.traffic_secrets = Some(quic::Secrets {
                client: read_key,
                server: write_key.clone(),
            });
        }

        sess.common.get_mut_key_schedule()
            .current_server_traffic_secret = Some(write_key);
        let exporter_secret = sess.common
            .get_key_schedule()
            .derive_logged_secret(SecretKind::ExporterMasterSecret,
                                  &self.handshake.hash_at_server_fin,
                                  &*sess.config.key_log,
                                  &self.handshake.randoms.client);
        sess.common
            .get_mut_key_schedule()
            .current_exporter_secret = Some(exporter_secret);
    }

    fn attempt_tls13_ticket_decryption(&mut self,
                                       sess: &mut ServerSessionImpl,
                                       ticket: &[u8]) -> Option<persist::ServerSessionValue> {
        if sess.config.ticketer.enabled() {
            sess.config
                .ticketer
                .decrypt(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        } else {
            sess.config
                .session_storage
                .take(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        }
    }

    pub fn handle_client_hello(mut self,
                               sess: &mut ServerSessionImpl,
                               sni: Option<webpki::DNSName>,
                               mut server_key: sign::CertifiedKey,
                               chm: &Message) -> hs::NextStateOrError {
        let client_hello = extract_handshake!(chm, HandshakePayload::ClientHello).unwrap();

        if client_hello.compression_methods.len() != 1 {
            return Err(hs::illegal_param(sess, "client offered wrong compressions"));
        }

        let groups_ext = client_hello.get_namedgroups_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't describe groups"))?;

        let mut sigschemes_ext = client_hello.get_sigalgs_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't describe sigschemes"))?
            .clone();

        let tls13_schemes = sign::supported_sign_tls13();
        sigschemes_ext.retain(|scheme| tls13_schemes.contains(scheme));

        let shares_ext = client_hello.get_keyshare_extension()
            .ok_or_else(|| hs::incompatible(sess, "client didn't send keyshares"))?;

        if client_hello.has_keyshare_extension_with_duplicates() {
            return Err(hs::illegal_param(sess, "client sent duplicate keyshares"));
        }

        let share_groups: Vec<NamedGroup> = shares_ext.iter()
            .map(|share| share.group)
            .collect();

        let supported_groups = suites::KeyExchange::supported_groups();
        let chosen_group = util::first_in_both(supported_groups, &share_groups);
        if chosen_group.is_none() {
            // We don't have a suitable key share.  Choose a suitable group and
            // send a HelloRetryRequest.
            let retry_group_maybe = util::first_in_both(supported_groups, groups_ext);
            self.handshake.transcript.add_message(chm);

            if let Some(group) = retry_group_maybe {
                if self.done_retry {
                    return Err(hs::illegal_param(sess, "did not follow retry request"));
                }

                self.emit_hello_retry_request(sess, group);
                self.emit_fake_ccs(sess);
                return Ok(self.into_expect_retried_client_hello());
            }

            return Err(hs::incompatible(sess, "no kx group overlap with client"));
        }

        hs::save_sni(sess, sni);

        let chosen_group = chosen_group.unwrap();
        let chosen_share = shares_ext.iter()
            .find(|share| share.group == chosen_group)
            .unwrap();

        let mut chosen_psk_index = None;
        let mut resumedata = None;
        if let Some(psk_offer) = client_hello.get_psk() {
            if !client_hello.check_psk_ext_is_last() {
                return Err(hs::illegal_param(sess, "psk extension in wrong position"));
            }

            if psk_offer.binders.is_empty() {
                return Err(hs::decode_error(sess, "psk extension missing binder"));
            }

            if psk_offer.binders.len() != psk_offer.identities.len() {
                return Err(hs::illegal_param(sess, "psk extension mismatched ids/binders"));
            }

            for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                let maybe_resume = self.attempt_tls13_ticket_decryption(sess, &psk_id.identity.0);

                if !hs::can_resume(sess, &self.handshake, &maybe_resume) {
                    continue;
                }

                let resume = maybe_resume.unwrap();

                if !self.check_binder(sess, chm, &resume.master_secret.0, &psk_offer.binders[i].0) {
                    sess.common.send_fatal_alert(AlertDescription::DecryptError);
                    return Err(TLSError::PeerMisbehavedError("client sent wrong binder".to_string()));
                }

                chosen_psk_index = Some(i);
                resumedata = Some(resume);
                break;
            }
        }

        if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
            warn!("Resumption ignored, DHE_KE not offered");
            self.send_ticket = false;
            chosen_psk_index = None;
            resumedata = None;
        } else {
            self.send_ticket = true;
        }

        let full_handshake = resumedata.is_none();
        self.handshake.transcript.add_message(chm);
        self.emit_server_hello(sess, &client_hello.session_id,
                               chosen_share, chosen_psk_index,
                               resumedata.as_ref().map(|x| &x.master_secret.0[..]))?;
        if !self.done_retry {
            self.emit_fake_ccs(sess);
        }
        self.emit_encrypted_extensions(sess, &mut server_key, client_hello, resumedata.as_ref())?;

        let doing_client_auth = if full_handshake {
            let client_auth = self.emit_certificate_req_tls13(sess);
            self.emit_certificate_tls13(sess, &mut server_key);
            self.emit_certificate_verify_tls13(sess, &mut server_key, &sigschemes_ext)?;
            client_auth
        } else {
            false
        };

        hs::check_aligned_handshake(sess)?;
        self.emit_finished_tls13(sess);

        if doing_client_auth {
            Ok(self.into_expect_certificate())
        } else {
            Ok(self.into_expect_finished())
        }
    }
}

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub send_ticket: bool,
}

impl ExpectCertificate {
    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            send_ticket: self.send_ticket,
        })
    }

    fn into_expect_certificate_verify(self,
                                      cert: ClientCertDetails) -> hs::NextState {
        Box::new(ExpectCertificateVerify {
            handshake: self.handshake,
            client_cert: cert,
            send_ticket: self.send_ticket,
        })
    }
}

impl hs::State for ExpectCertificate {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let certp = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
        self.handshake.transcript.add_message(&m);

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(TLSError::PeerMisbehavedError("client sent unsolicited cert extension"
                                                     .to_string()));
        }

        let cert_chain = certp.convert();

        if cert_chain.is_empty() {
            if !sess.config.verifier.client_auth_mandatory() {
                debug!("client auth requested but no certificate supplied");
                self.handshake.transcript.abandon_client_auth();
                return Ok(self.into_expect_finished());
            }

            sess.common.send_fatal_alert(AlertDescription::CertificateRequired);
            return Err(TLSError::NoCertificatesPresented);
        }

        sess.config.get_verifier().verify_client_cert(&cert_chain)
            .or_else(|err| {
                     hs::incompatible(sess, "certificate invalid");
                     Err(err)
                     })?;

        let cert = ClientCertDetails::new(cert_chain);
        Ok(self.into_expect_certificate_verify(cert))
    }
}

pub struct ExpectCertificateVerify {
    handshake: HandshakeDetails,
    client_cert: ClientCertDetails,
    send_ticket: bool,
}

impl ExpectCertificateVerify {
    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            send_ticket: self.send_ticket,
        })
    }
}

impl hs::State for ExpectCertificateVerify {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_handshake_message(m, &[HandshakeType::CertificateVerify])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let rc = {
            let sig = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();
            let handshake_hash = self.handshake.transcript.get_current_hash();
            self.handshake.transcript.abandon_client_auth();
            let certs = &self.client_cert.cert_chain;

            verify::verify_tls13(&certs[0],
                                 sig,
                                 &handshake_hash,
                                 b"TLS 1.3, client CertificateVerify\x00")
        };

        if let Err(e) = rc {
            sess.common.send_fatal_alert(AlertDescription::AccessDenied);
            return Err(e);
        }

        trace!("client CertificateVerify OK");
        sess.client_cert_chain = Some(self.client_cert.take_chain());

        self.handshake.transcript.add_message(&m);
        Ok(self.into_expect_finished())
    }
}

// --- Process client's Finished ---
fn get_server_session_value(handshake: &mut HandshakeDetails,
                            sess: &ServerSessionImpl,
                            nonce: &[u8]) -> persist::ServerSessionValue {
    let scs = sess.common.get_suite_assert();
    let version = ProtocolVersion::TLSv1_3;

    let handshake_hash = handshake
        .transcript
        .get_current_hash();
    let key_schedule = sess.common.get_key_schedule();
    let resumption_master_secret =
        key_schedule.derive(key_schedule.algorithm(),
                            SecretKind::ResumptionMasterSecret,
                            &handshake_hash);
    let secret = sess.common
        .get_key_schedule()
        .derive_ticket_psk(&resumption_master_secret, nonce);

    persist::ServerSessionValue::new(
        sess.get_sni(), version,
        scs.suite, secret,
        &sess.client_cert_chain,
        sess.alpn_protocol.clone())
}

pub struct ExpectFinished {
    pub handshake: HandshakeDetails,
    pub send_ticket: bool,
}

impl ExpectFinished {
    fn into_expect_traffic(self, fin: verify::FinishedMessageVerified) -> hs::NextState {
        Box::new(ExpectTraffic {
            _fin_verified: fin,
        })
    }

    fn emit_stateless_ticket(&mut self, sess: &mut ServerSessionImpl) {
        debug_assert!(self.send_ticket);
        let nonce = rand::random_vec(32);
        let plain = get_server_session_value(&mut self.handshake,
                                             sess, &nonce)
            .get_encoding();
        let maybe_ticket = sess.config
            .ticketer
            .encrypt(&plain);
        let ticket_lifetime = sess.config.ticketer.get_lifetime();

        if maybe_ticket.is_none() {
            return;
        }

        let ticket = maybe_ticket.unwrap();
        let age_add = rand::random_u32(); // nb, we don't do 0-RTT data, so whatever
        #[allow(unused_mut)]
        let mut payload = NewSessionTicketPayloadTLS13::new(ticket_lifetime, age_add, nonce, ticket);
        #[cfg(feature = "quic")] {
            if sess.config.max_early_data_size > 0 && sess.common.protocol == Protocol::Quic {
                payload.exts.push(NewSessionTicketExtension::EarlyData(sess.config.max_early_data_size));
            }
        }
        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::NewSessionTicket,
                payload: HandshakePayload::NewSessionTicketTLS13(payload),
            }),
        };

        trace!("sending new ticket {:?}", m);
        self.handshake.transcript.add_message(&m);
        sess.common.send_msg(m, true);
    }

    fn emit_stateful_ticket(&mut self, sess: &mut ServerSessionImpl) {
        debug_assert!(self.send_ticket);
        let nonce = rand::random_vec(32);
        let id = rand::random_vec(32);
        let plain = get_server_session_value(&mut self.handshake,
                                             sess, &nonce)
            .get_encoding();

        if sess.config.session_storage.put(id.clone(), plain) {
            let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
            let age_add = rand::random_u32();
            #[allow(unused_mut)]
            let mut payload = NewSessionTicketPayloadTLS13::new(stateful_lifetime, age_add, nonce, id);
            #[cfg(feature = "quic")] {
                if sess.config.max_early_data_size > 0 && sess.common.protocol == Protocol::Quic {
                    payload.exts.push(NewSessionTicketExtension::EarlyData(sess.config.max_early_data_size));
                }
            }
            let m = Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::Handshake(HandshakeMessagePayload {
                    typ: HandshakeType::NewSessionTicket,
                    payload: HandshakePayload::NewSessionTicketTLS13(payload),
                }),
            };

            trace!("sending new stateful ticket {:?}", m);
            self.handshake.transcript.add_message(&m);
            sess.common.send_msg(m, true);
        } else {
            trace!("resumption not available; not issuing ticket");
        }
    }
}

impl hs::State for ExpectFinished {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(mut self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        let handshake_hash = self.handshake.transcript.get_current_hash();
        let expect_verify_data = sess.common
            .get_key_schedule()
            .sign_finish(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);

        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     warn!("Finished wrong");
                     TLSError::DecryptError
                     })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // nb. future derivations include Client Finished, but not the
        // main application data keying.
        self.handshake.transcript.add_message(&m);

        // Now move to using application data keys for client traffic.
        // Server traffic is already done.
        let read_key = sess.common
            .get_key_schedule()
            .derive_logged_secret(SecretKind::ClientApplicationTrafficSecret,
                                  &self.handshake.hash_at_server_fin,
                                  &*sess.config.key_log,
                                  &self.handshake.randoms.client);

        let suite = sess.common.get_suite_assert();
        hs::check_aligned_handshake(sess)?;
        sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.common
            .get_mut_key_schedule()
            .current_client_traffic_secret = Some(read_key);

        if self.send_ticket {
            if sess.config.ticketer.enabled() {
                self.emit_stateless_ticket(sess);
            } else {
                self.emit_stateful_ticket(sess);
            }
        }

        sess.common.we_now_encrypting();
        sess.common.start_traffic();

        #[cfg(feature = "quic")] {
            if sess.common.protocol == Protocol::Quic {
                return Ok(Box::new(ExpectQUICTraffic { _fin_verified: fin }));
            }
        }

        Ok(self.into_expect_traffic(fin))
    }
}

// --- Process traffic ---
pub struct ExpectTraffic {
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_traffic(&self, sess: &mut ServerSessionImpl, mut m: Message) -> Result<(), TLSError> {
        sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(())
    }

    fn handle_key_update(&self, sess: &mut ServerSessionImpl, m: Message) -> Result<(), TLSError> {
        let kur = extract_handshake!(m, HandshakePayload::KeyUpdate).unwrap();
        sess.common.process_key_update(*kur, SecretKind::ClientApplicationTrafficSecret)
    }
}

impl hs::State for ExpectTraffic {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        check_message(m,
                      &[ContentType::ApplicationData, ContentType::Handshake],
                      &[HandshakeType::KeyUpdate])
    }

    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            self.handle_traffic(sess, m)?;
        } else if m.is_handshake_type(HandshakeType::KeyUpdate) {
            self.handle_key_update(sess, m)?;
        }

        Ok(self)
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic {
    _fin_verified: verify::FinishedMessageVerified,
}

#[cfg(feature = "quic")]
impl hs::State for ExpectQUICTraffic {
    fn check_message(&self, m: &Message) -> hs::CheckResult {
        Err(TLSError::InappropriateMessage {
            expect_types: Vec::new(),
            got_type: m.typ,
        })
    }

    fn handle(self: Box<Self>, _: &mut ServerSessionImpl, _: Message) -> hs::NextStateOrError {
        unreachable!("check_message always fails");
    }
}
