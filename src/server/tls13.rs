use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::enums::AlertDescription;
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::handshake::HandshakePayload;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::codec::Codec;
use crate::msgs::persist;
use crate::cipher;
use crate::server::ServerSessionImpl;
use crate::key_schedule::SecretKind;
use crate::verify;
use crate::rand;
#[cfg(feature = "logging")]
use crate::log::{warn, trace, debug};
use crate::error::TLSError;
use crate::handshake::{check_handshake_message, check_message};
#[cfg(feature = "quic")]
use crate::{
    msgs::handshake::NewSessionTicketExtension,
    session::Protocol
};

use crate::server::common::{HandshakeDetails, ClientCertDetails};
use crate::server::hs;

use ring::constant_time;

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

    fn handle(self: Box<Self>, sess: &mut ServerSessionImpl, m: Message) -> hs::NextStateOrError {
        let certp = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
        sess.common.hs_transcript.add_message(&m);

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
                sess.common.hs_transcript.abandon_client_auth();
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
            let handshake_hash = sess.common.hs_transcript.get_current_hash();
            sess.common.hs_transcript.abandon_client_auth();
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

        sess.common.hs_transcript.add_message(&m);
        Ok(self.into_expect_finished())
    }
}

// --- Process client's Finished ---
fn get_server_session_value(sess: &ServerSessionImpl,
                                  nonce: &[u8]) -> persist::ServerSessionValue {
    let scs = sess.common.get_suite_assert();
    let version = ProtocolVersion::TLSv1_3;

    let handshake_hash = sess.common
        .hs_transcript
        .get_current_hash();
    let resumption_master_secret = sess.common
        .get_key_schedule()
        .derive(SecretKind::ResumptionMasterSecret, &handshake_hash);
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
        let plain = get_server_session_value(sess, &nonce)
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
        sess.common.hs_transcript.add_message(&m);
        sess.common.send_msg(m, true);
    }

    fn emit_stateful_ticket(&mut self, sess: &mut ServerSessionImpl) {
        debug_assert!(self.send_ticket);
        let nonce = rand::random_vec(32);
        let id = rand::random_vec(32);
        let plain = get_server_session_value(sess, &nonce)
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
            sess.common.hs_transcript.add_message(&m);
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

        let handshake_hash = sess.common.hs_transcript.get_current_hash();
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
        sess.common.hs_transcript.add_message(&m);

        // Now move to using application data keys for client traffic.
        // Server traffic is already done.
        let read_key = sess.common
            .get_key_schedule()
            .derive(SecretKind::ClientApplicationTrafficSecret,
                    &self.handshake.hash_at_server_fin);
        sess.config.key_log.log(sess.common.protocol.labels().client_traffic_secret_0,
                                &self.handshake.randoms.client,
                                &read_key);

        let suite = sess.common.get_suite_assert();
        hs::check_aligned_handshake(sess)?;
        sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
        sess.common
            .get_mut_key_schedule()
            .current_client_traffic_secret = read_key;

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
