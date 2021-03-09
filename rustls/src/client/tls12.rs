use crate::check::check_message;
use crate::client::ClientSessionImpl;
use crate::error::TlsError;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ProtocolVersion};
use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::handshake::{DecomposedSignatureScheme, SCTList, CertificatePayload};
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::ServerKeyExchangePayload;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::session::{SessionRandoms, SessionSecrets};
use crate::SupportedCipherSuite;
use crate::kx;
use crate::ticketer;
use crate::verify;

use crate::client::common::{ClientAuthDetails, ReceivedTicketDetails};
use crate::client::common::{HandshakeDetails, ServerCertDetails, ServerKXDetails};
use crate::client::hs;

use ring::constant_time;
use std::mem;

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub randoms: SessionRandoms,
    pub using_ems: bool,
    pub suite: &'static SupportedCipherSuite,
    pub may_send_cert_status: bool,
    pub must_issue_new_ticket: bool,
    pub server_cert_sct_list: Option<SCTList>,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        _sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        let server_cert_chain =
            require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::Certificate)?;
        self.handshake
            .transcript
            .add_message(&m);

        // TODO(perf): Avoid this clone of a large object.
        let server_cert_chain = server_cert_chain.clone();

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKX {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert_sct_list: self.server_cert_sct_list,
                server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        } else {
            let server_cert = ServerCertDetails::new(
                server_cert_chain, vec![], self.server_cert_sct_list);

            Ok(Box::new(ExpectServerKX {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        }
    }
}

struct ExpectCertificateStatus {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateStatus {
    fn handle(
        mut self: Box<Self>,
        _sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        self.handshake
            .transcript
            .add_message(&m);
        let server_cert_ocsp_response = require_handshake_msg_mut!(
            m,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?.into_inner();

        trace!(
            "Server stapled OCSP response is {:?}",
            &server_cert_ocsp_response
        );

        let server_cert = ServerCertDetails::new(
            self.server_cert_chain, server_cert_ocsp_response, self.server_cert_sct_list);

        Ok(Box::new(ExpectServerKX {
            handshake: self.handshake,
            randoms: self.randoms,
            using_ems: self.using_ems,
            suite: self.suite,
            server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectCertificateStatusOrServerKX {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert_sct_list: Option<SCTList>,
    server_cert_chain: CertificatePayload,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateStatusOrServerKX {
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[
                HandshakeType::ServerKeyExchange,
                HandshakeType::CertificateStatus,
            ],
        )?;

        if m.is_handshake_type(HandshakeType::ServerKeyExchange) {
            Box::new(ExpectServerKX {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert: ServerCertDetails::new(
                    self.server_cert_chain, vec![], self.server_cert_sct_list),
                must_issue_new_ticket: self.must_issue_new_ticket,
            }).handle(sess, m)
        } else {
            Box::new(ExpectCertificateStatus {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert_sct_list: self.server_cert_sct_list,
                server_cert_chain: self.server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }).handle(sess, m)
        }
    }
}

struct ExpectServerKX {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectServerKX {
    fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        let opaque_kx = require_handshake_msg!(
            m,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.handshake
            .transcript
            .add_message(&m);

        let decoded_kx = opaque_kx.unwrap_given_kxa(&self.suite.kx)
            .ok_or_else(|| {
                sess.common
                    .send_fatal_alert(AlertDescription::DecodeError);
                TlsError::CorruptMessagePayload(ContentType::Handshake)
            })?;

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        decoded_kx.encode_params(&mut kx_params);
        let server_kx = ServerKXDetails::new(kx_params, decoded_kx.get_sig().unwrap());

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            if let ServerKeyExchangePayload::ECDHE(ecdhe) = decoded_kx {
                debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
            }
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            handshake: self.handshake,
            randoms: self.randoms,
            using_ems: self.using_ems,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

fn emit_certificate(
    handshake: &mut HandshakeDetails,
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) {
    let chosen_cert = client_auth.cert.take();

    let cert = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(chosen_cert.unwrap_or_else(Vec::new)),
        }),
    };

    handshake.transcript.add_message(&cert);
    sess.common.send_msg(cert, false);
}

fn emit_clientkx(
    handshake: &mut HandshakeDetails,
    sess: &mut ClientSessionImpl,
    kxd: &kx::KeyExchangeResult,
) {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.pubkey.as_ref()));
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    handshake.transcript.add_message(&ckx);
    sess.common.send_msg(ckx, false);
}

fn emit_certverify(
    handshake: &mut HandshakeDetails,
    client_auth: &mut ClientAuthDetails,
    sess: &mut ClientSessionImpl,
) -> Result<(), TlsError> {
    let signer = match client_auth.signer.take() {
        None => {
            trace!("Not sending CertificateVerify, no key");
            handshake
                .transcript
                .abandon_client_auth();
            return Ok(());
        },
        Some(signer) => {
            signer
        }
    };

    let message = handshake
        .transcript
        .take_handshake_buf();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
    let ccs = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(ccs, false);
}

fn emit_finished(
    secrets: &SessionSecrets,
    handshake: &mut HandshakeDetails,
    sess: &mut ClientSessionImpl,
) {
    let vh = handshake.transcript.get_current_hash();
    let verify_data = secrets.client_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    handshake.transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectCertificateRequest {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectCertificateRequest {
    fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        let certreq = require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )?;
        self.handshake
            .transcript
            .add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        let mut client_auth = ClientAuthDetails::new();

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.
        //
        // We ignore certreq.certtypes as a result, since the information it contains
        // is entirely duplicated in certreq.sigschemes.

        let canames = certreq
            .canames
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey = sess
            .config
            .client_auth_cert_resolver
            .resolve(&canames, &certreq.sigschemes);

        if let Some(mut certkey) = maybe_certkey {
            let maybe_signer = certkey
                .key
                .choose_scheme(&certreq.sigschemes);

            if let Some(_) = &maybe_signer {
                debug!("Attempting client auth");
                client_auth.cert = Some(certkey.take_cert());
            }
            client_auth.signer = maybe_signer;
        } else {
            debug!("Client auth requested but no cert/sigscheme available");
        }

        Ok(Box::new(ExpectServerDone {
            handshake: self.handshake,
            randoms: self.randoms,
            using_ems: self.using_ems,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }
}

struct ExpectServerDoneOrCertReq {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl hs::State for ExpectServerDoneOrCertReq {
    fn handle(
        mut self: Box<Self>,
        sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        if require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )
        .is_ok()
        {
            Box::new(ExpectCertificateRequest {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }).handle(sess, m)
        } else {
            self.handshake
                .transcript
                .abandon_client_auth();

            Box::new(ExpectServerDone {
                handshake: self.handshake,
                randoms: self.randoms,
                using_ems: self.using_ems,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }).handle(sess, m)
        }
    }
}

struct ExpectServerDone {
    handshake: HandshakeDetails,
    randoms: SessionRandoms,
    using_ems: bool,
    suite: &'static SupportedCipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl ExpectServerDone {
    fn into_expect_ccs(
        self,
        secrets: SessionSecrets,
        certv: verify::ServerCertVerified,
        sigv: verify::HandshakeSignatureValid,
    ) -> hs::NextState {
        Box::new(ExpectCCS {
            secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            ticket: ReceivedTicketDetails::new(),
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

impl hs::State for ExpectServerDone {
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        check_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHelloDone],
        )?;
        st.handshake.transcript.add_message(&m);

        hs::check_aligned_handshake(sess)?;

        trace!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.handshake.dns_name);

        let suite = st.suite;

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        let (end_entity, intermediates) = st
            .server_cert
            .cert_chain
            .split_first()
            .ok_or(TlsError::NoCertificatesPresented)?;
        let now = std::time::SystemTime::now();
        let cert_verified = sess
            .config
            .get_verifier()
            .verify_server_cert(
                end_entity,
                intermediates,
                st.handshake.dns_name.as_ref(),
                &mut st.server_cert.scts(),
                &st.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| hs::send_cert_error_alert(sess, err))?;

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sig_verified = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.randoms.client);
            message.extend_from_slice(&st.randoms.server);
            message.extend_from_slice(&st.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let sig = &st.server_kx.kx_sig;
            if !suite.usable_for_sigalg(sig.scheme.sign()) {
                let error_message = format!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.sign(),
                    suite.sign
                );
                return Err(TlsError::PeerMisbehavedError(error_message));
            }

            sess.config
                .get_verifier()
                .verify_tls12_signature(&message, &st.server_cert.cert_chain[0], sig)
                .map_err(|err| hs::send_cert_error_alert(sess, err))?
        };
        sess.server_cert_chain = st.server_cert.take_chain();

        // 4.
        if let Some(client_auth) = &mut st.client_auth {
            emit_certificate(&mut st.handshake, client_auth, sess);
        }

        // 5a.
        let kxd = kx::KeyExchange::client_ecdhe(&st.server_kx.kx_params, &sess.config.kx_groups)
            .ok_or_else(|| TlsError::PeerMisbehavedError("key exchange failed".to_string()))?;

        // 5b.
        emit_clientkx(&mut st.handshake, sess, &kxd);
        // nb. EMS handshake hash only runs up to ClientKeyExchange.
        let handshake_hash = st
            .handshake
            .transcript
            .get_current_hash();

        // 5c.
        if let Some(client_auth) = &mut st.client_auth {
            emit_certverify(&mut st.handshake, client_auth, sess)?;
        }

        // 5d.
        emit_ccs(sess);

        // 5e. Now commit secrets.
        let secrets = if st.using_ems {
            SessionSecrets::new_ems(
                &st.randoms,
                &handshake_hash,
                suite,
                &kxd.shared_secret,
            )
        } else {
            SessionSecrets::new(&st.randoms, suite, &kxd.shared_secret)
        };
        sess.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        sess.common
            .start_encryption_tls12(&secrets);
        sess.common
            .record_layer
            .start_encrypting();

        // 6.
        emit_finished(&secrets, &mut st.handshake, sess);

        if st.must_issue_new_ticket {
            Ok(Box::new(ExpectNewTicket {
                secrets,
                handshake: st.handshake,
                using_ems: st.using_ems,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        } else {
            Ok(st.into_expect_ccs(secrets, cert_verified, sig_verified))
        }
    }
}

// -- Waiting for their CCS --
pub struct ExpectCCS {
    pub secrets: SessionSecrets,
    pub handshake: HandshakeDetails,
    pub using_ems: bool,
    pub ticket: ReceivedTicketDetails,
    pub resuming: bool,
    pub cert_verified: verify::ServerCertVerified,
    pub sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectCCS {
    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            secrets: self.secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl hs::State for ExpectCCS {
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ChangeCipherSpec], &[])?;
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        hs::check_aligned_handshake(sess)?;

        // nb. msgs layer validates trivial contents of CCS
        sess.common
            .record_layer
            .start_decrypting();

        Ok(self.into_expect_finished())
    }
}

pub struct ExpectNewTicket {
    pub secrets: SessionSecrets,
    pub handshake: HandshakeDetails,
    pub using_ems: bool,
    pub resuming: bool,
    pub cert_verified: verify::ServerCertVerified,
    pub sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectNewTicket {
    fn into_expect_ccs(self, ticket: ReceivedTicketDetails) -> hs::NextState {
        Box::new(ExpectCCS {
            secrets: self.secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl hs::State for ExpectNewTicket {
    fn handle(
        mut self: Box<Self>,
        _sess: &mut ClientSessionImpl,
        m: Message,
    ) -> hs::NextStateOrError {
        self.handshake
            .transcript
            .add_message(&m);

        let nst = require_handshake_msg_mut!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;
        let recvd = ReceivedTicketDetails::from(nst.ticket.0, nst.lifetime_hint);
        Ok(self.into_expect_ccs(recvd))
    }
}

// -- Waiting for their finished --
fn save_session(
    secrets: &SessionSecrets,
    handshake: &mut HandshakeDetails,
    using_ems: bool,
    recvd_ticket: &mut ReceivedTicketDetails,
    sess: &mut ClientSessionImpl,
) {
    // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
    // original ticket again.
    let mut ticket = mem::replace(&mut recvd_ticket.new_ticket, Vec::new());

    if ticket.is_empty() {
        if let Some(resuming_session) = &mut handshake.resuming_session {
            ticket = resuming_session.take_ticket();
        }
    }

    if handshake.session_id.is_empty() && ticket.is_empty() {
        debug!("Session not saved: server didn't allocate id or ticket");
        return;
    }

    let key = persist::ClientSessionKey::session_for_dns_name(handshake.dns_name.as_ref());

    let master_secret = secrets.get_master_secret();
    let mut value = persist::ClientSessionValue::new(
        ProtocolVersion::TLSv1_2,
        secrets.suite(),
        &handshake.session_id,
        ticket,
        master_secret,
        &sess.server_cert_chain,
    );
    value.set_times(ticketer::timebase(), recvd_ticket.new_ticket_lifetime, 0);
    if using_ems {
        value.set_extended_ms_used();
    }

    let worked = sess
        .config
        .session_persistence
        .put(key.get_encoding(), value.get_encoding());

    if worked {
        debug!("Session saved");
    } else {
        debug!("Session not saved");
    }
}

struct ExpectFinished {
    handshake: HandshakeDetails,
    using_ems: bool,
    ticket: ReceivedTicketDetails,
    secrets: SessionSecrets,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    fn into_expect_traffic(self, fin: verify::FinishedMessageVerified) -> hs::NextState {
        Box::new(ExpectTraffic {
            secrets: self.secrets,
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        })
    }
}

impl hs::State for ExpectFinished {
    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        hs::check_aligned_handshake(sess)?;

        // Work out what verify_data we expect.
        let vh = st
            .handshake
            .transcript
            .get_current_hash();
        let expect_verify_data = st.secrets.server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                sess.common
                    .send_fatal_alert(AlertDescription::DecryptError);
                TlsError::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Hash this message too.
        st.handshake.transcript.add_message(&m);

        save_session(&st.secrets, &mut st.handshake, st.using_ems, &mut st.ticket, sess);

        if st.resuming {
            emit_ccs(sess);
            sess.common
                .record_layer
                .start_encrypting();
            emit_finished(&st.secrets, &mut st.handshake, sess);
        }

        sess.common.start_traffic();
        Ok(st.into_expect_traffic(fin))
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    secrets: SessionSecrets,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl hs::State for ExpectTraffic {
    fn handle(
        self: Box<Self>,
        sess: &mut ClientSessionImpl,
        mut m: Message,
    ) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ApplicationData], &[])?;
        sess.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        self.secrets
            .export_keying_material(output, label, context);
        Ok(())
    }
}
