use crate::check::check_message;
use crate::conn::{ConnectionRandoms, ConnectionSecrets};
use crate::error::Error;
use crate::key::Certificate;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertDescription, ClientCertificateType, SignatureScheme};
use crate::msgs::enums::{Compression, ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::{CertificateRequestPayload, NewSessionTicketPayload, Random};
use crate::msgs::handshake::{CertificateStatus, DigitallySignedStruct, ECDHEServerKeyExchange};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, ServerHelloPayload};
use crate::msgs::handshake::{HandshakePayload, ServerECDHParams, ServerKeyExchangePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::server::ServerConnection;
use crate::sign;
use crate::verify;
use crate::SupportedCipherSuite;

use crate::server::common::{ClientCertDetails, HandshakeDetails, ServerKxDetails};
use crate::server::hs;

use ring::constant_time;

pub(super) fn emit_server_hello(
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
    suite: &'static SupportedCipherSuite,
    using_ems: bool,
    ocsp_response: &mut Option<&[u8]>,
    sct_list: &mut Option<&[u8]>,
    hello: &ClientHelloPayload,
    resumedata: Option<&persist::ServerSessionValue>,
    randoms: &ConnectionRandoms,
) -> Result<bool, Error> {
    let mut ep = hs::ExtensionProcessing::new();
    ep.process_common(
        conn,
        suite,
        ocsp_response,
        sct_list,
        hello,
        resumedata,
        &handshake,
    )?;
    ep.process_tls12(conn, hello, using_ems);

    let sh = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                legacy_version: ProtocolVersion::TLSv1_2,
                random: Random::from_slice(&randoms.server),
                session_id: handshake.session_id,
                cipher_suite: suite.suite,
                compression_method: Compression::Null,
                extensions: ep.exts,
            }),
        }),
    };

    trace!("sending server hello {:?}", sh);
    handshake.transcript.add_message(&sh);
    conn.common.send_msg(sh, false);
    Ok(ep.send_ticket)
}

pub(super) fn emit_certificate(
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
    cert_chain: &[Certificate],
) {
    let c = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain.to_owned()),
        }),
    };

    handshake.transcript.add_message(&c);
    conn.common.send_msg(c, false);
}

pub(super) fn emit_cert_status(
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
    ocsp: &[u8],
) {
    let st = CertificateStatus::new(ocsp.to_owned());

    let c = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(st),
        }),
    };

    handshake.transcript.add_message(&c);
    conn.common.send_msg(c, false);
}

pub(super) fn emit_server_kx(
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
    sigschemes: Vec<SignatureScheme>,
    skxg: &'static kx::SupportedKxGroup,
    signing_key: &dyn sign::SigningKey,
    randoms: &ConnectionRandoms,
) -> Result<kx::KeyExchange, Error> {
    let kx = kx::KeyExchange::start(skxg)
        .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string()))?;
    let secdh = ServerECDHParams::new(skxg.name, kx.pubkey.as_ref());

    let mut msg = Vec::new();
    msg.extend(&randoms.client);
    msg.extend(&randoms.server);
    secdh.encode(&mut msg);

    let signer = signing_key
        .choose_scheme(&sigschemes)
        .ok_or_else(|| Error::General("incompatible signing key".to_string()))?;
    let sigscheme = signer.get_scheme();
    let sig = signer.sign(&msg)?;

    let skx = ServerKeyExchangePayload::ECDHE(ECDHEServerKeyExchange {
        params: secdh,
        dss: DigitallySignedStruct::new(sigscheme, sig),
    });

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(skx),
        }),
    };

    handshake.transcript.add_message(&m);
    conn.common.send_msg(m, false);
    Ok(kx)
}

pub(super) fn emit_certificate_req(
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
) -> Result<bool, Error> {
    let client_auth = conn.config.get_verifier();

    if !client_auth.offer_client_auth() {
        return Ok(false);
    }

    let verify_schemes = client_auth.supported_verify_schemes();

    let names = client_auth
        .client_auth_root_subjects(conn.get_sni())
        .ok_or_else(|| {
            debug!("could not determine root subjects based on SNI");
            conn.common
                .send_fatal_alert(AlertDescription::AccessDenied);
            Error::General("client rejected by client_auth_root_subjects".into())
        })?;

    let cr = CertificateRequestPayload {
        certtypes: vec![
            ClientCertificateType::RSASign,
            ClientCertificateType::ECDSASign,
        ],
        sigschemes: verify_schemes,
        canames: names,
    };

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequest(cr),
        }),
    };

    trace!("Sending CertificateRequest {:?}", m);
    handshake.transcript.add_message(&m);
    conn.common.send_msg(m, false);
    Ok(true)
}

// --- Process client's Certificate for client auth ---
pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub randoms: ConnectionRandoms,
    pub suite: &'static SupportedCipherSuite,
    pub using_ems: bool,
    pub server_kx: ServerKxDetails,
    pub send_ticket: bool,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        self.handshake
            .transcript
            .add_message(&m);
        let cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        // If we can't determine if the auth is mandatory, abort
        let mandatory = conn
            .config
            .verifier
            .client_auth_mandatory(conn.get_sni())
            .ok_or_else(|| {
                debug!("could not determine if client auth is mandatory based on SNI");
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_mandatory".into())
            })?;

        trace!("certs {:?}", cert_chain);

        let client_cert = match cert_chain.split_first() {
            None if mandatory => {
                conn.common
                    .send_fatal_alert(AlertDescription::CertificateRequired);
                return Err(Error::NoCertificatesPresented);
            }
            None => {
                debug!("client auth requested but no certificate supplied");
                self.handshake
                    .transcript
                    .abandon_client_auth();
                None
            }
            Some((end_entity, intermediates)) => {
                let now = std::time::SystemTime::now();
                conn.config
                    .verifier
                    .verify_client_cert(end_entity, intermediates, conn.get_sni(), now)
                    .map_err(|err| {
                        hs::incompatible(conn, "certificate invalid");
                        err
                    })?;

                Some(ClientCertDetails::new(cert_chain))
            }
        };

        Ok(Box::new(ExpectClientKx {
            handshake: self.handshake,
            randoms: self.randoms,
            suite: self.suite,
            using_ems: self.using_ems,
            server_kx: self.server_kx,
            client_cert,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's KeyExchange ---
pub struct ExpectClientKx {
    pub handshake: HandshakeDetails,
    pub randoms: ConnectionRandoms,
    pub suite: &'static SupportedCipherSuite,
    pub using_ems: bool,
    pub server_kx: ServerKxDetails,
    pub client_cert: Option<ClientCertDetails>,
    pub send_ticket: bool,
}

impl hs::State for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let client_kx = require_handshake_msg!(
            m,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        self.handshake
            .transcript
            .add_message(&m);

        // Complete key agreement, and set up encryption with the
        // resulting premaster secret.
        let kxd = self
            .server_kx
            .kx
            .server_complete(&client_kx.0)
            .ok_or_else(|| {
                conn.common
                    .send_fatal_alert(AlertDescription::DecodeError);
                Error::CorruptMessagePayload(ContentType::Handshake)
            })?;

        let secrets = if self.using_ems {
            let handshake_hash = self
                .handshake
                .transcript
                .get_current_hash();
            ConnectionSecrets::new_ems(
                &self.randoms,
                &handshake_hash,
                self.suite,
                &kxd.shared_secret,
            )
        } else {
            ConnectionSecrets::new(&self.randoms, self.suite, &kxd.shared_secret)
        };
        conn.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        conn.common
            .start_encryption_tls12(&secrets);

        if let Some(client_cert) = self.client_cert {
            Ok(Box::new(ExpectCertificateVerify {
                secrets,
                handshake: self.handshake,
                using_ems: self.using_ems,
                client_cert,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                secrets,
                handshake: self.handshake,
                using_ems: self.using_ems,
                resuming: false,
                send_ticket: self.send_ticket,
            }))
        }
    }
}

// --- Process client's certificate proof ---
pub struct ExpectCertificateVerify {
    secrets: ConnectionSecrets,
    handshake: HandshakeDetails,
    using_ems: bool,
    client_cert: ClientCertDetails,
    send_ticket: bool,
}

impl hs::State for ExpectCertificateVerify {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let rc = {
            let sig = require_handshake_msg!(
                m,
                HandshakeType::CertificateVerify,
                HandshakePayload::CertificateVerify
            )?;
            let handshake_msgs = self
                .handshake
                .transcript
                .take_handshake_buf();
            let certs = &self.client_cert.cert_chain;

            conn.config
                .get_verifier()
                .verify_tls12_signature(&handshake_msgs, &certs[0], sig)
        };

        if let Err(e) = rc {
            conn.common
                .send_fatal_alert(AlertDescription::AccessDenied);
            return Err(e);
        }

        trace!("client CertificateVerify OK");
        conn.client_cert_chain = Some(self.client_cert.take_chain());

        self.handshake
            .transcript
            .add_message(&m);
        Ok(Box::new(ExpectCcs {
            secrets: self.secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            resuming: false,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's ChangeCipherSpec ---
pub struct ExpectCcs {
    pub secrets: ConnectionSecrets,
    pub handshake: HandshakeDetails,
    pub using_ems: bool,
    pub resuming: bool,
    pub send_ticket: bool,
}

impl hs::State for ExpectCcs {
    fn handle(self: Box<Self>, conn: &mut ServerConnection, m: Message) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ChangeCipherSpec], &[])?;

        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        hs::check_aligned_handshake(conn)?;

        conn.common
            .record_layer
            .start_decrypting();
        Ok(Box::new(ExpectFinished {
            secrets: self.secrets,
            handshake: self.handshake,
            using_ems: self.using_ems,
            resuming: self.resuming,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_session_value_tls12(
    secrets: &ConnectionSecrets,
    using_ems: bool,
    conn: &ServerConnection,
) -> persist::ServerSessionValue {
    let version = ProtocolVersion::TLSv1_2;
    let secret = secrets.get_master_secret();

    let mut v = persist::ServerSessionValue::new(
        conn.get_sni(),
        version,
        secrets.suite().suite,
        secret,
        &conn.client_cert_chain,
        conn.common.alpn_protocol.clone(),
        conn.resumption_data.clone(),
    );

    if using_ems {
        v.set_extended_ms_used();
    }

    v
}

pub fn emit_ticket(
    secrets: &ConnectionSecrets,
    handshake: &mut HandshakeDetails,
    using_ems: bool,
    conn: &mut ServerConnection,
) {
    // If we can't produce a ticket for some reason, we can't
    // report an error. Send an empty one.
    let plain = get_server_session_value_tls12(secrets, using_ems, conn).get_encoding();
    let ticket = conn
        .config
        .ticketer
        .encrypt(&plain)
        .unwrap_or_else(Vec::new);
    let ticket_lifetime = conn.config.ticketer.lifetime();

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(
                ticket_lifetime,
                ticket,
            )),
        }),
    };

    handshake.transcript.add_message(&m);
    conn.common.send_msg(m, false);
}

pub fn emit_ccs(conn: &mut ServerConnection) {
    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    conn.common.send_msg(m, false);
}

pub fn emit_finished(
    secrets: &ConnectionSecrets,
    handshake: &mut HandshakeDetails,
    conn: &mut ServerConnection,
) {
    let vh = handshake.transcript.get_current_hash();
    let verify_data = secrets.server_verify_data(&vh);
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
    conn.common.send_msg(f, true);
}

pub struct ExpectFinished {
    secrets: ConnectionSecrets,
    handshake: HandshakeDetails,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl hs::State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        hs::check_aligned_handshake(conn)?;

        let vh = self
            .handshake
            .transcript
            .get_current_hash();
        let expect_verify_data = self.secrets.client_verify_data(&vh);

        let _fin_verified =
            constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
                .map_err(|_| {
                    conn.common
                        .send_fatal_alert(AlertDescription::DecryptError);
                    Error::DecryptError
                })
                .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Save session, perhaps
        if !self.resuming && !self.handshake.session_id.is_empty() {
            let value = get_server_session_value_tls12(&self.secrets, self.using_ems, conn);

            let worked = conn.config.session_storage.put(
                self.handshake.session_id.get_encoding(),
                value.get_encoding(),
            );
            if worked {
                debug!("Session saved");
            } else {
                debug!("Session not saved");
            }
        }

        // Send our CCS and Finished.
        self.handshake
            .transcript
            .add_message(&m);
        if !self.resuming {
            if self.send_ticket {
                emit_ticket(&self.secrets, &mut self.handshake, self.using_ems, conn);
            }
            emit_ccs(conn);
            conn.common
                .record_layer
                .start_encrypting();
            emit_finished(&self.secrets, &mut self.handshake, conn);
        }

        conn.common.start_traffic();
        Ok(Box::new(ExpectTraffic {
            secrets: self.secrets,
            _fin_verified,
        }))
    }
}

// --- Process traffic ---
pub struct ExpectTraffic {
    secrets: ConnectionSecrets,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {}

impl hs::State for ExpectTraffic {
    fn handle(
        self: Box<Self>,
        conn: &mut ServerConnection,
        mut m: Message,
    ) -> hs::NextStateOrError {
        check_message(&m, &[ContentType::ApplicationData], &[])?;
        conn.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.secrets
            .export_keying_material(output, label, context);
        Ok(())
    }
}
