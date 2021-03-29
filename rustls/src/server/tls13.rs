use crate::check::check_message;
use crate::conn::ConnectionRandoms;
use crate::error::Error;
use crate::key::Certificate;
use crate::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret, KeyScheduleTraffic,
    KeyScheduleTrafficWithClientFinishedPending,
};
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::enums::{AlertDescription, NamedGroup, SignatureScheme};
use crate::msgs::enums::{Compression, PSKKeyExchangeMode};
use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::handshake::CertReqExtension;
use crate::msgs::handshake::CertificateEntry;
use crate::msgs::handshake::CertificateExtension;
use crate::msgs::handshake::CertificatePayloadTLS13;
use crate::msgs::handshake::CertificateRequestPayloadTLS13;
use crate::msgs::handshake::CertificateStatus;
use crate::msgs::handshake::ClientHelloPayload;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::handshake::HandshakePayload;
use crate::msgs::handshake::HelloRetryExtension;
use crate::msgs::handshake::HelloRetryRequest;
use crate::msgs::handshake::KeyShareEntry;
use crate::msgs::handshake::NewSessionTicketPayloadTLS13;
use crate::msgs::handshake::Random;
use crate::msgs::handshake::ServerExtension;
use crate::msgs::handshake::ServerHelloPayload;
use crate::msgs::handshake::SessionID;
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::rand;
use crate::server::ServerConnection;
use crate::sign;
use crate::verify;
use crate::{cipher, SupportedCipherSuite};
#[cfg(feature = "quic")]
use crate::{conn::Protocol, msgs::handshake::NewSessionTicketExtension, quic};

use crate::server::common::{ClientCertDetails, HandshakeDetails};
use crate::server::hs;

use ring::constant_time;

pub struct CompleteClientHelloHandling {
    pub handshake: HandshakeDetails,
    pub suite: &'static SupportedCipherSuite,
    pub randoms: ConnectionRandoms,
    pub done_retry: bool,
    pub send_ticket: bool,
}

impl CompleteClientHelloHandling {
    fn check_binder(
        &self,
        suite: &'static SupportedCipherSuite,
        client_hello: &Message,
        psk: &[u8],
        binder: &[u8],
    ) -> bool {
        let binder_plaintext = match client_hello.payload {
            MessagePayload::Handshake(ref hmp) => hmp.get_encoding_for_binder_signing(),
            _ => unreachable!(),
        };

        let suite_hash = suite.get_hash();
        let handshake_hash = self
            .handshake
            .transcript
            .get_hash_given(suite_hash, &binder_plaintext);

        let key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, &psk);
        let real_binder =
            key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

        constant_time::verify_slices_are_equal(real_binder.as_ref(), binder).is_ok()
    }

    fn emit_certificate_req_tls13(&mut self, conn: &mut ServerConnection) -> Result<bool, Error> {
        if !conn.config.verifier.offer_client_auth() {
            return Ok(false);
        }

        let mut cr = CertificateRequestPayloadTLS13 {
            context: PayloadU8::empty(),
            extensions: Vec::new(),
        };

        let schemes = conn
            .config
            .get_verifier()
            .supported_verify_schemes();
        cr.extensions
            .push(CertReqExtension::SignatureAlgorithms(schemes.to_vec()));

        let names = conn
            .config
            .verifier
            .client_auth_root_subjects(conn.get_sni())
            .ok_or_else(|| {
                debug!("could not determine root subjects based on SNI");
                conn.common
                    .send_fatal_alert(AlertDescription::AccessDenied);
                Error::General("client rejected by client_auth_root_subjects".into())
            })?;

        if !names.is_empty() {
            cr.extensions
                .push(CertReqExtension::AuthorityNames(names));
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
        self.handshake
            .transcript
            .add_message(&m);
        conn.common.send_msg(m, true);
        Ok(true)
    }

    fn emit_certificate_tls13(
        &mut self,
        conn: &mut ServerConnection,
        cert_chain: &[Certificate],
        ocsp_response: Option<&[u8]>,
        sct_list: Option<&[u8]>,
    ) {
        let mut cert_entries = vec![];
        for cert in cert_chain {
            let entry = CertificateEntry {
                cert: cert.to_owned(),
                exts: Vec::new(),
            };

            cert_entries.push(entry);
        }

        if let Some(end_entity_cert) = cert_entries.first_mut() {
            // Apply OCSP response to first certificate (we don't support OCSP
            // except for leaf certs).
            if let Some(ocsp) = ocsp_response {
                let cst = CertificateStatus::new(ocsp.to_owned());
                end_entity_cert
                    .exts
                    .push(CertificateExtension::CertificateStatus(cst));
            }

            // Likewise, SCT
            if let Some(sct_list) = sct_list {
                end_entity_cert
                    .exts
                    .push(CertificateExtension::make_sct(sct_list.to_owned()));
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
        self.handshake
            .transcript
            .add_message(&c);
        conn.common.send_msg(c, true);
    }

    fn emit_certificate_verify_tls13(
        &mut self,
        conn: &mut ServerConnection,
        signing_key: &dyn sign::SigningKey,
        schemes: &[SignatureScheme],
    ) -> Result<(), Error> {
        let message = verify::construct_tls13_server_verify_message(
            &self
                .handshake
                .transcript
                .get_current_hash(),
        );

        let signer = signing_key
            .choose_scheme(schemes)
            .ok_or_else(|| hs::incompatible(conn, "no overlapping sigschemes"))?;

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
        self.handshake
            .transcript
            .add_message(&m);
        conn.common.send_msg(m, true);
        Ok(())
    }

    fn emit_finished_tls13(
        &mut self,
        conn: &mut ServerConnection,
        key_schedule: KeyScheduleHandshake,
    ) -> KeyScheduleTrafficWithClientFinishedPending {
        let handshake_hash = self
            .handshake
            .transcript
            .get_current_hash();
        let verify_data = key_schedule.sign_server_finish(&handshake_hash);
        let verify_data_payload = Payload::new(verify_data.as_ref());

        let m = Message {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(verify_data_payload),
            }),
        };

        trace!("sending finished {:?}", m);
        self.handshake
            .transcript
            .add_message(&m);
        let hash_at_server_fin = self
            .handshake
            .transcript
            .get_current_hash();
        self.handshake.hash_at_server_fin = Some(hash_at_server_fin);
        conn.common.send_msg(m, true);

        // Now move to application data keys.  Read key change is deferred until
        // the Finish message is received & validated.
        let mut key_schedule_traffic = key_schedule.into_traffic_with_client_finished_pending();
        let write_key = key_schedule_traffic.server_application_traffic_secret(
            &hash_at_server_fin,
            &*conn.config.key_log,
            &self.randoms.client,
        );
        conn.common
            .record_layer
            .set_message_encrypter(cipher::new_tls13_write(self.suite, &write_key));

        key_schedule_traffic.exporter_master_secret(
            &hash_at_server_fin,
            &*conn.config.key_log,
            &self.randoms.client,
        );

        let _read_key = key_schedule_traffic.client_application_traffic_secret(
            &hash_at_server_fin,
            &*conn.config.key_log,
            &self.randoms.client,
        );

        #[cfg(feature = "quic")]
        {
            conn.common.quic.traffic_secrets = Some(quic::Secrets {
                client: _read_key,
                server: write_key,
            });
        }

        key_schedule_traffic
    }

    fn attempt_tls13_ticket_decryption(
        &mut self,
        conn: &mut ServerConnection,
        ticket: &[u8],
    ) -> Option<persist::ServerSessionValue> {
        if conn.config.ticketer.enabled() {
            conn.config
                .ticketer
                .decrypt(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        } else {
            conn.config
                .session_storage
                .take(ticket)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain))
        }
    }

    pub fn handle_client_hello(
        mut self,
        suite: &'static SupportedCipherSuite,
        conn: &mut ServerConnection,
        server_key: &sign::CertifiedKey,
        chm: &Message,
    ) -> hs::NextStateOrError {
        let client_hello = require_handshake_msg!(
            chm,
            HandshakeType::ClientHello,
            HandshakePayload::ClientHello
        )?;

        if client_hello.compression_methods.len() != 1 {
            return Err(hs::illegal_param(conn, "client offered wrong compressions"));
        }

        let groups_ext = client_hello
            .get_namedgroups_extension()
            .ok_or_else(|| hs::incompatible(conn, "client didn't describe groups"))?;

        let mut sigschemes_ext = client_hello
            .get_sigalgs_extension()
            .ok_or_else(|| hs::incompatible(conn, "client didn't describe sigschemes"))?
            .clone();

        let tls13_schemes = sign::supported_sign_tls13();
        sigschemes_ext.retain(|scheme| tls13_schemes.contains(scheme));

        let shares_ext = client_hello
            .get_keyshare_extension()
            .ok_or_else(|| hs::incompatible(conn, "client didn't send keyshares"))?;

        if client_hello.has_keyshare_extension_with_duplicates() {
            return Err(hs::illegal_param(conn, "client sent duplicate keyshares"));
        }

        // choose a share that we support
        let chosen_share = conn
            .config
            .kx_groups
            .iter()
            .find_map(|group| {
                shares_ext
                    .iter()
                    .find(|share| share.group == group.name)
            });

        let chosen_share = match chosen_share {
            Some(s) => s,
            None => {
                // We don't have a suitable key share.  Choose a suitable group and
                // send a HelloRetryRequest.
                let retry_group_maybe = conn
                    .config
                    .kx_groups
                    .iter()
                    .find(|group| groups_ext.contains(&group.name))
                    .cloned();

                self.handshake
                    .transcript
                    .add_message(chm);

                if let Some(group) = retry_group_maybe {
                    if self.done_retry {
                        return Err(hs::illegal_param(conn, "did not follow retry request"));
                    }

                    emit_hello_retry_request(&mut self.handshake, suite, conn, group.name);
                    emit_fake_ccs(conn);
                    return Ok(Box::new(hs::ExpectClientHello {
                        handshake: self.handshake,
                        using_ems: false,
                        done_retry: true,
                        send_ticket: self.send_ticket,
                    }));
                }

                return Err(hs::incompatible(conn, "no kx group overlap with client"));
            }
        };

        let mut chosen_psk_index = None;
        let mut resumedata = None;
        if let Some(psk_offer) = client_hello.get_psk() {
            if !client_hello.check_psk_ext_is_last() {
                return Err(hs::illegal_param(conn, "psk extension in wrong position"));
            }

            if psk_offer.binders.is_empty() {
                return Err(hs::decode_error(conn, "psk extension missing binder"));
            }

            if psk_offer.binders.len() != psk_offer.identities.len() {
                return Err(hs::illegal_param(
                    conn,
                    "psk extension mismatched ids/binders",
                ));
            }

            for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                let resume = match self
                    .attempt_tls13_ticket_decryption(conn, &psk_id.identity.0)
                    .and_then(|resumedata| hs::can_resume(self.suite, &conn.sni, false, resumedata))
                {
                    Some(resume) => resume,
                    None => continue,
                };

                if !self.check_binder(suite, chm, &resume.master_secret.0, &psk_offer.binders[i].0)
                {
                    conn.common
                        .send_fatal_alert(AlertDescription::DecryptError);
                    return Err(Error::PeerMisbehavedError(
                        "client sent wrong binder".to_string(),
                    ));
                }

                chosen_psk_index = Some(i);
                resumedata = Some(resume);
                break;
            }
        }

        if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
            debug!("Client unwilling to resume, DHE_KE not offered");
            self.send_ticket = false;
            chosen_psk_index = None;
            resumedata = None;
        } else {
            self.send_ticket = true;
        }

        if let Some(ref resume) = resumedata {
            conn.received_resumption_data = Some(resume.application_data.0.clone());
            conn.client_cert_chain = resume.client_cert_chain.clone();
        }

        let full_handshake = resumedata.is_none();
        self.handshake
            .transcript
            .add_message(chm);
        let key_schedule = emit_server_hello(
            &mut self.handshake,
            &self.randoms,
            suite,
            conn,
            &client_hello.session_id,
            chosen_share,
            chosen_psk_index,
            resumedata
                .as_ref()
                .map(|x| &x.master_secret.0[..]),
        )?;
        if !self.done_retry {
            emit_fake_ccs(conn);
        }

        let (mut ocsp_response, mut sct_list) =
            (server_key.ocsp.as_deref(), server_key.sct_list.as_deref());
        emit_encrypted_extensions(
            &mut self.handshake,
            suite,
            conn,
            &mut ocsp_response,
            &mut sct_list,
            client_hello,
            resumedata.as_ref(),
        )?;

        let doing_client_auth = if full_handshake {
            let client_auth = self.emit_certificate_req_tls13(conn)?;
            self.emit_certificate_tls13(conn, &server_key.cert, ocsp_response, sct_list);
            self.emit_certificate_verify_tls13(conn, &*server_key.key, &sigschemes_ext)?;
            client_auth
        } else {
            false
        };

        hs::check_aligned_handshake(conn)?;
        let key_schedule_traffic = self.emit_finished_tls13(conn, key_schedule);

        if doing_client_auth {
            Ok(Box::new(ExpectCertificate {
                handshake: self.handshake,
                suite: self.suite,
                randoms: self.randoms,
                key_schedule: key_schedule_traffic,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(ExpectFinished {
                handshake: self.handshake,
                suite: self.suite,
                randoms: self.randoms,
                key_schedule: key_schedule_traffic,
                send_ticket: self.send_ticket,
            }))
        }
    }
}

fn emit_server_hello(
    handshake: &mut HandshakeDetails,
    randoms: &ConnectionRandoms,
    suite: &'static SupportedCipherSuite,
    sess: &mut ServerConnection,
    session_id: &SessionID,
    share: &KeyShareEntry,
    chosen_psk_idx: Option<usize>,
    resuming_psk: Option<&[u8]>,
) -> Result<KeyScheduleHandshake, Error> {
    let mut extensions = Vec::new();

    // Do key exchange
    let kxr = kx::KeyExchange::choose(share.group, &sess.config.kx_groups)
        .and_then(kx::KeyExchange::start)
        .and_then(|kx| kx.complete(&share.payload.0))
        .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string()))?;

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
                random: Random::from_slice(&randoms.server),
                session_id: *session_id,
                cipher_suite: suite.suite,
                compression_method: Compression::Null,
                extensions,
            }),
        }),
    };

    hs::check_aligned_handshake(sess)?;

    #[cfg(feature = "quic")]
    let client_hello_hash = handshake
        .transcript
        .get_hash_given(suite.get_hash(), &[]);

    trace!("sending server hello {:?}", sh);
    handshake.transcript.add_message(&sh);
    sess.common.send_msg(sh, false);

    // Start key schedule
    let mut key_schedule = if let Some(psk) = resuming_psk {
        let early_key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, psk);

        #[cfg(feature = "quic")]
        {
            if sess.common.protocol == Protocol::Quic {
                let client_early_traffic_secret = early_key_schedule.client_early_traffic_secret(
                    &client_hello_hash,
                    &*sess.config.key_log,
                    &randoms.client,
                );
                // If 0-RTT should be rejected, this will be clobbered by ExtensionProcessing
                // before the application can see.
                sess.common.quic.early_secret = Some(client_early_traffic_secret);
            }
        }

        early_key_schedule.into_handshake(&kxr.shared_secret)
    } else {
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&kxr.shared_secret)
    };

    let handshake_hash = handshake.transcript.get_current_hash();
    let write_key = key_schedule.server_handshake_traffic_secret(
        &handshake_hash,
        &*sess.config.key_log,
        &randoms.client,
    );
    sess.common
        .record_layer
        .set_message_encrypter(cipher::new_tls13_write(suite, &write_key));

    let read_key = key_schedule.client_handshake_traffic_secret(
        &handshake_hash,
        &*sess.config.key_log,
        &randoms.client,
    );
    sess.common
        .record_layer
        .set_message_decrypter(cipher::new_tls13_read(suite, &read_key));

    #[cfg(feature = "quic")]
    {
        sess.common.quic.hs_secrets = Some(quic::Secrets {
            client: read_key,
            server: write_key,
        });
    }

    Ok(key_schedule)
}

fn emit_fake_ccs(conn: &mut ServerConnection) {
    if conn.common.is_quic() {
        return;
    }
    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };
    conn.common.send_msg(m, false);
}

fn emit_hello_retry_request(
    handshake: &mut HandshakeDetails,
    suite: &'static SupportedCipherSuite,
    conn: &mut ServerConnection,
    group: NamedGroup,
) {
    let mut req = HelloRetryRequest {
        legacy_version: ProtocolVersion::TLSv1_2,
        session_id: SessionID::empty(),
        cipher_suite: suite.suite,
        extensions: Vec::new(),
    };

    req.extensions
        .push(HelloRetryExtension::KeyShare(group));
    req.extensions
        .push(HelloRetryExtension::SupportedVersions(
            ProtocolVersion::TLSv1_3,
        ));

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(req),
        }),
    };

    trace!("Requesting retry {:?}", m);
    handshake.transcript.rollup_for_hrr();
    handshake.transcript.add_message(&m);
    conn.common.send_msg(m, false);
}

fn emit_encrypted_extensions(
    handshake: &mut HandshakeDetails,
    suite: &'static SupportedCipherSuite,
    sess: &mut ServerConnection,
    ocsp_response: &mut Option<&[u8]>,
    sct_list: &mut Option<&[u8]>,
    hello: &ClientHelloPayload,
    resumedata: Option<&persist::ServerSessionValue>,
) -> Result<(), Error> {
    let mut ep = hs::ExtensionProcessing::new();
    ep.process_common(
        sess,
        suite,
        ocsp_response,
        sct_list,
        hello,
        resumedata,
        &handshake,
    )?;

    let ee = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(ep.exts),
        }),
    };

    trace!("sending encrypted extensions {:?}", ee);
    handshake.transcript.add_message(&ee);
    sess.common.send_msg(ee, true);
    Ok(())
}

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub suite: &'static SupportedCipherSuite,
    pub randoms: ConnectionRandoms,
    pub key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub send_ticket: bool,
}

impl hs::State for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let certp = require_handshake_msg!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTLS13
        )?;
        self.handshake
            .transcript
            .add_message(&m);

        // We don't send any CertificateRequest extensions, so any extensions
        // here are illegal.
        if certp.any_entry_has_extension() {
            return Err(Error::PeerMisbehavedError(
                "client sent unsolicited cert extension".to_string(),
            ));
        }

        let cert_chain = certp.convert();

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

        let (end_entity, intermediates) = match cert_chain.split_first() {
            None => {
                if !mandatory {
                    debug!("client auth requested but no certificate supplied");
                    self.handshake
                        .transcript
                        .abandon_client_auth();
                    return Ok(Box::new(ExpectFinished {
                        suite: self.suite,
                        key_schedule: self.key_schedule,
                        randoms: self.randoms,
                        handshake: self.handshake,
                        send_ticket: self.send_ticket,
                    }));
                }

                conn.common
                    .send_fatal_alert(AlertDescription::CertificateRequired);
                return Err(Error::NoCertificatesPresented);
            }
            Some(chain) => chain,
        };

        let now = std::time::SystemTime::now();
        conn.config
            .get_verifier()
            .verify_client_cert(end_entity, intermediates, conn.get_sni(), now)
            .map_err(|err| {
                hs::incompatible(conn, "certificate invalid");
                err
            })?;

        let client_cert = ClientCertDetails::new(cert_chain);
        Ok(Box::new(ExpectCertificateVerify {
            suite: self.suite,
            handshake: self.handshake,
            randoms: self.randoms,
            key_schedule: self.key_schedule,
            client_cert,
            send_ticket: self.send_ticket,
        }))
    }
}

pub struct ExpectCertificateVerify {
    handshake: HandshakeDetails,
    suite: &'static SupportedCipherSuite,
    randoms: ConnectionRandoms,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
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
            let handshake_hash = self
                .handshake
                .transcript
                .get_current_hash();
            self.handshake
                .transcript
                .abandon_client_auth();
            let certs = &self.client_cert.cert_chain;
            let msg = verify::construct_tls13_client_verify_message(&handshake_hash);

            conn.config
                .get_verifier()
                .verify_tls13_signature(&msg, &certs[0], sig)
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
        Ok(Box::new(ExpectFinished {
            suite: self.suite,
            key_schedule: self.key_schedule,
            handshake: self.handshake,
            randoms: self.randoms,
            send_ticket: self.send_ticket,
        }))
    }
}

// --- Process client's Finished ---
fn get_server_session_value(
    handshake: &mut HandshakeDetails,
    suite: &'static SupportedCipherSuite,
    key_schedule: &KeyScheduleTraffic,
    conn: &ServerConnection,
    nonce: &[u8],
) -> persist::ServerSessionValue {
    let version = ProtocolVersion::TLSv1_3;

    let handshake_hash = handshake.transcript.get_current_hash();
    let secret =
        key_schedule.resumption_master_secret_and_derive_ticket_psk(&handshake_hash, nonce);

    persist::ServerSessionValue::new(
        conn.get_sni(),
        version,
        suite.suite,
        secret,
        &conn.client_cert_chain,
        conn.common.alpn_protocol.clone(),
        conn.resumption_data.clone(),
    )
}

pub struct ExpectFinished {
    pub handshake: HandshakeDetails,
    pub suite: &'static SupportedCipherSuite,
    pub randoms: ConnectionRandoms,
    pub key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub send_ticket: bool,
}

impl ExpectFinished {
    fn emit_ticket(
        handshake: &mut HandshakeDetails,
        suite: &'static SupportedCipherSuite,
        conn: &mut ServerConnection,
        key_schedule: &KeyScheduleTraffic,
    ) -> Result<(), rand::GetRandomFailed> {
        let nonce = rand::random_vec(32)?;
        let plain =
            get_server_session_value(handshake, suite, key_schedule, conn, &nonce).get_encoding();

        let stateless = conn.config.ticketer.enabled();
        let (ticket, lifetime) = if stateless {
            let ticket = match conn.config.ticketer.encrypt(&plain) {
                Some(t) => t,
                None => return Ok(()),
            };
            (ticket, conn.config.ticketer.lifetime())
        } else {
            let id = rand::random_vec(32)?;
            let stored = conn
                .config
                .session_storage
                .put(id.clone(), plain);
            if !stored {
                trace!("resumption not available; not issuing ticket");
                return Ok(());
            }
            let stateful_lifetime = 24 * 60 * 60; // this is a bit of a punt
            (id, stateful_lifetime)
        };

        let age_add = rand::random_u32()?; // nb, we don't do 0-RTT data, so whatever
        #[allow(unused_mut)]
        let mut payload = NewSessionTicketPayloadTLS13::new(lifetime, age_add, nonce, ticket);
        #[cfg(feature = "quic")]
        {
            if conn.config.max_early_data_size > 0 && conn.common.protocol == Protocol::Quic {
                payload
                    .exts
                    .push(NewSessionTicketExtension::EarlyData(
                        conn.config.max_early_data_size,
                    ));
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

        trace!("sending new ticket {:?} (stateless: {})", m, stateless);
        handshake.transcript.add_message(&m);
        conn.common.send_msg(m, true);
        Ok(())
    }
}

impl hs::State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = self
            .handshake
            .transcript
            .get_current_hash();
        let expect_verify_data = self
            .key_schedule
            .sign_client_finish(&handshake_hash);

        let fin = constant_time::verify_slices_are_equal(expect_verify_data.as_ref(), &finished.0)
            .map_err(|_| {
                conn.common
                    .send_fatal_alert(AlertDescription::DecryptError);
                warn!("Finished wrong");
                Error::DecryptError
            })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // nb. future derivations include Client Finished, but not the
        // main application data keying.
        self.handshake
            .transcript
            .add_message(&m);

        hs::check_aligned_handshake(conn)?;

        // Install keying to read future messages.
        let read_key = self
            .key_schedule
            .client_application_traffic_secret(
                self.handshake
                    .hash_at_server_fin
                    .as_ref()
                    .unwrap(),
                &*conn.config.key_log,
                &self.randoms.client,
            );
        conn.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(self.suite, &read_key));

        let key_schedule_traffic = self.key_schedule.into_traffic();

        if self.send_ticket {
            Self::emit_ticket(&mut self.handshake, self.suite, conn, &key_schedule_traffic)?;
        }

        conn.common.start_traffic();

        #[cfg(feature = "quic")]
        {
            if conn.common.protocol == Protocol::Quic {
                return Ok(Box::new(ExpectQUICTraffic {
                    key_schedule: key_schedule_traffic,
                    _fin_verified: fin,
                }));
            }
        }

        Ok(Box::new(ExpectTraffic {
            suite: self.suite,
            key_schedule: key_schedule_traffic,
            want_write_key_update: false,
            _fin_verified: fin,
        }))
    }
}

// --- Process traffic ---
pub struct ExpectTraffic {
    suite: &'static SupportedCipherSuite,
    key_schedule: KeyScheduleTraffic,
    want_write_key_update: bool,
    _fin_verified: verify::FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_traffic(&self, conn: &mut ServerConnection, mut m: Message) {
        conn.common
            .take_received_plaintext(m.take_opaque_payload().unwrap());
    }

    fn handle_key_update(
        &mut self,
        conn: &mut ServerConnection,
        kur: &KeyUpdateRequest,
    ) -> Result<(), Error> {
        #[cfg(feature = "quic")]
        {
            if let Protocol::Quic = conn.common.protocol {
                conn.common
                    .send_fatal_alert(AlertDescription::UnexpectedMessage);
                let msg = "KeyUpdate received in QUIC connection".to_string();
                warn!("{}", msg);
                return Err(Error::PeerMisbehavedError(msg));
            }
        }

        hs::check_aligned_handshake(conn)?;

        match kur {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                self.want_write_key_update = true;
            }
            _ => {
                conn.common
                    .send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(Error::CorruptMessagePayload(ContentType::Handshake));
            }
        }

        // Update our read-side keys.
        let new_read_key = self
            .key_schedule
            .next_client_application_traffic_secret();
        conn.common
            .record_layer
            .set_message_decrypter(cipher::new_tls13_read(self.suite, &new_read_key));

        Ok(())
    }
}

impl hs::State for ExpectTraffic {
    fn handle(
        mut self: Box<Self>,
        conn: &mut ServerConnection,
        m: Message,
    ) -> hs::NextStateOrError {
        if m.is_content_type(ContentType::ApplicationData) {
            self.handle_traffic(conn, m);
        } else if let Ok(key_update) =
            require_handshake_msg!(m, HandshakeType::KeyUpdate, HandshakePayload::KeyUpdate)
        {
            self.handle_key_update(conn, key_update)?;
        } else {
            check_message(
                &m,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::KeyUpdate],
            )?;
        }

        Ok(self)
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

    fn perhaps_write_key_update(&mut self, conn: &mut ServerConnection) {
        if self.want_write_key_update {
            self.want_write_key_update = false;
            conn.common
                .send_msg_encrypt(Message::build_key_update_notify());

            let write_key = self
                .key_schedule
                .next_server_application_traffic_secret();
            conn.common
                .record_layer
                .set_message_encrypter(cipher::new_tls13_write(self.suite, &write_key));
        }
    }
}

#[cfg(feature = "quic")]
pub struct ExpectQUICTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: verify::FinishedMessageVerified,
}

#[cfg(feature = "quic")]
impl hs::State for ExpectQUICTraffic {
    fn handle(self: Box<Self>, _: &mut ServerConnection, m: Message) -> hs::NextStateOrError {
        // reject all messages
        check_message(&m, &[], &[])?;
        unreachable!();
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
}
