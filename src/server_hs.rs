use msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use msgs::enums::{Compression, NamedGroup, ECPointFormat, CipherSuite};
use msgs::enums::{ExtensionType, AlertDescription};
use msgs::enums::{ClientCertificateType, SignatureScheme, PSKKeyExchangeMode};
use msgs::message::{Message, MessagePayload};
use msgs::base::{Payload, PayloadU8};
use msgs::handshake::{HandshakePayload, SupportedSignatureSchemes};
use msgs::handshake::{HandshakeMessagePayload, ServerHelloPayload, Random};
use msgs::handshake::{ClientHelloPayload, ServerExtension, SessionID};
use msgs::handshake::{ConvertProtocolNameList, ConvertServerNameList};
use msgs::handshake::{NamedGroups, SupportedGroups, ClientExtension};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ServerECDHParams, DigitallySignedStruct};
use msgs::handshake::{ServerKeyExchangePayload, ECDHEServerKeyExchange};
use msgs::handshake::{CertificateRequestPayload, NewSessionTicketPayload};
use msgs::handshake::{CertificateRequestPayloadTLS13, NewSessionTicketPayloadTLS13};
use msgs::handshake::{HelloRetryRequest, HelloRetryExtension, KeyShareEntry};
use msgs::handshake::{CertificatePayloadTLS13, CertificateEntry};
use msgs::handshake::SupportedMandatedSignatureSchemes;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::codec::Codec;
use msgs::persist;
use session::SessionSecrets;
use cipher;
use server::ServerSessionImpl;
use key_schedule::{KeySchedule, SecretKind};
use suites;
use hash_hs;
use sign;
use verify;
use util;
use rand;
use error::TLSError;
use handshake::Expectation;

use std::sync::Arc;

use ring::constant_time;

macro_rules! extract_handshake(
  ( $m:expr, $t:path ) => (
    match $m.payload {
      MessagePayload::Handshake(ref hsp) => match hsp.payload {
        $t(ref hm) => Some(hm),
        _ => None
      },
      _ => None
    }
  )
);

// These are effectively operations on the ServerSessionImpl, variant on the
// connection state. They must not have state of their own -- so they're
// functions rather than a trait.
pub type HandleFunction = fn(&mut ServerSessionImpl, m: Message) -> StateResult;
type StateResult = Result<&'static State, TLSError>;

pub struct State {
    pub expect: Expectation,
    pub handle: HandleFunction,
}

fn process_extensions(sess: &mut ServerSessionImpl,
                      hello: &ClientHelloPayload)
                      -> Result<Vec<ServerExtension>, TLSError> {
    let mut ret = Vec::new();

    // ALPN
    let our_protocols = &sess.config.alpn_protocols;
    let maybe_their_protocols = hello.get_alpn_extension();
    if let Some(their_protocols) = maybe_their_protocols {
        let their_proto_strings = their_protocols.to_strings();

        if their_proto_strings.contains(&"".to_string()) {
            return Err(TLSError::PeerMisbehavedError("client offered empty ALPN protocol"
                .to_string()));
        }

        sess.alpn_protocol = util::first_in_both(our_protocols, &their_proto_strings);
        if let Some(ref selected_protocol) = sess.alpn_protocol {
            info!("Chosen ALPN protocol {:?}", selected_protocol);
            ret.push(ServerExtension::make_alpn(selected_protocol.clone()));
        }
    }

    // SNI
    if hello.get_sni_extension().is_some() {
        ret.push(ServerExtension::ServerNameAck);
    }

    if !sess.common.is_tls13() {
        // Renegotiation.
        // (We don't do reneg at all, but would support the secure version if we did.)
        let secure_reneg_offered =
            hello.find_extension(ExtensionType::RenegotiationInfo).is_some() ||
            hello.cipher_suites.contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            ret.push(ServerExtension::make_empty_renegotiation_info());
        }

        // Tickets:
        // If we get any SessionTicket extension and have tickets enabled,
        // we send an ack.
        if hello.find_extension(ExtensionType::SessionTicket).is_some() &&
           sess.config.ticketer.enabled() {
            sess.handshake_data.send_ticket = true;
            ret.push(ServerExtension::SessionTicketAck);
        }

        // Confirm use of EMS if offered.
        if sess.handshake_data.using_ems {
            ret.push(ServerExtension::ExtendedMasterSecretAck);
        }
    }

    Ok(ret)
}

fn emit_server_hello(sess: &mut ServerSessionImpl,
                     hello: &ClientHelloPayload)
                     -> Result<(), TLSError> {
    let extensions = process_extensions(sess, hello)?;

    if sess.handshake_data.session_id.is_empty() {
        let sessid = sess.config
            .session_storage
            .generate();
        sess.handshake_data.session_id = sessid;
    }

    let sh = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                server_version: ProtocolVersion::TLSv1_2,
                random: Random::from_slice(&sess.handshake_data.randoms.server),
                session_id: sess.handshake_data.session_id,
                cipher_suite: sess.common.get_suite().suite,
                compression_method: Compression::Null,
                extensions: extensions,
            }),
        }),
    };

    debug!("sending server hello {:?}", sh);
    sess.handshake_data.transcript.add_message(&sh);
    sess.common.send_msg(sh, false);
    Ok(())
}

fn emit_certificate(sess: &mut ServerSessionImpl) {
    let cert_chain = sess.handshake_data.server_cert_chain.as_ref().unwrap().clone();

    let c = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(cert_chain),
        }),
    };

    sess.handshake_data.transcript.add_message(&c);
    sess.common.send_msg(c, false);
}

fn emit_server_kx(sess: &mut ServerSessionImpl,
                  sigscheme: SignatureScheme,
                  group: &NamedGroup,
                  signer: Arc<Box<sign::Signer>>)
                  -> Result<(), TLSError> {
    let kx = sess.common.get_suite()
        .start_server_kx(*group)
        .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;
    let secdh = ServerECDHParams::new(group, &kx.pubkey);

    let mut msg = Vec::new();
    msg.extend(&sess.handshake_data.randoms.client);
    msg.extend(&sess.handshake_data.randoms.server);
    secdh.encode(&mut msg);

    let sig = signer.sign(sigscheme, &msg)
        .map_err(|_| TLSError::General("signing failed".to_string()))?;

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

    sess.handshake_data.kx_data = Some(kx);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(())
}

fn emit_certificate_req(sess: &mut ServerSessionImpl) {
    if !sess.config.client_auth_offer {
        return;
    }

    let names = sess.config.client_auth_roots.get_subjects();

    let cr = CertificateRequestPayload {
        certtypes: vec![ ClientCertificateType::RSASign,
                     ClientCertificateType::ECDSASign ],
        sigschemes: SupportedSignatureSchemes::supported_verify(),
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

    debug!("Sending CertificateRequest {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    sess.handshake_data.doing_client_auth = true;
}

fn emit_server_hello_done(sess: &mut ServerSessionImpl) {
    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        }),
    };

    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
}

fn incompatible(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    TLSError::PeerIncompatibleError(why.to_string())
}

fn illegal_param(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    TLSError::PeerMisbehavedError(why.to_string())
}

fn decode_error(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
    sess.common.send_fatal_alert(AlertDescription::DecodeError);
    TLSError::PeerMisbehavedError(why.to_string())
}

fn can_resume(sess: &ServerSessionImpl,
              resumedata: &Option<persist::ServerSessionValue>) -> bool {
    // The RFCs underspecify what happens if we try to resume to
    // an unoffered/varying suite.  We merely don't resume in weird cases.
    if let Some(ref resume) = *resumedata {
        resume.cipher_suite == sess.common.get_suite().suite &&
            (resume.extended_ms == sess.handshake_data.using_ems ||
             (resume.extended_ms && !sess.handshake_data.using_ems))
    } else {
        false
    }
}

fn start_resumption(sess: &mut ServerSessionImpl,
                    client_hello: &ClientHelloPayload,
                    id: &SessionID,
                    resumedata: persist::ServerSessionValue)
                    -> StateResult {
    info!("Resuming session");

    if resumedata.extended_ms && !sess.handshake_data.using_ems {
        return Err(illegal_param(sess, "refusing to resume without ems"));
    }

    sess.handshake_data.session_id = *id;
    emit_server_hello(sess, client_hello)?;

    let hashalg = sess.common.get_suite().get_hash();
    sess.secrets = Some(SessionSecrets::new_resume(&sess.handshake_data.randoms,
                                                   hashalg,
                                                   &resumedata.master_secret.0));
    sess.start_encryption_tls12();
    sess.handshake_data.valid_client_cert_chain = resumedata.client_cert_chain;
    sess.handshake_data.doing_resume = true;

    emit_ticket(sess);
    emit_ccs(sess);
    emit_finished(sess);
    Ok(&EXPECT_TLS12_CCS)
}

// Changing the keys must not span any fragmented handshake
// messages.  Otherwise the defragmented messages will have
// been protected with two different record layer protections,
// which is illegal.  Not mentioned in RFC.
fn check_aligned_handshake(sess: &mut ServerSessionImpl) -> Result<(), TLSError> {
    if !sess.common.handshake_joiner.is_empty() {
        Err(illegal_param(sess, "keys changed with pending hs fragment"))
    } else {
        Ok(())
    }
}

fn emit_server_hello_tls13(sess: &mut ServerSessionImpl,
                           share: &KeyShareEntry,
                           chosen_psk_idx: Option<usize>,
                           resuming_psk: Option<Vec<u8>>)
                           -> Result<(), TLSError> {
    let mut extensions = Vec::new();

    // Do key exchange
    let kxr = suites::KeyExchange::start_ecdhe(share.group)
        .and_then(|kx| kx.complete(&share.payload.0))
        .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;

    let kse = KeyShareEntry::new(share.group, &kxr.pubkey);
    extensions.push(ServerExtension::KeyShare(kse));

    if let Some(psk_idx) = chosen_psk_idx {
        extensions.push(ServerExtension::PresharedKey(psk_idx as u16));
    }

    let sh = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_0,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                server_version: ProtocolVersion::Unknown(0x7f12),
                random: Random::from_slice(&sess.handshake_data.randoms.server),
                session_id: SessionID::empty(),
                cipher_suite: sess.common.get_suite().suite,
                compression_method: Compression::Null,
                extensions: extensions,
            }),
        }),
    };

    check_aligned_handshake(sess)?;

    debug!("sending server hello {:?}", sh);
    sess.handshake_data.transcript.add_message(&sh);
    sess.common.send_msg(sh, false);

    // Start key schedule
    let suite = sess.common.get_suite();
    let mut key_schedule = KeySchedule::new(suite.get_hash());
    if let Some(psk) = resuming_psk {
        key_schedule.input_secret(&psk);
    } else {
        key_schedule.input_empty();
    }
    key_schedule.input_secret(&kxr.premaster_secret);

    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let write_key = key_schedule.derive(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);
    let read_key = key_schedule.derive(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
    sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
    sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
    key_schedule.current_client_traffic_secret = read_key;
    key_schedule.current_server_traffic_secret = write_key;
    sess.common.set_key_schedule(key_schedule);

    Ok(())
}

fn emit_hello_retry_request(sess: &mut ServerSessionImpl, group: NamedGroup) {
    let mut req = HelloRetryRequest {
        server_version: ProtocolVersion::Unknown(0x7f12),
        extensions: Vec::new(),
    };

    req.extensions.push(HelloRetryExtension::KeyShare(group));

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_0,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(req),
        }),
    };

    debug!("Requesting retry {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
}

fn emit_encrypted_extensions(sess: &mut ServerSessionImpl,
                             hello: &ClientHelloPayload)
                             -> Result<(), TLSError> {
    let encrypted_exts = process_extensions(sess, hello)?;
    let ee = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(encrypted_exts),
        }),
    };

    debug!("sending encrypted extensions {:?}", ee);
    sess.handshake_data.transcript.add_message(&ee);
    sess.common.send_msg(ee, true);
    Ok(())
}

fn emit_certificate_req_tls13(sess: &mut ServerSessionImpl) {
    if !sess.config.client_auth_offer {
        return;
    }

    let names = sess.config.client_auth_roots.get_subjects();

    let cr = CertificateRequestPayloadTLS13 {
        context: PayloadU8::empty(),
        sigschemes: SupportedSignatureSchemes::supported_verify(),
        canames: names,
        extensions: Vec::new(),
    };

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestTLS13(cr),
        }),
    };

    debug!("Sending CertificateRequest {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
    sess.handshake_data.doing_client_auth = true;
}

fn emit_certificate_tls13(sess: &mut ServerSessionImpl) {
    let mut cert_body = CertificatePayloadTLS13::new();

    for cert in sess.handshake_data.server_cert_chain.as_ref().unwrap() {
        let entry = CertificateEntry {
            cert: cert.clone(),
            exts: Vec::new(),
        };

        cert_body.list.push(entry);
    }

    let c = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(cert_body),
        }),
    };

    debug!("sending certificate {:?}", c);
    sess.handshake_data.transcript.add_message(&c);
    sess.common.send_msg(c, true);
}

fn emit_certificate_verify_tls13(sess: &mut ServerSessionImpl,
                                 schemes: &[SignatureScheme],
                                 signer: &Arc<Box<sign::Signer>>)
                                 -> Result<(), TLSError> {
    let mut message = Vec::new();
    message.resize(64, 0x20u8);
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    message.extend_from_slice(&sess.handshake_data.transcript.get_current_hash());

    let scheme = signer.choose_scheme(schemes)
        .ok_or_else(|| TLSError::PeerIncompatibleError("no overlapping sigschemes".to_string()))?;

    let sig = signer.sign(scheme, &message)
        .map_err(|_| TLSError::General("cannot sign".to_string()))?;

    let cv = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(cv),
        }),
    };

    debug!("sending certificate-verify {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(sess: &mut ServerSessionImpl) {
    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
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

    debug!("sending finished {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.handshake_data.hash_at_server_fin = sess.handshake_data.transcript.get_current_hash();
    sess.common.send_msg(m, true);

    // Now move to application data keys.
    sess.common.get_mut_key_schedule().input_empty();
    let write_key = sess.common
        .get_key_schedule()
        .derive(SecretKind::ServerApplicationTrafficSecret,
                &sess.handshake_data.hash_at_server_fin);
    let suite = sess.common.get_suite();
    sess.common.set_message_encrypter(cipher::new_tls13_write(suite, &write_key));
    sess.common
        .get_mut_key_schedule()
        .current_server_traffic_secret = write_key;
}

fn check_binder(sess: &mut ServerSessionImpl,
                client_hello: &Message,
                psk: &[u8],
                binder: &[u8])
                -> bool {
    let binder_plaintext = match client_hello.payload {
        MessagePayload::Handshake(ref hmp) => hmp.get_encoding_for_binder_signing(),
        _ => unreachable!(),
    };

    let suite_hash = sess.common.get_suite().get_hash();
    let handshake_hash =
        sess.handshake_data.transcript.get_hash_given(suite_hash, &binder_plaintext);

    let mut empty_hash_ctx = hash_hs::HandshakeHash::new();
    empty_hash_ctx.start_hash(suite_hash);
    let empty_hash = empty_hash_ctx.get_current_hash();

    let mut key_schedule = KeySchedule::new(suite_hash);
    key_schedule.input_secret(psk);
    let base_key = key_schedule.derive(SecretKind::ResumptionPSKBinderKey, &empty_hash);
    let real_binder = key_schedule.sign_verify_data(&base_key, &handshake_hash);

    constant_time::verify_slices_are_equal(&real_binder, binder).is_ok()
}

fn handle_client_hello_tls13(sess: &mut ServerSessionImpl,
                             chm: &Message,
                             signer: &Arc<Box<sign::Signer>>)
                             -> StateResult {
    let client_hello = extract_handshake!(chm, HandshakePayload::ClientHello).unwrap();

    if client_hello.compression_methods.len() != 1 {
        return Err(illegal_param(sess, "client offered wrong compressions"));
    }

    let groups_ext = client_hello.get_namedgroups_extension()
        .ok_or_else(|| incompatible(sess, "client didn't describe groups"))?;

    let mut sigschemes_ext = client_hello.get_sigalgs_extension()
        .ok_or_else(|| incompatible(sess, "client didn't describe sigschemes"))?
        .clone();

    let tls13_schemes = SupportedSignatureSchemes::supported_sign_tls13();
    sigschemes_ext.retain(|scheme| tls13_schemes.contains(scheme));

    let shares_ext = client_hello.get_keyshare_extension()
        .ok_or_else(|| incompatible(sess, "client didn't send keyshares"))?;

    if client_hello.has_keyshare_extension_with_duplicates() {
        return Err(illegal_param(sess, "client sent duplicate keyshares"));
    }

    let share_groups: Vec<NamedGroup> = shares_ext.iter()
        .map(|share| share.group)
        .collect();

    let chosen_group = util::first_in_both(&NamedGroups::supported(), &share_groups);
    if chosen_group.is_none() {
        // We don't have a suitable key share.  Choose a suitable group and
        // send a HelloRetryRequest.
        let retry_group_maybe = util::first_in_both(&NamedGroups::supported(), groups_ext);
        sess.handshake_data.transcript.add_message(chm);

        if let Some(group) = retry_group_maybe {
            if sess.handshake_data.done_retry {
                return Err(illegal_param(sess, "did not follow retry request"));
            } else {
                emit_hello_retry_request(sess, group);
                sess.handshake_data.done_retry = true;
                return Ok(&EXPECT_CLIENT_HELLO);
            }
        } else {
            return Err(incompatible(sess, "no kx group overlap with client"));
        }
    }

    let chosen_group = chosen_group.unwrap();
    let chosen_share = shares_ext.iter()
        .find(|share| share.group == chosen_group)
        .unwrap();

    let mut chosen_psk_index = None;
    let mut resuming_psk = None;
    if let Some(psk_offer) = client_hello.get_psk() {
        if !client_hello.check_psk_ext_is_last() {
            return Err(illegal_param(sess, "psk extension in wrong position"));
        }

        if psk_offer.binders.is_empty() {
            return Err(decode_error(sess, "psk extension missing binder"));
        }

        if psk_offer.binders.len() != psk_offer.identities.len() {
            return Err(illegal_param(sess, "psk extension mismatched ids/binders"));
        }

        for (i, psk_id) in psk_offer.identities.iter().enumerate() {
            let maybe_resume = sess.config
                .ticketer
                .decrypt(&psk_id.identity.0)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain));

            if !can_resume(sess, &maybe_resume) {
                continue;
            }

            let resume = maybe_resume.unwrap();

            if !check_binder(sess, chm, &resume.master_secret.0, &psk_offer.binders[i].0) {
                sess.common.send_fatal_alert(AlertDescription::DecryptError);
                return Err(TLSError::PeerMisbehavedError("client sent wrong binder".to_string()));
            }

            chosen_psk_index = Some(i);
            resuming_psk = Some(resume.master_secret.0);
            break;
        }
    }

    if !client_hello.psk_mode_offered(PSKKeyExchangeMode::PSK_DHE_KE) {
        warn!("Resumption ignored, DHE_KE not offered");
        sess.handshake_data.send_ticket = false;
        chosen_psk_index = None;
        resuming_psk = None;
    } else {
        sess.handshake_data.send_ticket = true;
    }

    let full_handshake = resuming_psk.is_none();
    sess.handshake_data.transcript.add_message(chm);
    emit_server_hello_tls13(sess, chosen_share, chosen_psk_index, resuming_psk)?;
    emit_encrypted_extensions(sess, client_hello)?;

    if full_handshake {
        emit_certificate_req_tls13(sess);
        emit_certificate_tls13(sess);
        emit_certificate_verify_tls13(sess, &sigschemes_ext, signer)?;
    }
    check_aligned_handshake(sess)?;
    emit_finished_tls13(sess);

    if sess.handshake_data.doing_client_auth && full_handshake {
        Ok(&EXPECT_TLS13_CERTIFICATE)
    } else {
        Ok(&EXPECT_TLS13_FINISHED)
    }
}

fn handle_client_hello(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();
    let tls13_enabled = sess.config.versions.contains(&ProtocolVersion::TLSv1_3);
    let tls12_enabled = sess.config.versions.contains(&ProtocolVersion::TLSv1_2);
    debug!("we got a clienthello {:?}", client_hello);

    if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
        sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
        return Err(TLSError::PeerIncompatibleError("client does not support TLSv1_2".to_string()));
    }

    if !client_hello.compression_methods.contains(&Compression::Null) {
        sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
        return Err(TLSError::PeerIncompatibleError("client did not offer Null compression"
            .to_string()));
    }

    if client_hello.has_duplicate_extension() {
        return Err(decode_error(sess, "client sent duplicate extensions"));
    }

    // Are we doing TLS1.3?
    let maybe_versions_ext = client_hello.get_versions_extension();
    if let Some(versions) = maybe_versions_ext {
        if versions.contains(&ProtocolVersion::Unknown(0x7f12)) && tls13_enabled {
            sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
        } else if !versions.contains(&ProtocolVersion::TLSv1_2) || !tls12_enabled {
            sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
            return Err(incompatible(sess, "TLS1.2 not offered/enabled"));
        }
    } else if !tls12_enabled && tls13_enabled {
        sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
        return Err(incompatible(sess, "Server requires TLS1.3, but client omitted versions ext"));
    }

    if sess.common.negotiated_version == None {
        sess.common.negotiated_version = Some(ProtocolVersion::TLSv1_2);
    }

    // Common to TLS1.2 and TLS1.3: ciphersuite and certificate selection.
    let default_sigschemes_ext = SupportedSignatureSchemes::default();

    let sni_ext = client_hello.get_sni_extension()
        .and_then(|sni| sni.get_hostname());
    let sigschemes_ext = client_hello.get_sigalgs_extension()
        .unwrap_or(&default_sigschemes_ext);

    debug!("sni {:?}", sni_ext);
    debug!("sig schemes {:?}", sigschemes_ext);

    // Choose a certificate.
    let maybe_cert_key = sess.config.cert_resolver.resolve(sni_ext, sigschemes_ext);
    if maybe_cert_key.is_none() {
        sess.common.send_fatal_alert(AlertDescription::AccessDenied);
        return Err(TLSError::General("no server certificate chain resolved".to_string()));
    }
    let (cert_chain, private_key) = maybe_cert_key.unwrap();
    sess.handshake_data.server_cert_chain = Some(cert_chain);

    // Reduce our supported ciphersuites by the certificate.
    // (no-op for TLS1.3)
    let suitable_suites = suites::reduce_given_sigalg(&sess.config.ciphersuites,
                                                      &private_key.algorithm());

    // And version
    let protocol_version = sess.common.negotiated_version.unwrap();
    let suitable_suites = suites::reduce_given_version(&suitable_suites, protocol_version);

    let maybe_ciphersuite = if sess.config.ignore_client_order {
        suites::choose_ciphersuite_preferring_server(&client_hello.cipher_suites, &suitable_suites)
    } else {
        suites::choose_ciphersuite_preferring_client(&client_hello.cipher_suites, &suitable_suites)
    };

    if maybe_ciphersuite.is_none() {
        return Err(incompatible(sess, "no ciphersuites in common"));
    }

    info!("decided upon suite {:?}", maybe_ciphersuite.as_ref().unwrap());
    sess.common.set_suite(maybe_ciphersuite.unwrap());

    // Start handshake hash.
    if !sess.handshake_data.transcript.start_hash(sess.common.get_suite().get_hash()) {
        sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
        return Err(TLSError::PeerIncompatibleError("hash differed on retry"
            .to_string()));
    }

    if sess.common.is_tls13() {
        return handle_client_hello_tls13(sess, &m, &private_key);
    }

    // -- TLS1.2 only from hereon in --
    sess.handshake_data.transcript.add_message(&m);
    // Save their Random.
    client_hello.random.write_slice(&mut sess.handshake_data.randoms.client);

    if client_hello.ems_support_offered() {
        sess.handshake_data.using_ems = true;
    }

    let groups_ext = client_hello.get_namedgroups_extension()
        .ok_or_else(|| incompatible(sess, "client didn't describe groups"))?;
    let ecpoints_ext = client_hello.get_ecpoints_extension()
        .ok_or_else(|| incompatible(sess, "client didn't describe ec points"))?;

    debug!("namedgroups {:?}", groups_ext);
    debug!("ecpoints {:?}", ecpoints_ext);

    if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
        sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
        return Err(TLSError::PeerIncompatibleError("client didn't support uncompressed ec points"
            .to_string()));
    }

    // -- Check for resumption --
    // We can do this either by (in order of preference):
    // 1. receiving a ticket that decrypts
    // 2. receiving a sessionid that is in our cache
    //
    // If we receive a ticket, the sessionid won't be in our
    // cache, so don't check.
    //
    // If either works, we end up with a ServerSessionValue
    // which is passed to start_resumption and concludes
    // our handling of the ClientHello.
    //
    let mut ticket_received = false;

    if let Some(ticket_ext) = client_hello.get_ticket_extension() {
        if let ClientExtension::SessionTicketOffer(ref ticket) = *ticket_ext {
            ticket_received = true;
            info!("Ticket received");

            let maybe_resume = sess.config
                .ticketer
                .decrypt(&ticket.0)
                .and_then(|plain| persist::ServerSessionValue::read_bytes(&plain));

            if can_resume(sess, &maybe_resume) {
                return start_resumption(sess,
                                        client_hello,
                                        &client_hello.session_id,
                                        maybe_resume.unwrap());
            } else {
                info!("Ticket didn't decrypt");
            }
        }
    }

    // Perhaps resume?  If we received a ticket, the sessionid
    // does not correspond to a real session.
    if !client_hello.session_id.is_empty() && !ticket_received {
        let maybe_resume = sess.config.session_storage
            .get(&client_hello.session_id)
            .and_then(|x| persist::ServerSessionValue::read_bytes(&x));

        if can_resume(sess, &maybe_resume) {
            return start_resumption(sess,
                                    client_hello,
                                    &client_hello.session_id,
                                    maybe_resume.unwrap());
        }
    }

    // Now we have chosen a ciphersuite, we can make kx decisions.
    let sigscheme = sess.common.get_suite()
        .resolve_sig_scheme(sigschemes_ext)
        .ok_or_else(|| incompatible(sess, "no supported sig scheme"))?;

    let group = util::first_in_both(NamedGroups::supported().as_slice(),
                                    groups_ext.as_slice())
        .ok_or_else(|| incompatible(sess, "no supported group"))?;

    let ecpoint = util::first_in_both(ECPointFormatList::supported().as_slice(),
                                      ecpoints_ext.as_slice())
        .ok_or_else(|| incompatible(sess, "no supported point format"))?;

    debug_assert_eq!(ecpoint, ECPointFormat::Uncompressed);

    emit_server_hello(sess, client_hello)?;
    emit_certificate(sess);
    emit_server_kx(sess, sigscheme, &group, private_key)?;
    emit_certificate_req(sess);
    emit_server_hello_done(sess);

    if sess.handshake_data.doing_client_auth {
        Ok(&EXPECT_TLS12_CERTIFICATE)
    } else {
        Ok(&EXPECT_TLS12_CLIENT_KX)
    }
}

pub static EXPECT_CLIENT_HELLO: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ClientHello],
    },
    handle: handle_client_hello,
};

// --- Process client's Certificate for client auth ---
fn handle_certificate_tls12(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    sess.handshake_data.transcript.add_message(&m);
    let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();

    if cert_chain.is_empty() && !sess.config.client_auth_mandatory {
        info!("client auth requested but no certificate supplied");
        sess.handshake_data.doing_client_auth = false;
        sess.handshake_data.transcript.abandon_client_auth();
        return Ok(&EXPECT_TLS12_CLIENT_KX);
    }

    debug!("certs {:?}", cert_chain);

    sess.config.get_verifier().verify_client_cert(&sess.config.client_auth_roots,
                                                  &cert_chain)
        .or_else(|err| {
                 incompatible(sess, "certificate invalid");
                 Err(err)
                 })?;

    sess.handshake_data.valid_client_cert_chain = Some(cert_chain.clone());
    Ok(&EXPECT_TLS12_CLIENT_KX)
}

static EXPECT_TLS12_CERTIFICATE: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Certificate],
    },
    handle: handle_certificate_tls12,
};

fn handle_certificate_tls13(sess: &mut ServerSessionImpl,
                            m: Message)
                            -> StateResult {
    sess.handshake_data.transcript.add_message(&m);
    let certp = extract_handshake!(m, HandshakePayload::CertificateTLS13).unwrap();
    let cert_chain = certp.convert();

    if cert_chain.is_empty() {
        if !sess.config.client_auth_mandatory {
            info!("client auth requested but no certificate supplied");
            sess.handshake_data.doing_client_auth = false;
            sess.handshake_data.transcript.abandon_client_auth();
            return Ok(&EXPECT_TLS13_FINISHED);
        }

        sess.common.send_fatal_alert(AlertDescription::CertificateRequired);
        return Err(TLSError::NoCertificatesPresented);
    }

    sess.config.get_verifier().verify_client_cert(&sess.config.client_auth_roots,
                                                  &cert_chain)?;

    sess.handshake_data.valid_client_cert_chain = Some(cert_chain);
    Ok(&EXPECT_TLS13_CERTIFICATE_VERIFY)
}

static EXPECT_TLS13_CERTIFICATE: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Certificate],
    },
    handle: handle_certificate_tls13,
};

// --- Process client's KeyExchange ---
fn handle_client_kx(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    let client_kx = extract_handshake!(m, HandshakePayload::ClientKeyExchange).unwrap();
    sess.handshake_data.transcript.add_message(&m);

    // Complete key agreement, and set up encryption with the
    // resulting premaster secret.
    let kx = sess.handshake_data.kx_data.take().unwrap();
    if !kx.check_client_params(&client_kx.0) {
        sess.common.send_fatal_alert(AlertDescription::DecodeError);
        return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
    }

    let kxd = kx.server_complete(&client_kx.0)
        .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange completion failed"
                                                     .to_string()))?;

    let hashalg = sess.common.get_suite().get_hash();
    if sess.handshake_data.using_ems {
        let handshake_hash = sess.handshake_data.transcript.get_current_hash();
        sess.secrets = Some(SessionSecrets::new_ems(&sess.handshake_data.randoms,
                                                    &handshake_hash,
                                                    hashalg,
                                                    &kxd.premaster_secret));
    } else {
        sess.secrets = Some(SessionSecrets::new(&sess.handshake_data.randoms,
                                                hashalg,
                                                &kxd.premaster_secret));
    }
    sess.start_encryption_tls12();

    if sess.handshake_data.doing_client_auth {
        Ok(&EXPECT_TLS12_CERTIFICATE_VERIFY)
    } else {
        Ok(&EXPECT_TLS12_CCS)
    }
}

static EXPECT_TLS12_CLIENT_KX: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::ClientKeyExchange],
    },
    handle: handle_client_kx,
};

// --- Process client's certificate proof ---
fn handle_certificate_verify_tls12(sess: &mut ServerSessionImpl,
                                   m: Message) -> StateResult {
    let rc = {
        let sig = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();
        let certs = sess.handshake_data.valid_client_cert_chain.as_ref().unwrap();
        let handshake_msgs = sess.handshake_data.transcript.take_handshake_buf();

        verify::verify_signed_struct(&handshake_msgs, &certs[0], sig)
    };

    if rc.is_err() {
        sess.common.send_fatal_alert(AlertDescription::AccessDenied);
        return Err(rc.unwrap_err());
    } else {
        debug!("client CertificateVerify OK");
    }

    sess.handshake_data.transcript.add_message(&m);
    Ok(&EXPECT_TLS12_CCS)
}

static EXPECT_TLS12_CERTIFICATE_VERIFY: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::CertificateVerify],
    },
    handle: handle_certificate_verify_tls12,
};

fn handle_certificate_verify_tls13(sess: &mut ServerSessionImpl,
                                   m: Message)
                                   -> StateResult {
    let rc = {
        let sig = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();
        let certs = sess.handshake_data.valid_client_cert_chain.as_ref().unwrap();
        let handshake_hash = sess.handshake_data.transcript.get_current_hash();
        sess.handshake_data.transcript.abandon_client_auth();

        verify::verify_tls13(&certs[0],
                             sig,
                             &handshake_hash,
                             b"TLS 1.3, client CertificateVerify\x00")
    };

    if rc.is_err() {
        sess.common.send_fatal_alert(AlertDescription::AccessDenied);
        return Err(rc.unwrap_err());
    } else {
        debug!("client CertificateVerify OK");
    }

    sess.handshake_data.transcript.add_message(&m);
    Ok(&EXPECT_TLS13_FINISHED)
}

static EXPECT_TLS13_CERTIFICATE_VERIFY: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::CertificateVerify],
    },
    handle: handle_certificate_verify_tls13,
};

// --- Process client's ChangeCipherSpec ---
fn handle_ccs(sess: &mut ServerSessionImpl, _m: Message) -> StateResult {
    // CCS should not be received interleaved with fragmented handshake-level
    // message.
    if !sess.common.handshake_joiner.is_empty() {
        warn!("CCS received interleaved with fragmented handshake");
        return Err(TLSError::InappropriateMessage {
            expect_types: vec![ ContentType::Handshake ],
            got_type: ContentType::ChangeCipherSpec,
        });
    }

    sess.common.peer_now_encrypting();
    Ok(&EXPECT_TLS12_FINISHED)
}

static EXPECT_TLS12_CCS: State = State {
    expect: Expectation {
        content_types: &[ContentType::ChangeCipherSpec],
        handshake_types: &[],
    },
    handle: handle_ccs,
};

// --- Process client's Finished ---
fn emit_ticket(sess: &mut ServerSessionImpl) {
    if !sess.handshake_data.send_ticket {
        return;
    }

    // If we can't produce a ticket for some reason, we can't
    // report an error. Send an empty one.
    let plain = get_server_session_value(sess).get_encoding();
    let ticket = sess.config
        .ticketer
        .encrypt(&plain)
        .unwrap_or_else(Vec::new);
    let ticket_lifetime = sess.config.ticketer.get_lifetime();

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload:
                HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(ticket_lifetime,
                                                                                ticket)),
        }),
    };

    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, false);
}

fn emit_ccs(sess: &mut ServerSessionImpl) {
    let m = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(m, false);
    sess.common.we_now_encrypting();
}

fn emit_finished(sess: &mut ServerSessionImpl) {
    let vh = sess.handshake_data.transcript.get_current_hash();
    let verify_data = sess.secrets.as_ref().unwrap().server_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    sess.handshake_data.transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

fn get_server_session_value(sess: &ServerSessionImpl) -> persist::ServerSessionValue {
    let scs = sess.common.get_suite();
    let client_certs = &sess.handshake_data.valid_client_cert_chain;

    let (version, secret) = if sess.common.is_tls13() {
        let handshake_hash = sess.handshake_data
            .transcript
            .get_current_hash();
        let resume_secret = sess.common
            .get_key_schedule()
            .derive(SecretKind::ResumptionMasterSecret, &handshake_hash);
        (ProtocolVersion::TLSv1_3, resume_secret)
    } else {
        (ProtocolVersion::TLSv1_2, sess.secrets.as_ref().unwrap().get_master_secret())
    };

    let mut v = persist::ServerSessionValue::new(version, scs.suite, secret, client_certs);

    if sess.handshake_data.using_ems {
        v.set_extended_ms_used();
    }

    v
}

fn handle_finished(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

    let vh = sess.handshake_data.transcript.get_current_hash();
    let expect_verify_data = sess.secrets.as_ref().unwrap().client_verify_data(&vh);

    constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
        .map_err(|_| {
                 sess.common.send_fatal_alert(AlertDescription::DecryptError);
                 warn!("Finished wrong");
                 TLSError::DecryptError
                 })?;

    // Save session, perhaps
    if !sess.handshake_data.doing_resume && !sess.handshake_data.session_id.is_empty() {
        let value = get_server_session_value(sess);

        let worked = sess.config.session_storage
            .put(&sess.handshake_data.session_id, value.get_encoding());
        if worked {
            info!("Session saved");
        } else {
            info!("Session not saved");
        }
    }

    // Send our CCS and Finished.
    sess.handshake_data.transcript.add_message(&m);
    if !sess.handshake_data.doing_resume {
        emit_ticket(sess);
        emit_ccs(sess);
        emit_finished(sess);
    }

    sess.common.we_now_encrypting();
    sess.common.start_traffic();
    Ok(&EXPECT_TLS12_TRAFFIC)
}

static EXPECT_TLS12_FINISHED: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Finished],
    },
    handle: handle_finished,
};

fn emit_ticket_tls13(sess: &mut ServerSessionImpl) {
    if !sess.handshake_data.send_ticket {
        return;
    }

    let plain = get_server_session_value(sess).get_encoding();
    let maybe_ticket = sess.config
        .ticketer
        .encrypt(&plain);
    let ticket_lifetime = sess.config.ticketer.get_lifetime();

    if maybe_ticket.is_none() {
        return;
    }

    let ticket = maybe_ticket.unwrap();
    let age_add = rand::random_u32(); // nb, we don't do 0-RTT data, so whatever
    let payload = NewSessionTicketPayloadTLS13::new(ticket_lifetime, age_add, ticket);
    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTLS13(payload),
        }),
    };

    debug!("sending new ticket {:?}", m);
    sess.handshake_data.transcript.add_message(&m);
    sess.common.send_msg(m, true);
}

fn handle_finished_tls13(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

    let handshake_hash = sess.handshake_data.transcript.get_current_hash();
    let expect_verify_data = sess.common
        .get_key_schedule()
        .sign_finish(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);

    constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
        .map_err(|_| {
                 sess.common.send_fatal_alert(AlertDescription::DecryptError);
                 warn!("Finished wrong");
                 TLSError::DecryptError
                 })?;

    // nb. future derivations include Client Finished, but not the
    // main application data keying.
    sess.handshake_data.transcript.add_message(&m);

    // Now move to using application data keys for client traffic.
    // Server traffic is already done.
    let read_key = sess.common
        .get_key_schedule()
        .derive(SecretKind::ClientApplicationTrafficSecret,
                &sess.handshake_data.hash_at_server_fin);

    let suite = sess.common.get_suite();
    check_aligned_handshake(sess)?;
    sess.common.set_message_decrypter(cipher::new_tls13_read(suite, &read_key));
    sess.common
        .get_mut_key_schedule()
        .current_client_traffic_secret = read_key;

    if sess.config.ticketer.enabled() {
        emit_ticket_tls13(sess);
    }

    sess.common.we_now_encrypting();
    sess.common.start_traffic();
    Ok(&EXPECT_TLS13_TRAFFIC)
}

static EXPECT_TLS13_FINISHED: State = State {
    expect: Expectation {
        content_types: &[ContentType::Handshake],
        handshake_types: &[HandshakeType::Finished],
    },
    handle: handle_finished_tls13,
};

// --- Process traffic ---
fn handle_traffic(sess: &mut ServerSessionImpl, mut m: Message) -> StateResult {
    sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
    Ok(&EXPECT_TLS12_TRAFFIC)
}

static EXPECT_TLS12_TRAFFIC: State = State {
    expect: Expectation {
        content_types: &[ContentType::ApplicationData],
        handshake_types: &[],
    },
    handle: handle_traffic,
};

fn handle_key_update(sess: &mut ServerSessionImpl, m: Message) -> Result<(), TLSError> {
    let kur = extract_handshake!(m, HandshakePayload::KeyUpdate).unwrap();
    sess.common.process_key_update(kur, SecretKind::ClientApplicationTrafficSecret)
}

fn handle_traffic_tls13(sess: &mut ServerSessionImpl, m: Message) -> StateResult {
    if m.is_content_type(ContentType::ApplicationData) {
        handle_traffic(sess, m)?;
    } else if m.is_handshake_type(HandshakeType::KeyUpdate) {
        handle_key_update(sess, m)?;
    }

    Ok(&EXPECT_TLS13_TRAFFIC)
}

static EXPECT_TLS13_TRAFFIC: State = State {
    expect: Expectation {
        content_types: &[ContentType::ApplicationData, ContentType::Handshake],
        handshake_types: &[HandshakeType::KeyUpdate],
    },
    handle: handle_traffic_tls13,
};
