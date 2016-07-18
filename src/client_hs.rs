use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion, AlertDescription};
use msgs::message::{Message, MessagePayload};
use msgs::base::{Payload, PayloadU8};
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload};
use msgs::handshake::{SessionID, Random};
use msgs::handshake::ClientExtension;
use msgs::handshake::{SupportedSignatureAlgorithms, SupportedMandatedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, SupportedCurves};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ProtocolNameList, ConvertProtocolNameList};
use msgs::handshake::ServerKeyExchangePayload;
use msgs::handshake::DigitallySignedStruct;
use msgs::enums::ClientCertificateType;
use msgs::codec::Codec;
use msgs::persist;
use msgs::ccs::ChangeCipherSpecPayload;
use client::{ClientSessionImpl, ConnState};
use suites;
use hash_hs;
use verify;
use error::TLSError;
use handshake::Expectation;

use std::mem;

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

pub type HandleFunction = fn(&mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError>;

/* These are effectively operations on the ClientSessionImpl, variant on the
 * connection state. They must not have state of their own -- so they're
 * functions rather than a trait. */
pub struct Handler {
  pub expect: Expectation,
  pub handle: HandleFunction
}

fn find_session(sess: &mut ClientSessionImpl) -> Option<persist::ClientSessionValue> {
  let key = persist::ClientSessionKey::for_dns_name(&sess.handshake_data.dns_name);
  let key_buf = key.get_encoding();

  let mut persist = sess.config.session_persistence.lock().expect("");
  let maybe_value = persist.get(&key_buf);

  if maybe_value.is_none() {
    info!("No cached session for {:?}", sess.handshake_data.dns_name);
    return None
  }

  let value = maybe_value.unwrap();
  persist::ClientSessionValue::read_bytes(&value)
}

pub fn emit_client_hello(sess: &mut ClientSessionImpl) {
  sess.handshake_data.generate_client_random();

  /* Do we have a SessionID cached for this host? */
  sess.handshake_data.resuming_session = find_session(sess);
  let session_id = if let Some(resuming) = sess.handshake_data.resuming_session.as_ref() {
    info!("Resuming session");
    resuming.session_id.clone()
  } else {
    info!("Not resuming any session");
    SessionID::empty()
  };

  let mut exts = Vec::new();
  exts.push(ClientExtension::make_sni(&sess.handshake_data.dns_name));
  exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));
  exts.push(ClientExtension::EllipticCurves(EllipticCurveList::supported()));
  exts.push(ClientExtension::SignatureAlgorithms(SupportedSignatureAlgorithms::supported()));

  if sess.config.alpn_protocols.len() > 0 {
    exts.push(ClientExtension::Protocols(ProtocolNameList::from_strings(&sess.config.alpn_protocols)));
  }

  let sh = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(
          ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_slice(&sess.handshake_data.secrets.client_random),
            session_id: session_id,
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts
          }
        )
      }
    )
  };

  debug!("Sending ClientHello {:#?}", sh);

  sh.payload.encode(&mut sess.handshake_data.client_hello);
  sess.common.send_msg(&sh, false);
}

fn handle_server_hello(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let server_hello = extract_handshake!(m, HandshakePayload::ServerHello).unwrap();
  debug!("We got ServerHello {:#?}", server_hello);

  if server_hello.server_version != ProtocolVersion::TLSv1_2 {
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    return Err(TLSError::General("server does not support TLSv1_2".to_string()));
  }

  if server_hello.compression_method != Compression::Null {
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    return Err(TLSError::General("server chose non-Null compression".to_string()));
  }

  /* Extract ALPN protocol */
  sess.alpn_protocol = server_hello.get_alpn_protocol();
  info!("ALPN protocol is {:?}", sess.alpn_protocol);

  let scs = sess.find_cipher_suite(&server_hello.cipher_suite);

  if scs.is_none() {
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    return Err(TLSError::General("server chose non-offered ciphersuite".to_string()));
  }

  info!("Using ciphersuite {:?}", server_hello.cipher_suite);

  /* Start our handshake hash, and input the client hello we sent, and this reply. */
  sess.handshake_data.handshake_hash = Some(
    hash_hs::HandshakeHash::new(scs.as_ref().unwrap().get_hash())
  );
  sess.handshake_data.handshake_hash.as_mut().unwrap()
    .update_raw(&sess.handshake_data.client_hello)
    .update(m);

  sess.handshake_data.ciphersuite = scs;

  /* Save ServerRandom and SessionID */
  server_hello.random.write_slice(&mut sess.handshake_data.secrets.server_random);
  sess.handshake_data.session_id = server_hello.session_id.clone();

  /* See if we're successfully resuming. */
  let mut abbreviated_handshake = false;
  if let Some(ref resuming) = sess.handshake_data.resuming_session {
    if resuming.session_id.bytes == sess.handshake_data.session_id.bytes {
      info!("Server agreed to resume");
      abbreviated_handshake = true;

      /* Is the server telling lies about the ciphersuite? */
      if resuming.cipher_suite != scs.unwrap().suite {
        return Err(TLSError::General("abbreviated handshake offered, but with varied cs".to_string()));
      }

      sess.secrets_current.init_resume(&sess.handshake_data.secrets,
                                       scs.unwrap().get_hash(),
                                       &resuming.master_secret.body);
    }
  }

  if abbreviated_handshake {
    sess.start_encryption();
    Ok(ConnState::ExpectCCSResume)
  } else {
    Ok(ConnState::ExpectCertificate)
  }
}

pub static EXPECT_SERVER_HELLO: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ServerHello]
  },
  handle: handle_server_hello
};

fn handle_certificate(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
  sess.handshake_data.hash_message(m);
  sess.handshake_data.server_cert_chain = cert_chain.clone();
  Ok(ConnState::ExpectServerKX)
}

pub static EXPECT_CERTIFICATE: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::Certificate]
  },
  handle: handle_certificate
};

fn handle_server_kx(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
  let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.handshake_data.ciphersuite.unwrap().kx);
  sess.handshake_data.hash_message(m);

  if maybe_decoded_kx.is_none() {
    return Err(TLSError::General("cannot decode server's kx".to_string()));
  }

  let decoded_kx = maybe_decoded_kx.unwrap();

  /* Save the signature and signed parameters for later verification. */
  sess.handshake_data.server_kx_sig = decoded_kx.get_sig();
  decoded_kx.encode_params(&mut sess.handshake_data.server_kx_params);

  match decoded_kx {
    ServerKeyExchangePayload::ECDHE(ecdhe) => info!("ECDHE curve is {:?}", ecdhe.params.curve_params),
    _ => ()
  }

  Ok(ConnState::ExpectServerHelloDoneOrCertRequest)
}

pub static EXPECT_SERVER_KX: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ServerKeyExchange]
  },
  handle: handle_server_kx
};

fn dumphex(_label: &str, _bytes: &[u8]) {
  /*
  print!("{}: ", _label);

  for b in _bytes {
    print!("{:02x}", b);
  }

  println!("");
  */
}

fn emit_certificate(sess: &mut ClientSessionImpl) {
  let chosen_cert = mem::replace(&mut sess.handshake_data.client_auth_cert, None);

  let cert = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::Certificate,
        payload: HandshakePayload::Certificate(
          chosen_cert.unwrap_or_else(|| Vec::new())
        )
      }
    )
  };

  sess.handshake_data.hash_message(&cert);
  sess.common.send_msg(&cert, false);
}

fn emit_clientkx(sess: &mut ClientSessionImpl, kxd: &suites::KeyExchangeResult) {
  let mut buf = Vec::new();
  let ecpoint = PayloadU8 { body: kxd.pubkey.clone().into_boxed_slice() };
  ecpoint.encode(&mut buf);
  let pubkey = Payload { body: buf.into_boxed_slice() };

  let ckx = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ClientKeyExchange,
        payload: HandshakePayload::ClientKeyExchange(pubkey)
      }
    )
  };

  sess.handshake_data.hash_message(&ckx);
  sess.common.send_msg(&ckx, false);
}

fn emit_certverify(sess: &mut ClientSessionImpl) {
  let message = sess.handshake_data.handshake_hash
    .as_mut()
    .unwrap()
    .take_handshake_buf();

  if sess.handshake_data.client_auth_key.is_none() {
    debug!("Not sending CertificateVerify, no key");
    return;
  }

  let key = mem::replace(&mut sess.handshake_data.client_auth_key, None).unwrap();
  let sigalg = sess.handshake_data.client_auth_sigalg
    .clone()
    .unwrap();
  let sig = key.sign(&sigalg.hash, &message)
    .expect("client auth signing failed unexpectedly");
  let body = DigitallySignedStruct::new(&sigalg, sig);

  let m = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::CertificateVerify,
        payload: HandshakePayload::CertificateVerify(body)
      }
    )
  };

  sess.handshake_data.hash_message(&m);
  sess.common.send_msg(&m, false);
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
  let ccs = Message {
    typ: ContentType::ChangeCipherSpec,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
  };

  sess.common.send_msg(&ccs, false);
}

fn emit_finished(sess: &mut ClientSessionImpl) {
  let vh = sess.handshake_data.get_verify_hash();
  dumphex("finished vh", &vh);
  let verify_data = sess.secrets_current.client_verify_data(&vh);
  dumphex("finished verify", &verify_data);
  let verify_data_payload = Payload { body: verify_data.into_boxed_slice() };

  let f = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::Finished,
        payload: HandshakePayload::Finished(verify_data_payload)
      }
    )
  };

  sess.handshake_data.hash_message(&f);
  sess.common.send_msg(&f, true);
}

/* --- Either a CertificateRequest, or a ServerHelloDone. ---
 * Existence of the CertificateRequest tells us the server is asking for
 * client auth.  Otherwise we go straight to ServerHelloDone. */
fn handle_certificate_req(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let certreq = extract_handshake!(m, HandshakePayload::CertificateRequest).unwrap();
  sess.handshake_data.hash_message(m);
  sess.handshake_data.doing_client_auth = true;
  info!("Got CertificateRequest {:?}", certreq);

  /* The RFC jovially describes the design here as 'somewhat complicated'
   * and 'somewhat underspecified'.  So thanks for that. */

  /* We only support RSA signing at the moment.  If you don't support that,
   * we're not doing client auth. */
  if !certreq.certtypes.contains(&ClientCertificateType::RSASign) {
    warn!("Server asked for client auth but without RSASign");
    return Ok(ConnState::ExpectServerHelloDone);
  }

  let maybe_certkey = sess.config.client_auth_cert_resolver.resolve(
    &certreq.canames, &certreq.sigalgs
  );

  let scs = sess.handshake_data.ciphersuite.as_ref().unwrap();
  let maybe_sigalg = scs.resolve_sig_alg(&certreq.sigalgs);

  if maybe_certkey.is_some() && maybe_sigalg.is_some() {
    let (cert, key) = maybe_certkey.unwrap();
    info!("Attempting client auth, will use {:?}", maybe_sigalg.as_ref().unwrap());
    sess.handshake_data.client_auth_cert = Some(cert);
    sess.handshake_data.client_auth_key = Some(key);
    sess.handshake_data.client_auth_sigalg = maybe_sigalg;
  } else {
    info!("Client auth requested but no cert/sigalg available");
  }

  Ok(ConnState::ExpectServerHelloDone)
}

fn handle_done_or_certreq(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  if extract_handshake!(m, HandshakePayload::CertificateRequest).is_some() {
    handle_certificate_req(sess, m)
  } else {
    handle_server_hello_done(sess, m)
  }
}

pub static EXPECT_DONE_OR_CERTREQ: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::CertificateRequest, HandshakeType::ServerHelloDone]
  },
  handle: handle_done_or_certreq
};

fn handle_server_hello_done(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  sess.handshake_data.hash_message(m);

  info!("Server cert is {:?}", sess.handshake_data.server_cert_chain);
  info!("Server DNS name is {:?}", sess.handshake_data.dns_name);

  /* 1. Verify the cert chain.
   * 2. Verify that the top certificate signed their kx.
   * 3. If doing client auth, send our Certificate.
   * 4. Complete the key exchange:
   *    a) generate our kx pair
   *    b) emit a ClientKeyExchange containing it
   *    c) if doing client auth, emit a CertificateVerify
   *    d) emit a CCS
   *    e) derive the shared keys, and start encryption
   * 5. emit a Finished, our first encrypted message under the new keys. */

  /* 1. */
  try!(verify::verify_cert(&sess.config.root_store,
                           &sess.handshake_data.server_cert_chain,
                           &sess.handshake_data.dns_name));

  /* 2. */
  /* Build up the contents of the signed message.
   * It's ClientHello.random || ServerHello.random || ServerKeyExchange.params */
  let mut message = Vec::new();
  message.extend_from_slice(&sess.handshake_data.secrets.client_random);
  message.extend_from_slice(&sess.handshake_data.secrets.server_random);
  message.extend_from_slice(&sess.handshake_data.server_kx_params);

  dumphex("verify message", &message);
  dumphex("verify sig", &sess.handshake_data.server_kx_sig.as_ref().unwrap().sig.body);

  try!(verify::verify_kx(&message,
                         &sess.handshake_data.server_cert_chain[0],
                         sess.handshake_data.server_kx_sig.as_ref().unwrap()));

  /* 3. */
  if sess.handshake_data.doing_client_auth {
    emit_certificate(sess);
  }

  /* 4a. */
  let kxd = try!(sess.handshake_data.ciphersuite.as_ref().unwrap()
    .do_client_kx(&sess.handshake_data.server_kx_params)
    .ok_or_else(|| TLSError::General("key exchange failed".to_string()))
  );

  /* 4b. */
  emit_clientkx(sess, &kxd);

  /* 4c. */
  if sess.handshake_data.doing_client_auth {
    emit_certverify(sess);
  }

  /* 4d. */
  emit_ccs(sess);

  /* 4e. Now commit secrets. */
  sess.secrets_current.init(&sess.handshake_data.secrets,
                            sess.handshake_data.ciphersuite.as_ref().unwrap().get_hash(),
                            &kxd.premaster_secret);
  sess.start_encryption();

  /* 5. */
  emit_finished(sess);

  Ok(ConnState::ExpectCCS)
}

pub static EXPECT_SERVER_HELLO_DONE: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ServerHelloDone]
  },
  handle: handle_server_hello_done
};

/* -- Waiting for their CCS -- */
fn handle_ccs(_sess: &mut ClientSessionImpl, _m: &Message) -> Result<ConnState, TLSError> {
  /* nb. msgs layer validates trivial contents of CCS */
  Ok(ConnState::ExpectFinished)
}

pub static EXPECT_CCS: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::ChangeCipherSpec],
    handshake_types: &[]
  },
  handle: handle_ccs
};

fn handle_ccs_resume(_sess: &mut ClientSessionImpl, _m: &Message) -> Result<ConnState, TLSError> {
  /* nb. msgs layer validates trivial contents of CCS */
  Ok(ConnState::ExpectFinishedResume)
}

pub static EXPECT_CCS_RESUME: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::ChangeCipherSpec],
    handshake_types: &[]
  },
  handle: handle_ccs_resume
};

/* -- Waiting for their finished -- */
fn save_session(sess: &mut ClientSessionImpl) {
  if sess.handshake_data.session_id.bytes.len() == 0 {
    info!("Session not saved: server didn't allocate id");
    return;
  }

  let key = persist::ClientSessionKey::for_dns_name(&sess.handshake_data.dns_name);
  let key_buf = key.get_encoding();

  let scs = sess.handshake_data.ciphersuite.as_ref().unwrap();
  let value = persist::ClientSessionValue::new(&scs.suite,
                                               &sess.handshake_data.session_id,
                                               sess.secrets_current.get_master_secret());
  let value_buf = value.get_encoding();

  let mut persist = sess.config.session_persistence.lock().expect("");
  let worked = persist.put(key_buf, value_buf);

  if worked {
    info!("Session saved");
  } else {
    info!("Session not saved");
  }
}

fn handle_finished(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

  /* Work out what verify_data we expect. */
  let vh = sess.handshake_data.get_verify_hash();
  let expect_verify_data = sess.secrets_current.server_verify_data(&vh);

  /* Constant-time verification of this is relatively unimportant: they only
   * get one chance.  But it can't hurt. */
  use ring;
  try!(
    ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.body)
      .map_err(|_| TLSError::DecryptError)
  );

  /* Hash this message too. */
  sess.handshake_data.hash_message(m);

  save_session(sess);

  Ok(ConnState::Traffic)
}

fn handle_finished_resume(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let next_state = try!(handle_finished(sess, m));

  emit_ccs(sess);
  emit_finished(sess);
  Ok(next_state)
}

pub static EXPECT_FINISHED: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::Finished]
  },
  handle: handle_finished
};

pub static EXPECT_FINISHED_RESUME: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[]
  },
  handle: handle_finished_resume
};

/* -- Traffic transit state -- */
fn handle_traffic(sess: &mut ClientSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  sess.common.take_received_plaintext(m.get_opaque_payload().unwrap());
  Ok(ConnState::Traffic)
}

pub static TRAFFIC: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::ApplicationData],
    handshake_types: &[]
  },
  handle: handle_traffic
};
