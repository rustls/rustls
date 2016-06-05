use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::base::Payload;
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload};
use msgs::handshake::{SessionID, Random};
use msgs::handshake::ClientExtension;
use msgs::handshake::{SupportedSignatureAlgorithms, SupportedMandatedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, SupportedCurves};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ProtocolNameList, ConvertProtocolNameList};
use msgs::handshake::ServerKeyExchangePayload;
use msgs::ccs::ChangeCipherSpecPayload;
use client::{ClientSession, ConnState};
use suites;
use hash_hs;
use verify;
use handshake::{HandshakeError, Expectation, ExpectFunction};

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

pub type HandleFunction = fn(&mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError>;

/* These are effectively operations on the ClientSession, variant on the
 * connection state. They must not have state of their own -- so they're
 * functions rather than a trait. */
pub struct Handler {
  pub expect: ExpectFunction,
  pub handle: HandleFunction
}

pub fn emit_client_hello(sess: &mut ClientSession) {
  sess.handshake_data.generate_client_random();

  let mut exts = Vec::new();
  exts.push(ClientExtension::make_sni(&sess.handshake_data.dns_name));
  exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));
  exts.push(ClientExtension::EllipticCurves(EllipticCurveList::supported()));
  exts.push(ClientExtension::SignatureAlgorithms(SupportedSignatureAlgorithms::supported()));

  if sess.config.alpn_protocols.len() > 0 {
    exts.push(ClientExtension::Protocols(ProtocolNameList::convert(&sess.config.alpn_protocols)));
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
            session_id: SessionID::empty(),
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts
          }
        )
      }
    )
  };

  debug!("Sending ClientHello {:?}", sh);

  sh.payload.encode(&mut sess.handshake_data.client_hello);
  sess.tls_queue.push_back(sh);
}

fn expect_server_hello() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ServerHello]
  }
}

fn handle_server_hello(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let server_hello = extract_handshake!(m, HandshakePayload::ServerHello).unwrap();
  debug!("We got ServerHello {:?}", server_hello);

  if server_hello.server_version != ProtocolVersion::TLSv1_2 {
    return Err(HandshakeError::General("server does not support TLSv1_2".to_string()));
  }

  if server_hello.compression_method != Compression::Null {
    return Err(HandshakeError::General("server chose non-Null compression".to_string()));
  }

  /* Extract ALPN protocol */
  sess.alpn_protocol = server_hello.get_alpn_protocol();
  info!("ALPN protocol is {:?}", sess.alpn_protocol);

  let scs = sess.find_cipher_suite(&server_hello.cipher_suite);

  if scs.is_none() {
    return Err(HandshakeError::General("server chose non-offered ciphersuite".to_string()));
  }

  /* Start our handshake hash, and input the client hello we sent, and this reply. */
  sess.handshake_data.handshake_hash = Some(
    hash_hs::HandshakeHash::new(scs.as_ref().unwrap().get_hash())
  );
  sess.handshake_data.handshake_hash.as_mut().unwrap()
    .update_raw(&sess.handshake_data.client_hello)
    .update(m);

  sess.handshake_data.ciphersuite = scs;

  /* Save ServerRandom */
  server_hello.random.write_slice(&mut sess.handshake_data.secrets.server_random);

  Ok(ConnState::ExpectCertificate)
}

pub static EXPECT_SERVER_HELLO: Handler = Handler {
  expect: expect_server_hello,
  handle: handle_server_hello
};

fn expect_certificate() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::Certificate]
  }
}

fn handle_certificate(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
  sess.handshake_data.hash_message(m);
  sess.handshake_data.server_cert_chain = cert_chain.clone();
  Ok(ConnState::ExpectServerKX)
}

pub static EXPECT_CERTIFICATE: Handler = Handler {
  expect: expect_certificate,
  handle: handle_certificate
};

fn expect_server_kx() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ServerKeyExchange]
  }
}

fn handle_server_kx(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
  let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.handshake_data.ciphersuite.unwrap().kx);
  sess.handshake_data.hash_message(m);

  if maybe_decoded_kx.is_none() {
    return Err(HandshakeError::General("cannot decode server's kx".to_string()));
  }

  let decoded_kx = maybe_decoded_kx.unwrap();

  /* Save the signature and signed parameters for later verification. */
  sess.handshake_data.server_kx_sig = decoded_kx.get_sig();
  decoded_kx.encode_params(&mut sess.handshake_data.server_kx_params);

  match decoded_kx {
    ServerKeyExchangePayload::ECDHE(ecdhe) => info!("ECDHE curve is {:?}", ecdhe.params.curve_params),
    _ => ()
  }

  Ok(ConnState::ExpectServerHelloDone)
}

pub static EXPECT_SERVER_KX: Handler = Handler {
  expect: expect_server_kx,
  handle: handle_server_kx
};

fn expect_server_hello_done() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ServerHelloDone]
  }
}

fn dumphex(label: &str, bytes: &[u8]) {
  print!("{}: ", label);

  for b in bytes {
    print!("{:02x}", b);
  }

  println!("");
}

fn emit_clientkx(sess: &mut ClientSession, kxd: &suites::KeyExchangeResult) {
  let ckx = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ClientKeyExchange,
        payload: HandshakePayload::ClientKeyExchange(kxd.encode_public())
      }
    )
  };

  sess.handshake_data.hash_message(&ckx);
  sess.tls_queue.push_back(ckx);
}

fn emit_ccs(sess: &mut ClientSession) {
  let ccs = Message {
    typ: ContentType::ChangeCipherSpec,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
  };

  sess.tls_queue.push_back(ccs);
}

fn emit_finished(sess: &mut ClientSession) {
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
  let ef = sess.encrypt_outgoing(&f);
  sess.tls_queue.push_back(ef);
}

fn handle_server_hello_done(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  sess.handshake_data.hash_message(m);

  info!("Server cert is {:?}", sess.handshake_data.server_cert_chain);
  info!("Server DNS name is {:?}", sess.handshake_data.dns_name);

  /* 1. Verify the cert chain.
   * 2. Verify that the top certificate signed their kx.
   * 3. Complete the key exchange:
   *    a) generate our kx pair
   *    b) emit a ClientKeyExchange containing it
   *    c) emit a CCS
   *    d) derive the shared keys, and start encryption
   * 4. emit a Finished, our first encrypted message under the new keys. */

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

  /* 3a. */
  let kxd = try!(sess.handshake_data.ciphersuite.as_ref().unwrap()
    .do_client_kx(&sess.handshake_data.server_kx_params)
    .ok_or_else(|| HandshakeError::General("key exchange failed".to_string()))
  );

  /* 3b. */
  emit_clientkx(sess, &kxd);

  /* 3c. */
  emit_ccs(sess);

  /* 3d. Now commit secrets. */
  sess.secrets_current.init(&sess.handshake_data.secrets,
                            sess.handshake_data.ciphersuite.as_ref().unwrap().get_hash(),
                            &kxd.premaster_secret);
  sess.start_encryption();

  /* 4. */
  emit_finished(sess);

  Ok(ConnState::ExpectCCS)
}

pub static EXPECT_SERVER_HELLO_DONE: Handler = Handler {
  expect: expect_server_hello_done,
  handle: handle_server_hello_done
};

/* -- Waiting for their CCS -- */
fn expect_ccs() -> Expectation {
  Expectation {
    content_types: vec![ContentType::ChangeCipherSpec],
    handshake_types: vec![]
  }
}

fn handle_ccs(_sess: &mut ClientSession, _m: &Message) -> Result<ConnState, HandshakeError> {
  /* nb. msgs layer validates trivial contents of CCS */
  Ok(ConnState::ExpectFinished)
}

pub static EXPECT_CCS: Handler = Handler {
  expect: expect_ccs,
  handle: handle_ccs
};

/* -- Waiting for their finished -- */
fn expect_finished() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![] /* we need to decrypt before we can check this */
  }
}

fn handle_finished(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let finished = try!(extract_handshake!(m, HandshakePayload::Finished)
    .ok_or(HandshakeError::General("finished message missing".to_string()))
  );

  /* Work out what verify_data we expect. */
  let vh = sess.handshake_data.get_verify_hash();
  let expect_verify_data = sess.secrets_current.server_verify_data(&vh);

  /* Constant-time verification of this is relatively unimportant: they only
   * get one chance.  But it can't hurt. */
  use ring;
  ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.body)
    .map_err(|_| HandshakeError::DecryptError)
    .unwrap();

  Ok(ConnState::Traffic)
}

pub static EXPECT_FINISHED: Handler = Handler {
  expect: expect_finished,
  handle: handle_finished
};

/* -- Traffic transit state -- */
fn expect_traffic() -> Expectation {
  Expectation {
    content_types: vec![ContentType::ApplicationData],
    handshake_types: Vec::new()
  }
}

fn handle_traffic(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  sess.take_received_plaintext(m.get_opaque_payload().unwrap());
  Ok(ConnState::Traffic)
}

pub static TRAFFIC: Handler = Handler {
  expect: expect_traffic,
  handle: handle_traffic
};
