use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::codec::Codec;
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload, ClientHelloPayload};
use msgs::handshake::{SessionID, Random};
use msgs::handshake::ClientExtension;
use msgs::handshake::{SupportedSignatureAlgorithms, SupportedMandatedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, SupportedCurves};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
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
  exts.push(ClientExtension::ECPointFormats(ECPointFormatList::supported()));
  exts.push(ClientExtension::EllipticCurves(EllipticCurveList::supported()));
  exts.push(ClientExtension::SignatureAlgorithms(SupportedSignatureAlgorithms::supported()));
  sess.add_extensions(&mut exts);

  let sh = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(
          ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from_vec(&sess.handshake_data.client_random),
            session_id: SessionID::empty(),
            cipher_suites: sess.get_cipher_suites(),
            compression_methods: vec![Compression::Null],
            extensions: exts
          }
        )
      }
    )
  };

  sh.payload.encode(&mut sess.handshake_data.client_hello);
  sess.tls_queue.push_back(sh);
}

fn ExpectServerHello_expect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ServerHello]
  }
}

fn ExpectServerHello_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let server_hello = extract_handshake!(m, HandshakePayload::ServerHello).unwrap();

  println!("we have server hello {:?}", server_hello);

  if server_hello.server_version != ProtocolVersion::TLSv1_2 {
    return Err(HandshakeError::General("server does not support TLSv1_2".to_string()));
  }

  if server_hello.compression_method != Compression::Null {
    return Err(HandshakeError::General("server chose non-Null compression".to_string()));
  }

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
  server_hello.random.encode(&mut sess.handshake_data.server_random);

  Ok(ConnState::ExpectCertificate)
}

pub static ExpectServerHello: Handler = Handler {
  expect: ExpectServerHello_expect,
  handle: ExpectServerHello_handle
};

fn ExpectCertificate_expect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::Certificate]
  }
}

fn ExpectCertificate_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
  sess.handshake_data.hash_message(m);
  sess.handshake_data.server_cert_chain = cert_chain.clone();
  println!("we have server cert {:?}", cert_chain);
  Ok(ConnState::ExpectServerKX)
}

pub static ExpectCertificate: Handler = Handler {
  expect: ExpectCertificate_expect,
  handle: ExpectCertificate_handle
};

fn ExpectServerKX_expect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ServerKeyExchange]
  }
}

fn ExpectServerKX_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
  let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.handshake_data.ciphersuite.unwrap().kx);
  sess.handshake_data.hash_message(m);

  if maybe_decoded_kx.is_none() {
    return Err(HandshakeError::General("cannot decode server's kx".to_string()));
  }

  let decoded_kx = maybe_decoded_kx.unwrap();
  println!("we have serverkx {:?}", decoded_kx);

  /* Save the signature and signed parameters for later verification. */
  sess.handshake_data.server_kx_sig = decoded_kx.get_sig();
  decoded_kx.encode_params(&mut sess.handshake_data.server_kx_params);

  Ok(ConnState::ExpectServerHelloDone)
}

pub static ExpectServerKX: Handler = Handler {
  expect: ExpectServerKX_expect,
  handle: ExpectServerKX_handle
};

fn ExpectServerHelloDone_expect() -> Expectation {
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

  println!("sending ckx {:?}", ckx);

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
  let verify_data = sess.handshake_data.get_verify_data();
  let mut f = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::Finished,
        payload: HandshakePayload::Finished(verify_data)
      }
    )
  };

  sess.handshake_data.hash_message(&f);
  //sess.encrypt_outgoing(&mut f);
  sess.tls_queue.push_back(f);
}

fn ExpectServerHelloDone_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  println!("we have serverhellodone");
  sess.handshake_data.hash_message(m);

  /* 1. Verify the cert chain.
   * 2. Verify that the top certificate signed their kx.
   * 3. Complete the key exchange:
   *    a) generate our kx pair
   *    b) emit a ClientKeyExchange containing it
   *    c) derive the resulting keys, emit a CCS and Finished. */

  /* 1. */
  try!(verify::verify_cert(&sess.config.root_store,
                           &sess.handshake_data.server_cert_chain,
                           &sess.handshake_data.dns_name));

  /* 2. */
  /* Build up the contents of the signed message.
   * It's ClientHello.random || ServerHello.random || ServerKeyExchange.params */
  let mut message = Vec::new();
  assert_eq!(sess.handshake_data.client_random.len(), 32);
  assert_eq!(sess.handshake_data.server_random.len(), 32);
  message.extend_from_slice(&sess.handshake_data.client_random);
  message.extend_from_slice(&sess.handshake_data.server_random);
  message.extend_from_slice(&sess.handshake_data.server_kx_params);

  dumphex("verify message", &message);
  dumphex("verify sig", &sess.handshake_data.server_kx_sig.as_ref().unwrap().sig.body);
  
  try!(verify::verify_kx(&message,
                         &sess.handshake_data.server_cert_chain[0],
                         sess.handshake_data.server_kx_sig.as_ref().unwrap()));

  /* 3. */
  let kxd = try!(sess.handshake_data.ciphersuite.as_ref().unwrap()
    .do_client_kx(&sess.handshake_data.server_kx_params)
    .ok_or_else(|| HandshakeError::General("key exchange failed".to_string()))
  );

  //sess.handshake_data.secrets.init_with_pms(&kxd.premaster_secret);

  emit_clientkx(sess, &kxd);
  emit_ccs(sess);
  emit_finished(sess);

  Ok(ConnState::ExpectCCS)
}

pub static ExpectServerHelloDone: Handler = Handler {
  expect: ExpectServerHelloDone_expect,
  handle: ExpectServerHelloDone_handle
};

/* -- Generic invalid state -- */
fn InvalidState_expect() -> Expectation {
  Expectation {
    content_types: Vec::new(),
    handshake_types: Vec::new()
  }
}

fn InvalidState_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  Err(HandshakeError::General("bad state".to_string()))
}

pub static InvalidState: Handler = Handler {
  expect: InvalidState_expect,
  handle: InvalidState_handle
};

