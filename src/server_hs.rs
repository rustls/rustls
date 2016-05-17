use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::codec::Codec;
use msgs::handshake::{HandshakePayload, default_supported_signature_algorithms};
use msgs::handshake::{HandshakeMessagePayload, ServerHelloPayload, Random};
use server::{ServerSession, ConnState};
use suites;

use std::fmt::{Debug, Formatter};
use std::fmt;

#[derive(Debug)]
pub enum HandshakeError {
  InappropriateMessage { expect_types: Vec<ContentType>, got_type: ContentType },
  InappropriateHandshakeMessage { expect_types: Vec<HandshakeType>, got_type: HandshakeType },
  General(String)
}

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

#[derive(Debug)]
struct Expectation {
  content_types: Vec<ContentType>,
  handshake_types: Vec<HandshakeType>
}

type ExpectFunction = fn() -> Expectation;
type HandleFunction = fn(&mut ServerSession, m: &Message) -> Result<ConnState, HandshakeError>;

/* These are effectively operations on the ServerSession, variant on the
 * connection state. They must not have state of their own -- so they're
 * function points rather than a trait. */
pub struct Handler {
  expect: ExpectFunction,
  handle: HandleFunction
}

fn emit_server_hello(sess: &mut ServerSession) {
  sess.handshake_data.generate_server_random();
  let sessid = sess.config.session_storage.generate();

  let sh = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ServerHello,
        payload: HandshakePayload::ServerHello(
          ServerHelloPayload {
            server_version: ProtocolVersion::TLSv1_2,
            random: Random::from_vec(&sess.handshake_data.server_random),
            session_id: sessid,
            cipher_suite: sess.handshake_data.ciphersuite.unwrap().suite.clone(),
            compression_method: Compression::Null,
            extensions: Vec::new()
          }
        )
      }
    )
  };

  sess.tls_queue.push_back(sh);
}

fn emit_certificate(sess: &mut ServerSession) {
  let cert_chain = sess.handshake_data.server_cert_chain.as_ref().unwrap().clone();

  let c = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::Certificate,
        payload: HandshakePayload::Certificate(cert_chain)
      }
    )
  };

  sess.tls_queue.push_back(c);
}

fn emit_server_kx(sess: &mut ServerSession) {
  println!("emit_server_kx");
}

fn ExpectClientHello_expect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ClientHello]
  }
}

fn ExpectClientHello_handle(sess: &mut ServerSession, m: &Message) -> Result<ConnState, HandshakeError> {
  let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();

  if client_hello.client_version != ProtocolVersion::TLSv1_2 {
    return Err(HandshakeError::General("client does not support TLSv1_2".to_string()));
  }

  if !client_hello.compression_methods.contains(&Compression::Null) {
    return Err(HandshakeError::General("client did not offer Null compression".to_string()));
  }

  let default_sigalgs_ext = default_supported_signature_algorithms();
  let default_eccurves_ext = vec![];
  let default_ecpoints_ext = vec![];

  let sni_ext = client_hello.get_sni_extension();
  let sigalgs_ext = client_hello.get_sigalgs_extension()
    .unwrap_or(&default_sigalgs_ext);
  let eccurves_ext = client_hello.get_eccurves_extension()
    .unwrap_or(&default_eccurves_ext);
  let ecpoints_ext = client_hello.get_ecpoints_extension()
    .unwrap_or(&default_ecpoints_ext);

  println!("we got a clienthello {:?}", client_hello);
  println!("sni {:?}", sni_ext);
  println!("sigalgs {:?}", sigalgs_ext);
  println!("eccurves {:?}", eccurves_ext);
  println!("ecpoints {:?}", ecpoints_ext);

  /* Choose a certificate. */
  let maybe_cert_chain = sess.config.cert_resolver.resolve(sni_ext, sigalgs_ext, eccurves_ext, ecpoints_ext);
  if maybe_cert_chain.is_err() {
    return Err(HandshakeError::General("no server certificate chain resolved".to_string()));
  }
  let cert_chain = maybe_cert_chain.unwrap();

  /* Reduce our supported ciphersuites by the certificate. */
  let ciphersuites_suitable_for_cert = suites::reduce_given_cert(&sess.config.ciphersuites,
                                                                 &cert_chain);
  sess.handshake_data.server_cert_chain = Some(cert_chain);

  let maybe_ciphersuite = if sess.config.ignore_client_order {
    suites::choose_ciphersuite_preferring_server(&client_hello.cipher_suites,
                                                 &ciphersuites_suitable_for_cert)
  } else {
    suites::choose_ciphersuite_preferring_client(&client_hello.cipher_suites,
                                                 &ciphersuites_suitable_for_cert)
  };

  if maybe_ciphersuite.is_none() {
    return Err(HandshakeError::General("no ciphersuites in common".to_string()));
  }

  sess.handshake_data.ciphersuite = maybe_ciphersuite;
  client_hello.random.encode(&mut sess.handshake_data.client_random);

  emit_server_hello(sess);
  emit_certificate(sess);
  emit_server_kx(sess);

  Ok(ConnState::ExpectClientKX)
}

pub static ExpectClientHello: Handler = Handler {
  expect: ExpectClientHello_expect,
  handle: ExpectClientHello_handle
};

fn ExpectClientKX_expect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ClientKeyExchange]
  }
}

fn ExpectClientKX_handle(sess: &mut ServerSession, m: &Message) -> Result<ConnState, HandshakeError> {
  Err(HandshakeError::General("ExpectClientKeyExchange nyi".to_string()))
}

pub static ExpectClientKX: Handler = Handler {
  expect: ExpectClientKX_expect,
  handle: ExpectClientKX_handle
};

fn InvalidState_expect() -> Expectation {
  Expectation {
    content_types: Vec::new(),
    handshake_types: Vec::new()
  }
}

fn InvalidState_handle(sess: &mut ServerSession, m: &Message) -> Result<ConnState, HandshakeError> {
  Err(HandshakeError::General("bad state".to_string()))
}

pub static InvalidState: Handler = Handler {
  expect: InvalidState_expect,
  handle: InvalidState_handle
};

pub fn process_message(handler: &Handler, sess: &mut ServerSession, m: &Message) -> Result<ConnState, HandshakeError> {
  (handler.handle)(sess, m)
}

pub fn check_message(handler: &Handler, m: &Message) -> Result<(), HandshakeError> {
  let expect = (handler.expect)();

  if !expect.content_types.contains(&m.typ) {
    return Err(HandshakeError::InappropriateMessage {
      expect_types: expect.content_types,
      got_type: m.typ.clone()
    });
  }

  if let MessagePayload::Handshake(ref hsp) = m.payload {
    if !expect.handshake_types.contains(&hsp.typ) {
      return Err(HandshakeError::InappropriateHandshakeMessage {
        expect_types: expect.handshake_types,
        got_type: hsp.typ.clone()
      });
    }
  }

  Ok(())
}

