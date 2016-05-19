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
use client::{ClientSession, ConnState};
use suites;
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

pub fn send_client_hello(sess: &mut ClientSession) {
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

  if !sess.handshake_data.init_with_cs(scs.unwrap()) {
    return Err(HandshakeError::General("failed to init our ciphersuite data".to_string()));
  }

  /* TODO: we can send a ClientKeyExchange now */

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
  sess.handshake_data.server_cert_chain = Some(cert_chain.clone());
  println!("we have server cert {:?}", cert_chain);
  /* TODO: verify cert here, extract subject pubkey */
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
  let kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();

  println!("we have serverkx {:?}", kx);
  /* TODO: check signature by subject pubkey on this struct */
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

fn ExpectServerHelloDone_handle(sess: &mut ClientSession, m: &Message) -> Result<ConnState, HandshakeError> {
  println!("we have serverhellodone");
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

