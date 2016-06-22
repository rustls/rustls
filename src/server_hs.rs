use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::handshake::{HandshakePayload, SupportedSignatureAlgorithms};
use msgs::handshake::{HandshakeMessagePayload, ServerHelloPayload, Random};
use server::{ServerSession, ConnState};
use suites;
use error::TLSError;
use handshake::Expectation;

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

pub type HandleFunction = fn(&mut ServerSession, m: &Message) -> Result<ConnState, TLSError>;

/* These are effectively operations on the ServerSession, variant on the
 * connection state. They must not have state of their own -- so they're
 * functions rather than a trait. */
pub struct Handler {
  pub expect: Expectation,
  pub handle: HandleFunction
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
            random: Random::from_slice(&sess.handshake_data.secrets.server_random),
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

fn emit_server_kx(_sess: &mut ServerSession) {
  println!("emit_server_kx");
}

fn handle_client_hello(sess: &mut ServerSession, m: &Message) -> Result<ConnState, TLSError> {
  let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();

  if client_hello.client_version != ProtocolVersion::TLSv1_2 {
    return Err(TLSError::General("client does not support TLSv1_2".to_string()));
  }

  if !client_hello.compression_methods.contains(&Compression::Null) {
    return Err(TLSError::General("client did not offer Null compression".to_string()));
  }

  let default_sigalgs_ext = SupportedSignatureAlgorithms::default();
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
    return Err(TLSError::General("no server certificate chain resolved".to_string()));
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
    return Err(TLSError::General("no ciphersuites in common".to_string()));
  }

  sess.handshake_data.ciphersuite = maybe_ciphersuite;
  client_hello.random.write_slice(&mut sess.handshake_data.secrets.client_random);

  emit_server_hello(sess);
  emit_certificate(sess);
  emit_server_kx(sess);

  Ok(ConnState::ExpectClientKX)
}

pub static EXPECT_CLIENT_HELLO: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientHello]
  },
  handle: handle_client_hello
};

fn handle_client_kx(_sess: &mut ServerSession, _m: &Message) -> Result<ConnState, TLSError> {
  Err(TLSError::General("ExpectClientKeyExchange nyi".to_string()))
}

pub static EXPECT_CLIENT_KX: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientKeyExchange]
  },
  handle: handle_client_kx
};

fn handle_invalid(_sess: &mut ServerSession, _m: &Message) -> Result<ConnState, TLSError> {
  Err(TLSError::General("bad state".to_string()))
}

pub static INVALID_STATE: Handler = Handler {
  expect: Expectation {
    content_types: &[],
    handshake_types: &[]
  },
  handle: handle_invalid
};

