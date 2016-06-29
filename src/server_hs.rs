use msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use msgs::enums::{Compression, NamedCurve, ECPointFormat};
use msgs::enums::{AlertLevel, AlertDescription};
use msgs::alert::AlertMessagePayload;
use msgs::message::{Message, MessagePayload};
use msgs::base::Payload;
use msgs::handshake::{HandshakePayload, SupportedSignatureAlgorithms};
use msgs::handshake::{HandshakeMessagePayload, ServerHelloPayload, Random};
use msgs::handshake::SignatureAndHashAlgorithm;
use msgs::handshake::{EllipticCurveList, SupportedCurves};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ServerECDHParams, DigitallySignedStruct};
use msgs::handshake::{ServerKeyExchangePayload, ECDHEServerKeyExchange};
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::codec::Codec;
use server::{ServerSessionImpl, ConnState};
use suites;
use sign;
use error::TLSError;
use handshake::Expectation;

use std::sync::Arc;
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

pub type HandleFunction = fn(&mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError>;

/* These are effectively operations on the ServerSessionImpl, variant on the
 * connection state. They must not have state of their own -- so they're
 * functions rather than a trait. */
pub struct Handler {
  pub expect: Expectation,
  pub handle: HandleFunction
}

fn emit_server_hello(sess: &mut ServerSessionImpl) {
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

  debug!("sending server hello {:?}", sh);
  sess.handshake_data.hash_message(&sh);
  sess.common.send_msg(&sh, false);
}

fn emit_certificate(sess: &mut ServerSessionImpl) {
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

  sess.handshake_data.hash_message(&c);
  sess.common.send_msg(&c, false);
}

fn emit_server_kx(sess: &mut ServerSessionImpl,
                  sigalg: &SignatureAndHashAlgorithm,
                  curve: &NamedCurve,
                  signer: Arc<Box<sign::Signer>>) -> Result<(), TLSError> {
  let kx = {
    let scs = sess.handshake_data.ciphersuite.as_ref().unwrap();
    scs.start_server_kx(curve)
  };
  let secdh = ServerECDHParams::new(curve, &kx.pubkey);

  let mut msg = Vec::new();
  msg.extend(&sess.handshake_data.secrets.client_random);
  msg.extend(&sess.handshake_data.secrets.server_random);
  secdh.encode(&mut msg);

  let sig = try!(
    signer.sign(&sigalg.hash, &msg)
    .map_err(|_| TLSError::General("signing failed".to_string()))
  );

  let skx = ServerKeyExchangePayload::ECDHE(
    ECDHEServerKeyExchange {
      params: secdh,
      dss: DigitallySignedStruct::new(sigalg, sig)
    }
  );

  let m = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ServerKeyExchange,
        payload: HandshakePayload::ServerKeyExchange(skx)
      }
    )
  };

  sess.handshake_data.kx_data = Some(kx);
  sess.handshake_data.hash_message(&m);
  sess.common.send_msg(&m, false);
  Ok(())
}

fn emit_server_hello_done(sess: &mut ServerSessionImpl) {
  let m = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::ServerHelloDone,
        payload: HandshakePayload::ServerHelloDone
      }
    )
  };

  sess.handshake_data.hash_message(&m);
  sess.common.send_msg(&m, false);
}

fn handle_client_hello(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();

  if client_hello.client_version != ProtocolVersion::TLSv1_2 {
    return Err(TLSError::General("client does not support TLSv1_2".to_string()));
  }

  if !client_hello.compression_methods.contains(&Compression::Null) {
    return Err(TLSError::General("client did not offer Null compression".to_string()));
  }

  /* Save their Random. */
  client_hello.random.write_slice(&mut sess.handshake_data.secrets.client_random);

  let default_sigalgs_ext = SupportedSignatureAlgorithms::default();

  let sni_ext = client_hello.get_sni_extension();
  let sigalgs_ext = client_hello.get_sigalgs_extension()
    .unwrap_or(&default_sigalgs_ext);
  let eccurves_ext = try!(client_hello.get_eccurves_extension()
                          .ok_or(TLSError::General("client didn't describe ec curves".to_string())));
  let ecpoints_ext = try!(client_hello.get_ecpoints_extension()
                          .ok_or(TLSError::General("client didn't describe ec points".to_string())));

  debug!("we got a clienthello {:?}", client_hello);
  debug!("sni {:?}", sni_ext);
  debug!("sigalgs {:?}", sigalgs_ext);
  debug!("eccurves {:?}", eccurves_ext);
  debug!("ecpoints {:?}", ecpoints_ext);

  if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
    return Err(TLSError::General("client didn't support uncompressed ec points".to_string()));
  }

  /* Choose a certificate. */
  let maybe_cert_key = sess.config.cert_resolver.resolve(sni_ext, sigalgs_ext, eccurves_ext, ecpoints_ext);
  if maybe_cert_key.is_err() {
    return Err(TLSError::General("no server certificate chain resolved".to_string()));
  }
  let (cert_chain, private_key) = maybe_cert_key.unwrap();

  /* Reduce our supported ciphersuites by the certificate. */
  let ciphersuites_suitable_for_cert = suites::reduce_given_sigalg(&sess.config.ciphersuites,
                                                                   &private_key.algorithm());
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
  info!("decided upon suite {:?}", maybe_ciphersuite.as_ref().unwrap());

  /* Start handshake hash. */
  sess.handshake_data.start_handshake_hash();
  sess.handshake_data.hash_message(m);

  /* Now we have chosen a ciphersuite, we can make kx decisions. */
  let sigalg = try!(
    sess.handshake_data.ciphersuite.as_ref().unwrap()
      .resolve_sig_alg(sigalgs_ext)
      .ok_or_else(|| TLSError::General("no supported sigalg".to_string()))
  );
  let eccurve = try!(
    EllipticCurveList::supported()
      .first_appearing_in(eccurves_ext)
      .ok_or_else(|| TLSError::General("no supported curve".to_string()))
  );
  let ecpoint = try!(
    ECPointFormatList::supported()
      .first_appearing_in(ecpoints_ext)
      .ok_or_else(|| TLSError::General("no supported point format".to_string()))
  );

  assert_eq!(ecpoint, ECPointFormat::Uncompressed);

  emit_server_hello(sess);
  emit_certificate(sess);
  try!(emit_server_kx(sess, &sigalg, &eccurve, private_key));
  emit_server_hello_done(sess);

  Ok(ConnState::ExpectClientKX)
}

pub static EXPECT_CLIENT_HELLO: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientHello]
  },
  handle: handle_client_hello
};

fn handle_client_kx(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let client_kx = extract_handshake!(m, HandshakePayload::ClientKeyExchange).unwrap();
  sess.handshake_data.hash_message(m);

  /* Complete key agreement, and set up encryption with the
   * resulting premaster secret. */
  let kx = mem::replace(&mut sess.handshake_data.kx_data, None).unwrap();
  let kxd = try!(
    kx.server_complete(&client_kx.body)
    .ok_or_else(|| TLSError::General("kx failed".to_string()))
  );

  sess.secrets_current.init(&sess.handshake_data.secrets,
                            sess.handshake_data.ciphersuite.as_ref().unwrap().get_hash(),
                            &kxd.premaster_secret);
  sess.start_encryption();
  Ok(ConnState::ExpectCCS)
}

pub static EXPECT_CLIENT_KX: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientKeyExchange]
  },
  handle: handle_client_kx
};

/* --- Process client's ChangeCipherSpec --- */
fn handle_ccs(_sess: &mut ServerSessionImpl, _m: &Message) -> Result<ConnState, TLSError> {
  Ok(ConnState::ExpectFinished)
}

pub static EXPECT_CCS: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::ChangeCipherSpec],
    handshake_types: &[]
  },
  handle: handle_ccs
};

/* --- Process client's Finished --- */
fn emit_ccs(sess: &mut ServerSessionImpl) {
  let m = Message {
    typ: ContentType::ChangeCipherSpec,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {})
  };

  sess.common.send_msg(&m, false);
}

fn emit_finished(sess: &mut ServerSessionImpl) {
  let vh = sess.handshake_data.get_verify_hash();
  let verify_data = sess.secrets_current.server_verify_data(&vh);
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

  sess.common.send_msg(&f, true);
}

fn handle_finished(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

  let vh = sess.handshake_data.get_verify_hash();
  let expect_verify_data = sess.secrets_current.client_verify_data(&vh);

  use ring;
  try!(
    ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.body)
      .map_err(|_| { error!("Finished wrong"); TLSError::DecryptError })
  );

  sess.handshake_data.hash_message(m);
  emit_ccs(sess);
  emit_finished(sess);
  Ok(ConnState::Traffic)
}

pub static EXPECT_FINISHED: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::Finished]
  },
  handle: handle_finished
};

/* --- Process traffic --- */
fn handle_traffic(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
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

/* --- Send a close_notify --- */
pub fn emit_close_notify(sess: &mut ServerSessionImpl) {
  info!("Sending close_notify");
  let m = Message {
    typ: ContentType::Alert,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Alert(
      AlertMessagePayload {
        level: AlertLevel::Warning,
        description: AlertDescription::CloseNotify
      }
    )
  };
  sess.common.send_msg(&m, true);
}
