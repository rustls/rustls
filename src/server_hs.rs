use msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
use msgs::enums::{Compression, NamedCurve, ECPointFormat, CipherSuite};
use msgs::enums::{ExtensionType, AlertDescription};
use msgs::enums::ClientCertificateType;
use msgs::message::{Message, MessagePayload};
use msgs::base::Payload;
use msgs::handshake::{HandshakePayload, SupportedSignatureAlgorithms};
use msgs::handshake::{HandshakeMessagePayload, ServerHelloPayload, Random};
use msgs::handshake::{ClientHelloPayload, ServerExtension};
use msgs::handshake::ConvertProtocolNameList;
use msgs::handshake::SignatureAndHashAlgorithm;
use msgs::handshake::{EllipticCurveList, SupportedCurves};
use msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use msgs::handshake::{ServerECDHParams, DigitallySignedStruct};
use msgs::handshake::{ServerKeyExchangePayload, ECDHEServerKeyExchange};
use msgs::handshake::CertificateRequestPayload;
use msgs::handshake::SupportedMandatedSignatureAlgorithms;
use msgs::ccs::ChangeCipherSpecPayload;
use msgs::codec::Codec;
use server::{ServerSessionImpl, ConnState};
use suites;
use sign;
use verify;
use util;
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

fn process_extensions(sess: &mut ServerSessionImpl, hello: &ClientHelloPayload) -> Vec<ServerExtension> {
  let mut ret = Vec::new();

  /* ALPN */
  let our_protocols = &sess.config.alpn_protocols;
  let maybe_their_protocols = hello.get_alpn_extension();
  if let Some(their_protocols) = maybe_their_protocols {
    sess.alpn_protocol = util::first_in_both(&our_protocols, &their_protocols.to_strings());
    match sess.alpn_protocol {
      Some(ref selected_protocol) => {
        info!("Chosen ALPN protocol {:?}", selected_protocol);
        ret.push(ServerExtension::make_alpn(selected_protocol.clone()))
      },
      _ => {}
    };
  }

  /* Renegotiation.
   * (We don't do reneg at all, but would support the secure version if we did.) */
  let secure_reneg_offered =
    hello.find_extension(ExtensionType::RenegotiationInfo).is_some() ||
    hello.cipher_suites.contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

  if secure_reneg_offered {
    ret.push(ServerExtension::make_empty_renegotiation_info());
  }

  ret
}

fn emit_server_hello(sess: &mut ServerSessionImpl, hello: &ClientHelloPayload) {
  sess.handshake_data.generate_server_random();
  let sessid = sess.config.session_storage.generate();
  let extensions = process_extensions(sess, hello);

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
            extensions: extensions
          }
        )
      }
    )
  };

  debug!("sending server hello {:?}", sh);
  sess.handshake_data.transcript.add_message(&sh);
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

  sess.handshake_data.transcript.add_message(&c);
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
  sess.handshake_data.transcript.add_message(&m);
  sess.common.send_msg(&m, false);
  Ok(())
}

fn emit_certificate_req(sess: &mut ServerSessionImpl) {
  if sess.config.client_auth_roots.len() == 0 {
    return;
  }

  let names = sess.config.client_auth_roots.get_subjects();

  let cr = CertificateRequestPayload {
    certtypes: vec![ ClientCertificateType::RSASign ],
    sigalgs: SupportedSignatureAlgorithms::supported(),
    canames: names
  };

  let m = Message {
    typ: ContentType::Handshake,
    version: ProtocolVersion::TLSv1_2,
    payload: MessagePayload::Handshake(
      HandshakeMessagePayload {
        typ: HandshakeType::CertificateRequest,
        payload: HandshakePayload::CertificateRequest(cr)
      }
    )
  };

  debug!("Sending CertificateRequest {:?}", m);
  sess.handshake_data.transcript.add_message(&m);
  sess.common.send_msg(&m, false);
  sess.handshake_data.doing_client_auth = true;
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

  sess.handshake_data.transcript.add_message(&m);
  sess.common.send_msg(&m, false);
}

fn hsfail(sess: &mut ServerSessionImpl, why: &str) -> TLSError {
  sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
  TLSError::General(why.to_string())
}

fn handle_client_hello(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();

  if client_hello.client_version.get_u16() < ProtocolVersion::TLSv1_2.get_u16() {
    sess.common.send_fatal_alert(AlertDescription::ProtocolVersion);
    return Err(TLSError::General("client does not support TLSv1_2".to_string()));
  }

  if !client_hello.compression_methods.contains(&Compression::Null) {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    return Err(TLSError::General("client did not offer Null compression".to_string()));
  }

  /* Save their Random. */
  client_hello.random.write_slice(&mut sess.handshake_data.secrets.client_random);

  let default_sigalgs_ext = SupportedSignatureAlgorithms::default();

  let sni_ext = client_hello.get_sni_extension();
  let sigalgs_ext = client_hello.get_sigalgs_extension()
    .unwrap_or(&default_sigalgs_ext);
  let eccurves_ext = try!(client_hello.get_eccurves_extension()
                          .ok_or_else(|| hsfail(sess, "client didn't describe ec curves")));
  let ecpoints_ext = try!(client_hello.get_ecpoints_extension()
                          .ok_or_else(|| hsfail(sess, "client didn't describe ec points")));

  debug!("we got a clienthello {:?}", client_hello);
  debug!("sni {:?}", sni_ext);
  debug!("sigalgs {:?}", sigalgs_ext);
  debug!("eccurves {:?}", eccurves_ext);
  debug!("ecpoints {:?}", ecpoints_ext);

  if !ecpoints_ext.contains(&ECPointFormat::Uncompressed) {
    sess.common.send_fatal_alert(AlertDescription::IllegalParameter);
    return Err(TLSError::General("client didn't support uncompressed ec points".to_string()));
  }

  /* Choose a certificate. */
  let maybe_cert_key = sess.config.cert_resolver.resolve(sni_ext, sigalgs_ext, eccurves_ext, ecpoints_ext);
  if maybe_cert_key.is_err() {
    sess.common.send_fatal_alert(AlertDescription::AccessDenied);
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
    sess.common.send_fatal_alert(AlertDescription::HandshakeFailure);
    return Err(TLSError::General("no ciphersuites in common".to_string()));
  }

  sess.handshake_data.ciphersuite = maybe_ciphersuite;
  info!("decided upon suite {:?}", maybe_ciphersuite.as_ref().unwrap());

  /* Start handshake hash. */
  sess.handshake_data.start_handshake_hash();
  sess.handshake_data.transcript.add_message(m);

  /* Now we have chosen a ciphersuite, we can make kx decisions. */
  let sigalg = try!(
    sess.handshake_data.ciphersuite.as_ref().unwrap()
      .resolve_sig_alg(sigalgs_ext)
      .ok_or_else(|| hsfail(sess, "no supported sigalg"))
  );
  let eccurve = try!(
    util::first_in_both(EllipticCurveList::supported().as_slice(),
                        eccurves_ext.as_slice())
      .ok_or_else(|| hsfail(sess, "no supported curve"))
  );
  let ecpoint = try!(
    util::first_in_both(ECPointFormatList::supported().as_slice(),
                        ecpoints_ext.as_slice())
      .ok_or_else(|| hsfail(sess, "no supported point format"))
  );

  assert_eq!(ecpoint, ECPointFormat::Uncompressed);

  emit_server_hello(sess, client_hello);
  emit_certificate(sess);
  try!(emit_server_kx(sess, &sigalg, &eccurve, private_key));
  emit_certificate_req(sess);
  emit_server_hello_done(sess);

  if sess.handshake_data.doing_client_auth {
    Ok(ConnState::ExpectCertificate)
  } else {
    Ok(ConnState::ExpectClientKX)
  }
}

pub static EXPECT_CLIENT_HELLO: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientHello]
  },
  handle: handle_client_hello
};

/* --- Process client's Certificate for client auth --- */
fn handle_certificate(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  sess.handshake_data.transcript.add_message(m);
  let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();

  if cert_chain.len() == 0 && !sess.config.client_auth_mandatory {
    info!("client auth requested but no certificate supplied");
    sess.handshake_data.doing_client_auth = false;
    sess.handshake_data.transcript.abandon_client_auth();
    return Ok(ConnState::ExpectClientKX);
  }

  debug!("certs {:?}", cert_chain);

  try!(
    verify::verify_client_cert(&sess.config.client_auth_roots,
                               &cert_chain)
  );

  sess.handshake_data.valid_client_cert_chain = Some(cert_chain.clone());
  Ok(ConnState::ExpectClientKX)
}

pub static EXPECT_CERTIFICATE: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::Certificate]
  },
  handle: handle_certificate
};

/* --- Process client's KeyExchange --- */
fn handle_client_kx(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let client_kx = extract_handshake!(m, HandshakePayload::ClientKeyExchange).unwrap();
  sess.handshake_data.transcript.add_message(m);

  /* Complete key agreement, and set up encryption with the
   * resulting premaster secret. */
  let kx = mem::replace(&mut sess.handshake_data.kx_data, None).unwrap();
  let kxd = try!(
    kx.server_complete(&client_kx.0)
    .ok_or_else(|| hsfail(sess, "kx failed"))
  );

  sess.secrets_current.init(&sess.handshake_data.secrets,
                            sess.handshake_data.ciphersuite.as_ref().unwrap().get_hash(),
                            &kxd.premaster_secret);

  if sess.handshake_data.doing_client_auth {
    Ok(ConnState::ExpectCertificateVerify)
  } else {
    Ok(ConnState::ExpectCCS)
  }
}

pub static EXPECT_CLIENT_KX: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::ClientKeyExchange]
  },
  handle: handle_client_kx
};

/* --- Process client's certificate proof --- */
fn handle_certificate_verify(sess: &mut ServerSessionImpl, m: &Message) -> Result<ConnState, TLSError> {
  let rc = {
    let sig = extract_handshake!(m, HandshakePayload::CertificateVerify).unwrap();
    let certs = sess.handshake_data.valid_client_cert_chain.as_ref().unwrap();
    let handshake_msgs = sess.handshake_data.transcript.take_handshake_buf();

    verify::verify_signed_struct(&handshake_msgs, &certs[0], &sig)
  };

  if rc.is_err() {
    hsfail(sess, "invalid client certverify");
    return Err(rc.unwrap_err());
  } else {
    debug!("client CertificateVerify OK");
  }

  sess.handshake_data.transcript.add_message(m);
  Ok(ConnState::ExpectCCS)
}

pub static EXPECT_CERTIFICATE_VERIFY: Handler = Handler {
  expect: Expectation {
    content_types: &[ContentType::Handshake],
    handshake_types: &[HandshakeType::CertificateVerify]
  },
  handle: handle_certificate_verify
};

/* --- Process client's ChangeCipherSpec --- */
fn handle_ccs(sess: &mut ServerSessionImpl, _m: &Message) -> Result<ConnState, TLSError> {
  sess.start_encryption();
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
  let vh = sess.handshake_data.transcript.get_current_hash();
  let verify_data = sess.secrets_current.server_verify_data(&vh);
  let verify_data_payload = Payload::new(verify_data);

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

  let vh = sess.handshake_data.transcript.get_current_hash();
  let expect_verify_data = sess.secrets_current.client_verify_data(&vh);

  use ring;
  try!(
    ring::constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
      .map_err(|_| { error!("Finished wrong"); TLSError::DecryptError })
  );

  sess.handshake_data.transcript.add_message(m);
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
