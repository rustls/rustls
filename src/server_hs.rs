use msgs::enums::{ContentType, HandshakeType};
use msgs::enums::{Compression, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::handshake::{HandshakePayload, SupportedSignatureAlgorithms_default};
use server::ServerSession;

use std::fmt::{Debug, Formatter};
use std::fmt;

#[derive(Debug)]
enum HandshakeError {
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

trait Handler : Debug {
  fn expect(&self) -> Expectation;
  fn handle(&self, sess: &mut ServerSession, m: &Message) -> Result<Option<Box<Handler>>, HandshakeError>;
}

#[derive(Debug)]
struct ExpectClientHello {}

impl Handler for ExpectClientHello {
  fn expect(&self) -> Expectation {
    Expectation {
      content_types: vec![ContentType::Handshake],
      handshake_types: vec![HandshakeType::ClientHello]
    }
  }

  fn handle(&self, sess: &mut ServerSession, m: &Message) -> Result<Option<Box<Handler>>, HandshakeError> {
    let client_hello = extract_handshake!(m, HandshakePayload::ClientHello).unwrap();

    if client_hello.client_version != ProtocolVersion::TLSv1_2 {
      return Err(HandshakeError::General("client does not support TLSv1_2".to_string()));
    }

    if !client_hello.compression_methods.contains(&Compression::Null) {
      return Err(HandshakeError::General("client did not offer Null compression".to_string()));
    }

    let default_sigalgs_ext = SupportedSignatureAlgorithms_default();
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

    let cert_chain = sess.config.cert_resolver.resolve(sni_ext, sigalgs_ext, eccurves_ext, ecpoints_ext);
    if cert_chain.is_err() {
      return Err(HandshakeError::General("no server certificate resolved".to_string()));
    }

    Ok(None)
  }
}

pub struct HandshakeState<'a> {
  handler: Box<Handler>,
  session: &'a mut ServerSession
}

impl<'a> Debug for HandshakeState<'a> {
  fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
    fmt.debug_struct("HandshakeState")
       .field("handler", &self.handler)
       .finish()
  }
}

/* Is this message interesting handshake-wise? */
fn interesting_p(m: &Message) -> bool {
  (m.is_content_type(ContentType::Handshake) ||
   m.is_content_type(ContentType::ChangeCipherSpec))
}

impl<'a> HandshakeState<'a> {
  pub fn new(session: &'a mut ServerSession) -> HandshakeState<'a> {
    HandshakeState { handler: Box::new(ExpectClientHello {}), session: session }
  }

  pub fn process_message(&mut self, m: &Message) -> Result<(), HandshakeError> {
    if !interesting_p(m) {
      return Ok(());
    }

    try!(self.check_appropriate(m));

    let maybe_new_handler = try!(self.handler.handle(self.session, m));
    if let Some(new_handler) = maybe_new_handler {
      self.handler = new_handler;
    }

    Ok(())
  }

  fn check_appropriate(&self, m: &Message) -> Result<(), HandshakeError> {
    let expect = self.handler.expect();

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
}

