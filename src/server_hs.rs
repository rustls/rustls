use msgs::enums::{ContentType, HandshakeType};
use msgs::message::{Message, MessagePayload};
use msgs::handshake::{HandshakePayload};

use std::fmt;

#[derive(Debug)]
enum HandshakeError {
  InappropriateMessage { expect_types: Vec<ContentType>, got_type: ContentType },
  InappropriateHandshakeMessage { expect_types: Vec<HandshakeType>, got_type: HandshakeType },
  General(String)
}

#[derive(Debug, Clone)]
enum State {
  AwaitClientHello,
}

#[derive(Debug)]
struct Expectation {
  content_types: Vec<ContentType>,
  handshake_types: Vec<HandshakeType>
}

fn AwaitClientHelloExpect() -> Expectation {
  Expectation {
    content_types: vec![ContentType::Handshake],
    handshake_types: vec![HandshakeType::ClientHello]
  }
}

fn ProcessClientHello(m: &Message) -> Result<Option<HandshakeState>, HandshakeError> {
  if let MessagePayload::Handshake(ref hsp) = m.payload {
    print!("we got a handshake {:?}", hsp);

    if let HandshakePayload::ClientHello(ref ch) = hsp.payload {
      print!("we got a clienthello {:?}", ch);
    }
  }

  Ok(None)
}

pub struct HandshakeState  {
  state: State,
  expect_next: fn() -> Expectation,
  process: fn(m: &Message) -> Result<Option<HandshakeState>, HandshakeError>
}

impl fmt::Debug for HandshakeState {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("HandshakeState")
     .field("state", &self.state)
     .field("expect_next", &(self.expect_next)())
     .finish()
  }
}

/* Is this message interesting handshake-wise? */
fn interesting_p(m: &Message) -> bool {
  (m.is_content_type(ContentType::Handshake) ||
   m.is_content_type(ContentType::ChangeCipherSpec))
}

impl HandshakeState {
  pub fn new() -> HandshakeState {
    HandshakeState {
      state: State::AwaitClientHello,
      expect_next: AwaitClientHelloExpect,
      process: ProcessClientHello
    }
  }

  pub fn process_message(&self, m: &Message) -> Result<Option<HandshakeState>, HandshakeError> {
    if !interesting_p(m) {
      return Ok(None);
    }

    try!(self.check_appropriate(m));
    (self.process)(m)
  }

  fn check_appropriate(&self, m: &Message) -> Result<(), HandshakeError> {
    let expect = (self.expect_next)();

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

