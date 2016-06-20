use msgs::enums::{ContentType, HandshakeType};
use msgs::message::{Message, MessagePayload};
use error::TLSError;

#[derive(Debug)]
pub struct Expectation {
  pub content_types: Vec<ContentType>,
  pub handshake_types: Vec<HandshakeType>
}

impl Expectation {
  pub fn check_message(&self, m: &Message) -> Result<(), TLSError> {
    if !self.content_types.contains(&m.typ) {
      return Err(TLSError::InappropriateMessage {
        expect_types: self.content_types.clone(),
        got_type: m.typ.clone()
      });
    }

    if let MessagePayload::Handshake(ref hsp) = m.payload {
      if self.handshake_types.len() > 0
        && !self.handshake_types.contains(&hsp.typ) {
        return Err(TLSError::InappropriateHandshakeMessage {
          expect_types: self.handshake_types.clone(),
          got_type: hsp.typ.clone()
        });
      }
    }

    Ok(())
  }
}

pub type ExpectFunction = fn() -> Expectation;
