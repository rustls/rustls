use msgs::enums::{ContentType, HandshakeType};
use msgs::message::{Message, MessagePayload};
use error::TLSError;

#[derive(Debug, Clone)]
pub struct Expectation {
  pub content_types: &'static [ContentType],
  pub handshake_types: &'static [HandshakeType]
}

impl Expectation {
  pub fn check_message(&self, m: &Message) -> Result<(), TLSError> {
    if !self.content_types.contains(&m.typ) {
      warn!("Received a {:?} message while expecting {:?}",
            m.typ, self.content_types);
      return Err(TLSError::InappropriateMessage {
        expect_types: self.content_types.to_vec(),
        got_type: m.typ
      });
    }

    if let MessagePayload::Handshake(ref hsp) = m.payload {
      if self.handshake_types.len() > 0
        && !self.handshake_types.contains(&hsp.typ) {
        warn!("Received a {:?} handshake message while expecting {:?}",
              hsp.typ, self.handshake_types);
        return Err(TLSError::InappropriateHandshakeMessage {
          expect_types: self.handshake_types.to_vec(),
          got_type: hsp.typ
        });
      }
    }

    Ok(())
  }
}

