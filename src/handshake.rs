use msgs::enums::{ContentType, HandshakeType};
use msgs::message::{Message, MessagePayload};
use error::TLSError;

pub fn check_handshake_message(m: &Message,
                               handshake_types: &[HandshakeType]) -> Result<(), TLSError> {
    check_message(m,
                  &[ContentType::Handshake],
                  handshake_types)
}

pub fn check_message(m: &Message,
                     content_types: &[ContentType],
                     handshake_types: &[HandshakeType]) -> Result<(), TLSError> {
    if !content_types.contains(&m.typ) {
        warn!("Received a {:?} message while expecting {:?}",
              m.typ,
              content_types);
        return Err(TLSError::InappropriateMessage {
            expect_types: content_types.to_vec(),
            got_type: m.typ,
        });
    }

    if let MessagePayload::Handshake(ref hsp) = m.payload {
        if handshake_types.len() > 0 && !handshake_types.contains(&hsp.typ) {
            warn!("Received a {:?} handshake message while expecting {:?}",
                  hsp.typ,
                  handshake_types);
            return Err(TLSError::InappropriateHandshakeMessage {
                expect_types: handshake_types.to_vec(),
                got_type: hsp.typ,
            });
        }
    }

    Ok(())
}

/* DELETEME: */
#[derive(Debug, Clone)]
pub struct Expectation {
    pub content_types: &'static [ContentType],
    pub handshake_types: &'static [HandshakeType],
}

impl Expectation {
    pub fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, self.content_types, self.handshake_types)
    }
}
