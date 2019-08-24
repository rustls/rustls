use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::message::{Message, MessagePayload};
use crate::error::TLSError;
#[cfg(feature = "logging")]
use crate::log::warn;

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
        if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
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
