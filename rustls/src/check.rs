use crate::error::Error;
#[cfg(feature = "logging")]
use crate::log::warn;
use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::message::{Message, MessagePayload};

/// For a Message $m, and a HandshakePayload enum member $payload_type,
/// return Ok(payload) if $m is both a handshake message and one that
/// has the given $payload_type.  If not, return Err(rustls::Error) quoting
/// $handshake_type as the expected handshake type.
macro_rules! require_handshake_msg(
  ( $m:expr, $handshake_type:path, $payload_type:path ) => (
    match &$m.payload {
        MessagePayload::Handshake($crate::msgs::handshake::HandshakeMessagePayload {
            payload: $payload_type(hm),
            ..
        }) => Ok(hm),
        payload => Err($crate::check::inappropriate_handshake_message(payload, &[$handshake_type]))
    }
  )
);

/// Like require_handshake_msg, but moves the payload out of $m.
#[cfg(feature = "tls12")]
macro_rules! require_handshake_msg_move(
  ( $m:expr, $handshake_type:path, $payload_type:path ) => (
    match $m.payload {
        MessagePayload::Handshake($crate::msgs::handshake::HandshakeMessagePayload {
            payload: $payload_type(hm),
            ..
        }) => Ok(hm),
        ref payload =>
            Err($crate::check::inappropriate_handshake_message(payload, &[$handshake_type]))
    }
  )
);

/// Validate the message `m`: return an error if:
///
/// - the type of m does not appear in `content_types`.
/// - if m is a handshake message, the handshake message type does
///   not appear in `handshake_types`.
pub(crate) fn check_message(
    m: &Message,
    content_types: &[ContentType],
    handshake_types: &[HandshakeType],
) -> Result<(), Error> {
    if !content_types.contains(&m.payload.content_type()) {
        return Err(inappropriate_message(&m.payload, content_types));
    }

    if let MessagePayload::Handshake(hsp) = &m.payload {
        if !handshake_types.is_empty() && !handshake_types.contains(&hsp.typ) {
            return Err(inappropriate_handshake_message(&m.payload, handshake_types));
        }
    }

    Ok(())
}

pub(crate) fn inappropriate_message(
    payload: &MessagePayload,
    content_types: &[ContentType],
) -> Error {
    warn!(
        "Received a {:?} message while expecting {:?}",
        payload.content_type(),
        content_types
    );
    Error::InappropriateMessage {
        expect_types: content_types.to_vec(),
        got_type: payload.content_type(),
    }
}

pub(crate) fn inappropriate_handshake_message(
    payload: &MessagePayload,
    handshake_types: &[HandshakeType],
) -> Error {
    match payload {
        MessagePayload::Handshake(hsp) => {
            warn!(
                "Received a {:?} handshake message while expecting {:?}",
                hsp.typ, handshake_types
            );
            Error::InappropriateHandshakeMessage {
                expect_types: handshake_types.to_vec(),
                got_type: hsp.typ,
            }
        }
        payload => inappropriate_message(payload, &[ContentType::Handshake]),
    }
}
