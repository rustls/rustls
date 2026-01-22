#[cfg(test)]
use alloc::vec::Vec;

use super::codec::{Codec, Reader};
use super::enums::{AlertLevel, KeyUpdateRequest};
use super::handshake::{HandshakeMessagePayload, HandshakePayload};
use super::{AlertMessagePayload, MessagePayload};
use crate::crypto::cipher::{EncodedMessage, MessageError, Payload};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, InvalidMessage};

/// A message with decoded payload
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct Message<'a> {
    pub version: ProtocolVersion,
    pub payload: MessagePayload<'a>,
}

impl Message<'_> {
    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
            )),
        }
    }

    pub fn build_key_update_request() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
            )),
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_wire_bytes(self) -> Vec<u8> {
        EncodedMessage::<Payload<'_>>::from(self)
            .into_unencrypted_opaque()
            .encode()
    }

    pub(crate) fn handshake_type(&self) -> Option<HandshakeType> {
        match &self.payload {
            MessagePayload::Handshake { parsed, .. } => Some(parsed.0.handshake_type()),
            _ => None,
        }
    }
}

impl<'a> TryFrom<&'a EncodedMessage<&'a [u8]>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: &'a EncodedMessage<&'a [u8]>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

impl<'a> TryFrom<&'a EncodedMessage<Payload<'a>>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: &'a EncodedMessage<Payload<'a>>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.bytes())?,
        })
    }
}

pub(crate) fn read_opaque_message_header(
    r: &mut Reader<'_>,
) -> Result<(ContentType, ProtocolVersion, u16), MessageError> {
    let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Don't accept any new content-types.
    if let ContentType::Unknown(_) = typ {
        return Err(MessageError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Accept only versions 0x03XX for any XX.
    match &version {
        ProtocolVersion::Unknown(v) if (v & 0xff00) != 0x0300 => {
            return Err(MessageError::UnknownProtocolVersion);
        }
        _ => {}
    };

    let len = u16::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    //              per section 6.2.1 of RFC5246 (TLSv1.2)
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(MessageError::InvalidEmptyPayload);
    }

    // Reject oversize messages
    if len >= MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, len))
}

/// Content type, version and size.
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

/// Maximum message payload size.
/// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
pub(crate) const MAX_PAYLOAD: u16 = 16_384 + 2048;

/// Maximum on-the-wire message size.
#[cfg(feature = "std")]
pub(crate) const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;
