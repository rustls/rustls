use crate::error::Error;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::HandshakeType;
use crate::msgs::enums::{AlertDescription, AlertLevel};
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::handshake::HandshakeMessagePayload;

use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload<'a>),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            MessagePayload::Alert(ref x) => x.encode(bytes),
            MessagePayload::Handshake(ref x) => x.encode(bytes),
            MessagePayload::ChangeCipherSpec(ref x) => x.encode(bytes),
            MessagePayload::ApplicationData(ref x) => x.encode(bytes),
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<MessagePayload<'a>, Error> {
        let mut r = Reader::init(payload);
        let parsed = match typ {
            ContentType::ApplicationData => {
                return Ok(MessagePayload::ApplicationData(Payload::new(payload)));
            }
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(MessagePayload::Handshake)
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => None,
        };

        parsed
            .filter(|_| !r.any_left())
            .ok_or(Error::CorruptMessagePayload(typ))
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            MessagePayload::Alert(_) => ContentType::Alert,
            MessagePayload::Handshake(_) => ContentType::Handshake,
            MessagePayload::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            MessagePayload::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
#[derive(Debug)]
pub struct OpaqueMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Buffer<'a>,
}

impl<'a> OpaqueMessage<'a> {
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(buf: &mut [u8]) -> Result<(OpaqueMessage, usize), MessageError> {
        let mut r = Reader::init(&buf);
        let typ = ContentType::read(&mut r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(&mut r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(&mut r).ok_or(MessageError::TooShortForHeader)?;

        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return Err(MessageError::IllegalProtocolVersion);
            }
            _ => {}
        };

        if r.left() < len as usize {
            return Err(MessageError::TooShortForLength);
        }

        let used = r.used() + len as usize;
        let end = (Self::HEADER_SIZE + len) as usize;
        let msg = OpaqueMessage {
            typ,
            version,
            payload: Buffer::Slice(&mut buf[Self::HEADER_SIZE as usize..end]),
        };
        Ok((msg, used))
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.len() as u16).encode(&mut buf);
        buf.extend_from_slice(self.payload.as_ref());
        buf
    }

    pub fn to_plain_message(&self) -> PlainMessage<'_> {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.as_ref().into(),
        }
    }

    pub fn to_owned(&self) -> OpaqueMessage<'static> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Buffer::Vec(self.payload.as_ref().to_vec()),
        }
    }

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

impl From<Message<'_>> for PlainMessage<'static> {
    fn from(msg: Message<'_>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.0.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                buf
            }
        };

        PlainMessage {
            typ,
            version: msg.version,
            payload: payload.into(),
        }
    }
}

#[derive(Debug)]
pub struct PlainMessage<'a> {
    pub version: ProtocolVersion,
    pub typ: ContentType,
    pub payload: Cow<'a, [u8]>,
}

impl<'a> PlainMessage<'a> {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage<'static> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Buffer::Vec(self.payload.into_owned()),
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message<'a> {
    pub version: ProtocolVersion,
    pub payload: MessagePayload<'a>,
}

impl<'a> Message<'a> {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake(ref hsp) = self.payload {
            hsp.typ == hstyp
        } else {
            false
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Message<'static> {
        Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Message<'static> {
        Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

impl<'a> TryFrom<&'a PlainMessage<'a>> for Message<'a> {
    type Error = Error;

    fn try_from(plain: &'a PlainMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Message {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.as_ref())?,
        })
    }
}

#[derive(Debug)]
pub enum Buffer<'a> {
    Slice(&'a mut [u8]),
    Vec(Vec<u8>),
}

impl<'a> Buffer<'a> {
    pub(crate) fn truncate(&mut self, new_len: usize) {
        match self {
            Buffer::Slice(slice) => *slice = &mut std::mem::take(slice)[..new_len],
            Buffer::Vec(vec) => vec.truncate(new_len),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Buffer::Slice(slice) => slice.len(),
            Buffer::Vec(vec) => vec.len(),
        }
    }
}

impl<'a> AsRef<[u8]> for Buffer<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Buffer::Slice(slice) => slice,
            Buffer::Vec(vec) => vec,
        }
    }
}

impl<'a> AsMut<[u8]> for Buffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Buffer::Slice(slice) => slice,
            Buffer::Vec(vec) => vec,
        }
    }
}

impl From<Vec<u8>> for Buffer<'static> {
    fn from(vec: Vec<u8>) -> Self {
        Buffer::Vec(vec)
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalLength,
    IllegalContentType,
    IllegalProtocolVersion,
}
