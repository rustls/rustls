use crate::enums::ProtocolVersion;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::AlertLevel;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::handshake::HandshakeMessagePayload;

use alloc::vec::Vec;

#[derive(Debug)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake {
        parsed: HandshakeMessagePayload,
        encoded: Payload,
    },
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload),
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(&encoded.0),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub fn handshake(parsed: HandshakeMessagePayload) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: Payload,
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(&payload.0);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(payload)),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: payload,
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
///
/// # Decryption
/// Internally the message payload is stored as a `Vec<u8>`; this can by mutably borrowed with
/// [`OpaqueMessage::payload_mut()`].  This is useful for decrypting a message in-place.
/// After the message is decrypted, call [`OpaqueMessage::into_plain_message()`] or
/// [`OpaqueMessage::into_tls13_unpadded_message()`] (depending on the
/// protocol version).
#[derive(Clone, Debug)]
pub struct OpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    payload: Payload,
}

impl OpaqueMessage {
    /// Construct a new `OpaqueMessage` from constituent fields.
    ///
    /// `body` is moved into the `payload` field.
    pub fn new(typ: ContentType, version: ProtocolVersion, body: Vec<u8>) -> Self {
        Self {
            typ,
            version,
            payload: Payload::new(body),
        }
    }

    /// Access the message payload as a slice.
    pub fn payload(&self) -> &[u8] {
        &self.payload.0
    }

    /// Access the message payload as a mutable `Vec<u8>`.
    pub fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.payload.0
    }

    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;
        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::InvalidContentType);
        }

        let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;
        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
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
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::MessageTooLarge);
        }

        let mut sub = r
            .sub(len as usize)
            .map_err(|_| MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            payload,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.0.len() as u16).encode(&mut buf);
        self.payload.encode(&mut buf);
        buf
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<PlainMessage, Error> {
        let payload = &mut self.payload.0;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.typ = unpad_tls13(payload);
        if self.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.version = ProtocolVersion::TLSv1_3;
        Ok(self.into_plain_message())
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

/// `v` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

impl From<Message> for PlainMessage {
    fn from(msg: Message) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload,
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    pub fn borrow(&self) -> BorrowedPlainMessage<'_> {
        BorrowedPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: &self.payload.0,
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message {
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
}

impl Message {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake { parsed, .. } = &self.payload {
            parsed.typ == hstyp
        } else {
            false
        }
    }

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
            payload: MessagePayload::handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl TryFrom<PlainMessage> for Message {
    type Error = Error;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `OpaqueMessage` because it borrows
/// its payload.  You can make a `OpaqueMessage` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
pub struct BorrowedPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl<'a> BorrowedPlainMessage<'a> {
    pub fn to_unencrypted_opaque(&self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: Payload(self.payload.to_vec()),
        }
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
}
