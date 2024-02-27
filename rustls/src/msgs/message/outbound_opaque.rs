use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::message::{MessageError, PlainMessage};
use crate::{ContentType, ProtocolVersion};

use alloc::vec::Vec;

use super::OutboundChunks;

/// A TLS frame, named `TLSPlaintext` in the standard.
///
/// This outbound type owns all memory for its interior parts.
/// It results from encryption and is used for io write.
#[derive(Clone, Debug)]
pub struct OutboundOpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: PrefixedPayload,
}

impl OutboundOpaqueMessage {
    /// Construct a new `OpaqueMessage` from constituent fields.
    ///
    /// `body` is moved into the `payload` field.
    pub fn new(typ: ContentType, version: ProtocolVersion, payload: PrefixedPayload) -> Self {
        Self {
            typ,
            version,
            payload,
        }
    }

    /// Construct by decoding from a [`Reader`].
    ///
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let (typ, version, len) = read_opaque_message_header(r)?;

        let content = r
            .take(len as usize)
            .ok_or(MessageError::TooShortForLength)?;

        Ok(Self {
            typ,
            version,
            payload: PrefixedPayload::from(content),
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let length = self.payload.len() as u16;
        let mut encoded_payload = self.payload.0;
        encoded_payload[0] = self.typ.into();
        encoded_payload[1..3].copy_from_slice(&self.version.to_array());
        encoded_payload[3..5].copy_from_slice(&(length).to_be_bytes());
        encoded_payload
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OutboundOpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: Payload::Owned(self.payload.to_vec()),
        }
    }

    /// Maximum message payload size.
    /// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16_384 + 2048;

    /// Content type, version and size.
    pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

    /// Maximum on-the-wire message size.
    pub const MAX_WIRE_SIZE: usize = Self::MAX_PAYLOAD as usize + Self::HEADER_SIZE;
}

#[derive(Clone, Debug)]
pub struct PrefixedPayload(pub(super) Vec<u8>);

impl PrefixedPayload {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut prefixed_payload =
            Vec::with_capacity(OutboundOpaqueMessage::HEADER_SIZE + capacity);
        prefixed_payload.resize(OutboundOpaqueMessage::HEADER_SIZE, 0);
        Self(prefixed_payload)
    }

    pub fn len(&self) -> usize {
        self.0.len() - OutboundOpaqueMessage::HEADER_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice)
    }

    pub fn extend_from_chunks(&mut self, chunks: &OutboundChunks) {
        chunks.copy_to_vec(&mut self.0)
    }

    pub fn truncate(&mut self, len: usize) {
        self.0
            .truncate(len + OutboundOpaqueMessage::HEADER_SIZE)
    }
}

impl AsRef<[u8]> for PrefixedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.0[OutboundOpaqueMessage::HEADER_SIZE..]
    }
}

impl AsMut<[u8]> for PrefixedPayload {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[OutboundOpaqueMessage::HEADER_SIZE..]
    }
}

impl<'a> Extend<&'a u8> for PrefixedPayload {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

impl From<&[u8]> for PrefixedPayload {
    fn from(content: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(OutboundOpaqueMessage::HEADER_SIZE + content.len());
        payload.extend(&[0u8; OutboundOpaqueMessage::HEADER_SIZE]);
        payload.extend(content);
        Self(payload)
    }
}

impl<const N: usize> From<&[u8; N]> for PrefixedPayload {
    fn from(content: &[u8; N]) -> Self {
        Self::from(&content[..])
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
    if len >= OutboundOpaqueMessage::MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, len))
}
