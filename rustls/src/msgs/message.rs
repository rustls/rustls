use crate::enums::ProtocolVersion;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::internal::record_layer::RecordLayer;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::{BorrowedPayload, Payload};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader, ReaderMut};
use crate::msgs::enums::AlertLevel;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::handshake::HandshakeMessagePayload;

use alloc::vec::Vec;

#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    Handshake {
        parsed: HandshakeMessagePayload<'a>,
        encoded: Payload<'a>,
    },
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload),
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

    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake { parsed, encoded } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            ApplicationData(x) => ApplicationData(x.into_owned()),
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
/// After the message is decrypted, call [`OpaqueMessage::into_plain_message()`] or borrow this
/// message and call [`BorrowedOpaqueMessage::into_tls13_unpadded_message`].
#[derive(Clone, Debug)]
pub struct OpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    payload: Payload<'static>,
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
        self.payload.bytes()
    }

    /// Access the message payload as a mutable `Vec<u8>`.
    pub fn payload_mut(&mut self) -> &mut Vec<u8> {
        match &mut self.payload {
            Payload::Borrowed(_) => unreachable!("due to how constructor works"),
            Payload::Owned(bytes) => bytes,
        }
    }

    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let (typ, version, len) = read_opaque_message_header(r)?;

        let mut sub = r
            .sub(len as usize)
            .map_err(|_| MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub).into_owned();

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
        (self.payload.bytes().len() as u16).encode(&mut buf);
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

    #[cfg(test)]
    pub(crate) fn borrow(&mut self) -> BorrowedOpaqueMessage {
        BorrowedOpaqueMessage {
            typ: self.typ,
            version: self.version,
            payload: BorrowedPayload::new(self.payload_mut()),
        }
    }

    /// Maximum message payload size.
    /// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16_384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-the-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

/// A borrowed version of [`OpaqueMessage`].
pub struct BorrowedOpaqueMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: BorrowedPayload<'a>,
}

impl<'a> BorrowedOpaqueMessage<'a> {
    /// Force conversion into an inbound plaintext message.
    ///
    /// See [`OpaqueMessage::into_plain_message`] for more information
    pub fn into_inbound_message(self) -> InboundMessage<'a> {
        InboundMessage {
            typ: self.typ,
            version: self.version,
            payload: self.payload.into_inner(),
        }
    }

    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<InboundMessage<'a>, Error> {
        let payload = &mut self.payload;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.typ = unpad_tls13_payload(payload);
        if self.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.version = ProtocolVersion::TLSv1_3;
        Ok(self.into_inbound_message())
    }

    pub(crate) fn read(r: &mut ReaderMut<'a>) -> Result<Self, MessageError> {
        let (typ, version, len) = r.as_reader(read_opaque_message_header)?;

        let mut sub = r
            .sub(len as usize)
            .map_err(|_| MessageError::TooShortForLength)?;
        let payload = BorrowedPayload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            payload,
        })
    }
}

fn read_opaque_message_header(
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
    if len >= OpaqueMessage::MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, len))
}

/// `v` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13_payload(p: &mut BorrowedPayload) -> ContentType {
    loop {
        match p.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

impl From<Message<'_>> for PlainMessage {
    fn from(msg: Message) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
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
    pub payload: Payload<'static>,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    pub fn borrow_inbound(&self) -> InboundMessage<'_> {
        InboundMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes(),
        }
    }

    pub fn borrow_outbound(&self) -> OutboundMessage<'_> {
        OutboundMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes().into(),
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message<'a> {
    pub version: ProtocolVersion,
    pub payload: MessagePayload<'a>,
}

impl Message<'_> {
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

    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }
}

impl TryFrom<PlainMessage> for Message<'static> {
    type Error = Error;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.bytes())?
                .into_owned(),
        })
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl<'a> TryFrom<InboundMessage<'a>> for Message<'a> {
    type Error = Error;

    fn try_from(plain: InboundMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type borrows its decrypted payload from a `MessageDeframer`.
/// You can make a `OpaqueMessage` from an `InboundMessage`,
/// but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
#[derive(Debug)]
pub struct InboundMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl InboundMessage<'_> {
    /// Returns true if the payload is a CCS message.
    ///
    /// We passthrough ChangeCipherSpec messages in the deframer without decrypting them.
    /// Note: this is prior to the record layer, so is unencrypted. See
    /// third paragraph of section 5 in RFC8446.
    pub(crate) fn is_valid_ccs(&self) -> bool {
        self.typ == ContentType::ChangeCipherSpec && self.payload == [0x01]
    }
}

impl BorrowedPlainMessage for InboundMessage<'_> {
    fn payload_to_vec(&self) -> Vec<u8> {
        self.payload.to_vec()
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn typ(&self) -> ContentType {
        self.typ
    }

    fn version(&self) -> ProtocolVersion {
        self.version
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type borrows its "to be encrypted" data from the client.
/// You can make a `OpaqueMessage` from an `OutboundMessage`,
/// but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.

#[derive(Debug)]
pub struct OutboundMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: OutboundChunks<'a>,
}

impl BorrowedPlainMessage for OutboundMessage<'_> {
    fn payload_to_vec(&self) -> Vec<u8> {
        self.payload.to_vec()
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn typ(&self) -> ContentType {
        self.typ
    }

    fn version(&self) -> ProtocolVersion {
        self.version
    }
}

/// Abstract both inbound and outbound variants of a plaintext message
pub trait BorrowedPlainMessage: Sized {
    fn into_owned(self) -> PlainMessage {
        PlainMessage {
            version: self.version(),
            typ: self.typ(),
            payload: Payload::Owned(self.payload_to_vec()),
        }
    }

    fn to_unencrypted_opaque(&self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version(),
            typ: self.typ(),
            payload: Payload::Owned(self.payload_to_vec()),
        }
    }

    fn encoded_len(&self, record_layer: &RecordLayer) -> usize {
        OpaqueMessage::HEADER_SIZE as usize + record_layer.encrypted_len(self.payload_len())
    }

    fn payload_to_vec(&self) -> Vec<u8>;

    fn payload_len(&self) -> usize;

    fn typ(&self) -> ContentType;

    fn version(&self) -> ProtocolVersion;
}

#[derive(Debug, Clone)]
/// A collection of borrowed plaintext slices.
/// Warning: OutboundChunks does not guarantee that the simplest variant is used.
/// Multiple can hold non fragmented or empty payloads.
pub enum OutboundChunks<'a> {
    /// A single byte slice. Contrary to `Multiple`, this uses a single pointer indirection
    Single(&'a [u8]),
    /// A collection of chunks (byte slices)
    /// and cursors to single out a fragmented range of bytes.
    /// OutboundChunks assumes that start <= end
    Multiple {
        chunks: &'a [&'a [u8]],
        start: usize,
        end: usize,
    },
}

impl<'a> OutboundChunks<'a> {
    /// Create a payload from a slice of byte slices.
    /// If fragmented the cursors are added by default: start = 0, end = length
    pub fn new(chunks: &'a [&'a [u8]]) -> Self {
        if chunks.len() == 1 {
            Self::Single(chunks[0])
        } else {
            Self::Multiple {
                chunks,
                start: 0,
                end: chunks
                    .iter()
                    .map(|chunk| chunk.len())
                    .sum(),
            }
        }
    }

    /// Create a payload with a single empty slice
    pub fn new_empty() -> Self {
        Self::Single(&[])
    }

    /// Flatten the slice of byte slices to an owned vector of bytes
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.len());
        self.copy_to_vec(&mut vec);
        vec
    }

    /// Append all bytes to a vector
    pub fn copy_to_vec(&self, vec: &mut Vec<u8>) {
        match *self {
            Self::Single(chunk) => vec.extend_from_slice(chunk),
            Self::Multiple { chunks, start, end } => {
                let mut size = 0;
                for chunk in chunks.iter() {
                    let psize = size;
                    let len = chunk.len();
                    size += len;
                    if size <= start || psize >= end {
                        continue;
                    }
                    let start = if psize < start { start - psize } else { 0 };
                    let end = if end - psize < len { end - psize } else { len };
                    vec.extend_from_slice(&chunk[start..end]);
                }
            }
        }
    }

    /// Split self in two, around an index
    /// Works similarly to `split_at` in the core library, except it doesn't panic if out of bound
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        match *self {
            Self::Single(chunk) => {
                let mid = Ord::min(mid, chunk.len());
                (Self::Single(&chunk[..mid]), Self::Single(&chunk[mid..]))
            }
            Self::Multiple { chunks, start, end } => {
                let mid = Ord::min(start + mid, end);
                (
                    Self::Multiple {
                        chunks,
                        start,
                        end: mid,
                    },
                    Self::Multiple {
                        chunks,
                        start: mid,
                        end,
                    },
                )
            }
        }
    }

    /// Returns true if the payload is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the cumulative length of all chunks
    pub fn len(&self) -> usize {
        match self {
            Self::Single(chunk) => chunk.len(),
            Self::Multiple { start, end, .. } => end - start,
        }
    }
}

impl<'a> From<&'a [u8]> for OutboundChunks<'a> {
    fn from(payload: &'a [u8]) -> Self {
        Self::Single(payload)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for OutboundChunks<'a> {
    fn from(payload: &'a [u8; N]) -> Self {
        Self::Single(payload)
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

#[cfg(test)]
mod tests {
    use std::{println, vec};

    use super::*;

    #[test]
    fn split_at_with_single_slice() {
        let owner: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7];
        let borrowed_payload = OutboundChunks::Single(owner);

        let (before, after) = borrowed_payload.split_at(6);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5]);
        assert_eq!(after.to_vec(), &[6, 7]);
    }

    #[test]
    fn split_at_with_multiple_slices() {
        let owner: Vec<&[u8]> = vec![&[0, 1, 2, 3], &[4, 5], &[6, 7, 8], &[9, 10, 11, 12]];
        let borrowed_payload = OutboundChunks::new(&owner);

        let (before, after) = borrowed_payload.split_at(3);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2]);
        assert_eq!(after.to_vec(), &[3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let (before, after) = borrowed_payload.split_at(8);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(after.to_vec(), &[8, 9, 10, 11, 12]);

        let (before, after) = borrowed_payload.split_at(11);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(after.to_vec(), &[11, 12]);
    }

    #[test]
    fn split_out_of_bounds() {
        let owner: Vec<&[u8]> = vec![&[0, 1, 2, 3], &[4, 5], &[6, 7, 8], &[9, 10, 11, 12]];

        let single_payload = OutboundChunks::Single(owner[0]);
        let (before, after) = single_payload.split_at(17);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2, 3]);
        assert!(after.is_empty());

        let multiple_payload = OutboundChunks::new(&owner);
        let (before, after) = multiple_payload.split_at(17);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert!(after.is_empty());

        let empty_payload = OutboundChunks::new_empty();
        let (before, after) = empty_payload.split_at(17);
        println!("before:{:?}\nafter:{:?}", before, after);
        assert!(before.is_empty());
        assert!(after.is_empty());
    }

    #[test]
    fn empty_slices_mixed() {
        let owner: Vec<&[u8]> = vec![&[], &[], &[0], &[], &[1, 2], &[], &[3], &[4], &[], &[]];
        let mut borrowed_payload = OutboundChunks::new(&owner);
        let mut fragment_count = 0;
        let mut fragment;
        let expected_fragments: &[&[u8]] = &[&[0, 1], &[2, 3], &[4]];

        while !borrowed_payload.is_empty() {
            (fragment, borrowed_payload) = borrowed_payload.split_at(2);
            println!("{fragment:?}");
            assert_eq!(&expected_fragments[fragment_count], &fragment.to_vec());
            fragment_count += 1;
        }
        assert_eq!(fragment_count, expected_fragments.len());
    }

    #[test]
    fn exhaustive_splitting() {
        let owner: Vec<u8> = (0..127).collect();
        let slices = (0..7)
            .map(|i| &owner[((1 << i) - 1)..((1 << (i + 1)) - 1)])
            .collect::<Vec<_>>();
        let payload = OutboundChunks::new(&slices);

        assert_eq!(payload.to_vec(), owner);
        println!("{:#?}", payload);

        for start in 0..128 {
            for end in start..128 {
                for mid in 0..(end - start) {
                    let witness = owner[start..end].split_at(mid);
                    let split_payload = payload
                        .split_at(end)
                        .0
                        .split_at(start)
                        .1
                        .split_at(mid);
                    assert_eq!(
                        witness.0,
                        split_payload.0.to_vec(),
                        "start: {start}, mid:{mid}, end:{end}"
                    );
                    assert_eq!(
                        witness.1,
                        split_payload.1.to_vec(),
                        "start: {start}, mid:{mid}, end:{end}"
                    );
                }
            }
        }
    }
}
