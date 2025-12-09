use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut, Range};

use crate::crypto::cipher::RecordLayer;
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::base::hex;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{HEADER_SIZE, read_opaque_message_header};

/// A TLS message with encoded (but not necessarily encrypted) payload.
#[expect(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
pub struct EncodedMessage<P> {
    /// The content type of this message.
    pub typ: ContentType,
    /// The protocol version of this message.
    pub version: ProtocolVersion,
    /// The payload of this message.
    pub payload: P,
}

impl<P> EncodedMessage<P> {
    /// Create a new `EncodedMessage` with the given fields.
    pub fn new(typ: ContentType, version: ProtocolVersion, payload: P) -> Self {
        Self {
            typ,
            version,
            payload,
        }
    }
}

impl<'a> EncodedMessage<Payload<'a>> {
    /// Construct by decoding from a [`Reader`].
    ///
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader<'a>) -> Result<Self, MessageError> {
        let (typ, version, len) = read_opaque_message_header(r)?;

        let content = r
            .take(len as usize)
            .ok_or(MessageError::TooShortForLength)?;

        Ok(Self {
            typ,
            version,
            payload: Payload::Borrowed(content),
        })
    }

    /// Convert into an unencrypted [`EncodedMessage<OutboundOpaque>`] (without decrypting).
    pub fn into_unencrypted_opaque(self) -> EncodedMessage<OutboundOpaque> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: OutboundOpaque::from(self.payload.bytes()),
        }
    }

    /// Borrow as an [`EncodedMessage<OutboundPlain<'a>>`].
    pub fn borrow_outbound(&'a self) -> EncodedMessage<OutboundPlain<'a>> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: self.payload.bytes().into(),
        }
    }

    /// Convert into an owned `EncodedMessage<Plain<'static>>`.
    pub fn into_owned(self) -> Self {
        Self {
            typ: self.typ,
            version: self.version,
            payload: self.payload.into_owned(),
        }
    }
}

impl EncodedMessage<&'_ [u8]> {
    /// Returns true if the payload is a CCS message.
    ///
    /// We passthrough ChangeCipherSpec messages in the deframer without decrypting them.
    /// Note: this is prior to the record layer, so is unencrypted. See
    /// third paragraph of section 5 in RFC8446.
    pub(crate) fn is_valid_ccs(&self) -> bool {
        self.typ == ContentType::ChangeCipherSpec && self.payload == [0x01]
    }
}

impl<'a> EncodedMessage<InboundOpaque<'a>> {
    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<EncodedMessage<&'a [u8]>, Error> {
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
        Ok(self.into_plain_message())
    }

    /// Force conversion into a plaintext message.
    ///
    /// `range` restricts the resulting message: this function panics if it is out of range for
    /// the underlying message payload.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// [`EncodedMessage<InboundOpaque<'_>>`] should be decrypted into an
    /// `EncodedMessage<&'_ [u8]>` using a `MessageDecrypter`.
    pub fn into_plain_message_range(self, range: Range<usize>) -> EncodedMessage<&'a [u8]> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: &self.payload.into_inner()[range],
        }
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// [`EncodedMessage<InboundOpaque<'a>>`] should be decrypted into a
    /// `EncodedMessage<&'a [u8]>` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> EncodedMessage<&'a [u8]> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: self.payload.into_inner(),
        }
    }
}

impl EncodedMessage<OutboundPlain<'_>> {
    pub(crate) fn to_unencrypted_opaque(&self) -> EncodedMessage<OutboundOpaque> {
        let mut payload = OutboundOpaque::with_capacity(self.payload.len());
        payload.extend_from_chunks(&self.payload);
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload,
        }
    }

    pub(crate) fn encoded_len(&self, record_layer: &RecordLayer) -> usize {
        HEADER_SIZE + record_layer.encrypted_len(self.payload.len())
    }
}

impl EncodedMessage<OutboundOpaque> {
    /// Encode this message to a vector of bytes.
    pub fn encode(self) -> Vec<u8> {
        let length = self.payload.len() as u16;
        let mut encoded_payload = self.payload.0;
        encoded_payload[0] = self.typ.into();
        encoded_payload[1..3].copy_from_slice(&self.version.to_array());
        encoded_payload[3..5].copy_from_slice(&(length).to_be_bytes());
        encoded_payload
    }
}

/// A collection of borrowed plaintext slices.
///
/// Warning: OutboundChunks does not guarantee that the simplest variant is used.
/// Multiple can hold non fragmented or empty payloads.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum OutboundPlain<'a> {
    /// A single byte slice.
    ///
    /// Contrary to `Multiple`, this uses a single pointer indirection
    Single(&'a [u8]),
    /// A collection of chunks (byte slices).
    Multiple {
        /// A collection of byte slices that hold the buffered data.
        chunks: &'a [&'a [u8]],
        /// The start cursor into the first chunk.
        start: usize,
        /// The end cursor into the last chunk.
        end: usize,
    },
}

impl<'a> OutboundPlain<'a> {
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
                    let start = start.saturating_sub(psize);
                    let end = if end - psize < len { end - psize } else { len };
                    vec.extend_from_slice(&chunk[start..end]);
                }
            }
        }
    }

    /// Split self in two, around an index
    /// Works similarly to `split_at` in the core library, except it doesn't panic if out of bound
    pub(crate) fn split_at(&self, mid: usize) -> (Self, Self) {
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
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the cumulative length of all chunks
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::Single(chunk) => chunk.len(),
            Self::Multiple { start, end, .. } => end - start,
        }
    }
}

impl<'a> From<&'a [u8]> for OutboundPlain<'a> {
    fn from(payload: &'a [u8]) -> Self {
        Self::Single(payload)
    }
}

/// A payload buffer with space reserved at the front for a TLS message header.
///
/// `EncodedMessage<OutboundOpaque>` is named `TLSPlaintext` in the standard.
///
/// This outbound type owns all memory for its interior parts.
/// It results from encryption and is used for io write.
#[derive(Clone, Debug)]
pub struct OutboundOpaque(Vec<u8>);

impl OutboundOpaque {
    /// Create a new value with the given payload capacity.
    ///
    /// (The actual capacity of the returned value will be at least `HEADER_SIZE + capacity`.)
    pub fn with_capacity(capacity: usize) -> Self {
        let mut prefixed_payload = Vec::with_capacity(HEADER_SIZE + capacity);
        prefixed_payload.resize(HEADER_SIZE, 0);
        Self(prefixed_payload)
    }

    /// Append bytes from a slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice)
    }

    /// Append bytes from an `OutboundChunks`.
    pub fn extend_from_chunks(&mut self, chunks: &OutboundPlain<'_>) {
        chunks.copy_to_vec(&mut self.0)
    }

    /// Truncate the payload to the given length (plus header).
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len + HEADER_SIZE)
    }

    fn len(&self) -> usize {
        self.0.len() - HEADER_SIZE
    }
}

impl AsRef<[u8]> for OutboundOpaque {
    fn as_ref(&self) -> &[u8] {
        &self.0[HEADER_SIZE..]
    }
}

impl AsMut<[u8]> for OutboundOpaque {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_SIZE..]
    }
}

impl<'a> Extend<&'a u8> for OutboundOpaque {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

impl From<&[u8]> for OutboundOpaque {
    fn from(content: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(HEADER_SIZE + content.len());
        payload.extend(&[0u8; HEADER_SIZE]);
        payload.extend(content);
        Self(payload)
    }
}

impl<const N: usize> From<&[u8; N]> for OutboundOpaque {
    fn from(content: &[u8; N]) -> Self {
        Self::from(&content[..])
    }
}

/// An externally length'd payload
///
/// When encountered in an [`EncodedMessage`], it represents a plaintext payload. It can be
/// decrypted from an [`InboundOpaque`] or encrypted into an [`OutboundOpaque`],
/// and it is also used for joining and fragmenting.
#[non_exhaustive]
#[derive(Clone, Eq, PartialEq)]
pub enum Payload<'a> {
    /// Borrowed payload
    Borrowed(&'a [u8]),
    /// Owned payload
    Owned(Vec<u8>),
}

impl<'a> Payload<'a> {
    /// A reference to the payload's bytes
    pub fn bytes(&'a self) -> &'a [u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Borrowed(bytes) => bytes.to_vec(),
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }
}

impl Payload<'static> {
    /// Create a new owned payload from the given `bytes`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Owned(bytes.into())
    }
}

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.bytes());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.bytes())
    }
}

/// A borrowed payload buffer.
#[expect(clippy::exhaustive_structs)]
pub struct InboundOpaque<'a>(pub &'a mut [u8]);

impl<'a> InboundOpaque<'a> {
    /// Truncate the payload to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }

        self.0 = core::mem::take(&mut self.0)
            .split_at_mut(len)
            .0;
    }

    pub(crate) fn into_inner(self) -> &'a mut [u8] {
        self.0
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }

        let len = self.len();
        let last = self[len - 1];
        self.truncate(len - 1);
        Some(last)
    }
}

impl Deref for InboundOpaque<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for InboundOpaque<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

/// Decode a TLS1.3 `TLSInnerPlaintext` encoding.
///
/// `p` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13_payload(p: &mut InboundOpaque<'_>) -> ContentType {
    loop {
        match p.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

/// Errors from trying to parse a TLS message.
#[expect(missing_docs)]
#[non_exhaustive]
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
        let borrowed_payload = OutboundPlain::Single(owner);

        let (before, after) = borrowed_payload.split_at(6);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5]);
        assert_eq!(after.to_vec(), &[6, 7]);
    }

    #[test]
    fn split_at_with_multiple_slices() {
        let owner: Vec<&[u8]> = vec![&[0, 1, 2, 3], &[4, 5], &[6, 7, 8], &[9, 10, 11, 12]];
        let borrowed_payload = OutboundPlain::new(&owner);

        let (before, after) = borrowed_payload.split_at(3);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2]);
        assert_eq!(after.to_vec(), &[3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let (before, after) = borrowed_payload.split_at(8);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(after.to_vec(), &[8, 9, 10, 11, 12]);

        let (before, after) = borrowed_payload.split_at(11);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(after.to_vec(), &[11, 12]);
    }

    #[test]
    fn split_out_of_bounds() {
        let owner: Vec<&[u8]> = vec![&[0, 1, 2, 3], &[4, 5], &[6, 7, 8], &[9, 10, 11, 12]];

        let single_payload = OutboundPlain::Single(owner[0]);
        let (before, after) = single_payload.split_at(17);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2, 3]);
        assert!(after.is_empty());

        let multiple_payload = OutboundPlain::new(&owner);
        let (before, after) = multiple_payload.split_at(17);
        println!("before:{before:?}\nafter:{after:?}");
        assert_eq!(before.to_vec(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert!(after.is_empty());

        let empty_payload = OutboundPlain::new_empty();
        let (before, after) = empty_payload.split_at(17);
        println!("before:{before:?}\nafter:{after:?}");
        assert!(before.is_empty());
        assert!(after.is_empty());
    }

    #[test]
    fn empty_slices_mixed() {
        let owner: Vec<&[u8]> = vec![&[], &[], &[0], &[], &[1, 2], &[], &[3], &[4], &[], &[]];
        let mut borrowed_payload = OutboundPlain::new(&owner);
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
        let payload = OutboundPlain::new(&slices);

        assert_eq!(payload.to_vec(), owner);
        println!("{payload:#?}");

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
