use alloc::vec::Vec;
use core::ops::{Deref, DerefMut, Range};
use core::{fmt, slice};

use crate::crypto::cipher::EncryptionState;
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{ApiMisuse, Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::{Codec, HEADER_SIZE, MAX_FRAGMENT_LEN, Reader, hex, read_opaque_message_header};

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
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, MessageError> {
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
        if self.typ == ContentType(0) {
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
    /// Encode this message into its unencrypted wire representation, including
    /// its record header.
    pub(crate) fn to_unencrypted_bytes(&self) -> Vec<u8> {
        let len = self.payload.len();
        debug_assert!(len <= usize::from(u16::MAX));
        let mut buf = Vec::with_capacity(HEADER_SIZE + len);
        buf.extend_from_slice(&encode_record_header(self.typ, self.version, len as u16));
        self.payload.copy_to_vec(&mut buf);
        buf
    }

    #[expect(dead_code)]
    pub(crate) fn encoded_len(&self, record_layer: &EncryptionState) -> usize {
        HEADER_SIZE + record_layer.encrypted_len(self.payload.len())
    }
}

/// Encode a TLS record header.
///
/// `typ`, `version` and `len` describe the record's payload.
pub(crate) fn encode_record_header(
    typ: ContentType,
    version: ProtocolVersion,
    len: u16,
) -> [u8; HEADER_SIZE] {
    let [version_hi, version_lo] = version.to_array();
    let [len_hi, len_lo] = len.to_be_bytes();
    [typ.into(), version_hi, version_lo, len_hi, len_lo]
}

/// A collection of borrowed plaintext slices.
///
/// Warning: OutboundPlain does not guarantee that the simplest variant is used.
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
        /// Offset of the payload's first byte within the logical
        /// concatenation of all `chunks`.
        ///
        /// This may point beyond the first chunk (for example, after
        /// `split_at()`).
        start: usize,
        /// Offset one past the payload's last byte within the logical
        /// concatenation of all `chunks`, so `end - start` is the payload's
        /// length in bytes.
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
        for chunk in self.chunks() {
            vec.extend_from_slice(chunk);
        }
    }

    /// Iterate over the payload's chunks of bytes, in order.
    ///
    /// Empty chunks are not yielded.
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> + '_ {
        match self {
            Self::Single(chunk) => Chunks::Single((!chunk.is_empty()).then_some(*chunk)),
            Self::Multiple { chunks, start, end } => Chunks::Multiple {
                chunks: chunks.iter(),
                skip: *start,
                remaining: end - start,
            },
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

/// Iterator over an [`OutboundPlain`]'s chunks, returned by [`OutboundPlain::chunks()`].
enum Chunks<'a> {
    Single(Option<&'a [u8]>),
    Multiple {
        /// Chunks not yet visited, including any leading ones `skip` covers.
        chunks: slice::Iter<'a, &'a [u8]>,
        /// How many leading bytes remain to be skipped.
        skip: usize,
        /// How many bytes remain to be yielded.
        remaining: usize,
    },
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (chunks, skip, remaining) = match self {
            Self::Single(chunk) => return chunk.take(),
            Self::Multiple {
                chunks,
                skip,
                remaining,
            } => (chunks, skip, remaining),
        };

        loop {
            if *remaining == 0 {
                return None;
            }

            let chunk = chunks.next()?;
            let Some((_, chunk)) = chunk.split_at_checked(*skip) else {
                *skip -= chunk.len();
                continue;
            };

            *skip = 0;
            if chunk.is_empty() {
                continue;
            }

            let take = Ord::min(chunk.len(), *remaining);
            *remaining -= take;
            return Some(&chunk[..take]);
        }
    }
}

impl<'a> From<&'a [u8]> for OutboundPlain<'a> {
    fn from(payload: &'a [u8]) -> Self {
        Self::Single(payload)
    }
}

/// A fixed-size buffer into which a [`MessageEncrypter`][] writes an encrypted message payload.
///
/// This wraps the output buffer passed to [`MessageEncrypter::encrypt()`][], tracking how
/// much of it has been written as the append methods fill it front-to-back. It writes
/// into caller-owned memory and cannot grow. [`Self::new()`] checks that the caller's
/// buffer can hold the `len` bytes the encrypter declared, and the append methods then
/// panic if the writes exceed that length.
///
/// Such a panic always indicates a bug in the `MessageEncrypter` implementation, not a
/// runtime condition the caller can handle. The same implementation declares the total
/// length up front (via [`MessageEncrypter::encrypted_payload_len()`]) and performs the
/// writes, so overflowing the buffer means the two disagree. The record layer also
/// relies on that declared length for framing, so there is no way to recover from the
/// mismatch after the fact.
///
/// [`MessageEncrypter`]: crate::crypto::cipher::MessageEncrypter
/// [`MessageEncrypter::encrypt()`]: crate::crypto::cipher::MessageEncrypter::encrypt()
/// [`MessageEncrypter::encrypted_payload_len()`]: crate::crypto::cipher::MessageEncrypter::encrypted_payload_len()
pub struct EncryptBuffer<'a> {
    buf: &'a mut [u8],
    used: usize,
}

impl<'a> EncryptBuffer<'a> {
    /// Wrap the first `len` bytes of `out`, all of which are as yet unwritten.
    ///
    /// Returns [`ApiMisuse::EncryptBufferTooSmall`] if `out` is shorter than `len` bytes.
    pub fn new(out: &'a mut [u8], len: usize) -> Result<Self, Error> {
        let provided = out.len();
        match out.get_mut(..len) {
            Some(buf) => Ok(Self { buf, used: 0 }),
            None => Err(ApiMisuse::EncryptBufferTooSmall {
                required: len,
                provided,
            }
            .into()),
        }
    }

    /// Append bytes from an `OutboundPlain`'s chunks.
    ///
    /// Panics if the write would extend beyond the `len` given to [`Self::new()`],
    /// which indicates a bug in the calling `MessageEncrypter` implementation (see
    /// the type-level documentation).
    pub fn extend_from_chunks(&mut self, chunks: &OutboundPlain<'_>) {
        match chunks {
            // for the common case with a single chunk we want to avoid iteration overhead.
            OutboundPlain::Single(chunk) => self.extend_from_slice(chunk),
            chunks => {
                for chunk in chunks.chunks() {
                    self.extend_from_slice(chunk);
                }
            }
        }
    }

    /// Append bytes from a slice.
    ///
    /// Panics if the write would extend beyond the `len` given to [`Self::new()`],
    /// which indicates a bug in the calling `MessageEncrypter` implementation (see
    /// the type-level documentation).
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.buf[self.used..self.used + slice.len()].copy_from_slice(slice);
        self.used += slice.len();
    }

    /// Consume this value, returning the written prefix of the wrapped buffer.
    pub fn into_written(self) -> &'a [u8] {
        &self.buf[..self.used]
    }
}

impl AsMut<[u8]> for EncryptBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }
}

/// An externally length'd payload
///
/// When encountered in an [`EncodedMessage`], it represents a plaintext payload. It can be
/// decrypted from an [`InboundOpaque`] or encrypted by a
/// [`MessageEncrypter`](crate::crypto::cipher::MessageEncrypter), and it is also used for
/// joining and fragmenting.
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
            None => return ContentType(0),
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
    fn encrypt_buffer_appends() {
        let mut space = [0u8; 8];
        let mut buf = EncryptBuffer::new(&mut space[..], 6).unwrap();
        buf.extend_from_slice(&[1, 2]);
        buf.extend_from_chunks(&OutboundPlain::new(&[&[3u8, 4][..], &[5][..]]));
        buf.extend_from_slice(&[6]);
        assert_eq!(buf.as_mut(), &mut [1, 2, 3, 4, 5, 6]);
        assert_eq!(buf.into_written(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(space, [1, 2, 3, 4, 5, 6, 0, 0]);
    }

    #[test]
    fn encrypt_buffer_rejects_short_buffer() {
        let mut space = [0u8; 4];
        assert!(matches!(
            EncryptBuffer::new(&mut space[..], 5),
            Err(Error::ApiMisuse(ApiMisuse::EncryptBufferTooSmall {
                required: 5,
                provided: 4,
            }))
        ));
    }

    #[test]
    fn chunks_iteration() {
        // `Single` yields its chunk, unless empty
        assert_eq!(
            OutboundPlain::Single(&[1, 2, 3])
                .chunks()
                .collect::<Vec<_>>(),
            [&[1u8, 2, 3][..]],
        );
        assert_eq!(
            OutboundPlain::new_empty()
                .chunks()
                .count(),
            0
        );

        // `Multiple` yields the in-window part of each chunk, skipping
        // empty chunks
        let owner: Vec<&[u8]> = vec![&[], &[1, 2, 3], &[], &[4, 5], &[], &[6, 7], &[]];
        let (_, tail) = OutboundPlain::new(&owner).split_at(1);
        let (window, _) = tail.split_at(5);
        assert_eq!(
            window.chunks().collect::<Vec<_>>(),
            [&[2u8, 3][..], &[4, 5][..], &[6][..]],
        );
    }

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
