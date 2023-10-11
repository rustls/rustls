use crate::error::InvalidMessage;

use alloc::vec::Vec;
use core::fmt::Debug;

/// Wrapper over a slice of bytes that allows reading chunks from
/// with the current position state held using a cursor.
///
/// A new reader for a sub section of the the buffer can be created
/// using the `sub` function or a section of a certain length can
/// be obtained using the `take` function
pub struct Reader<'a> {
    /// The underlying buffer storing the readers content
    buffer: &'a [u8],
    /// Stores the current reading position for the buffer
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new Reader of the provided `bytes` slice with
    /// the initial cursor position of zero.
    pub fn init(bytes: &[u8]) -> Reader {
        Reader {
            buffer: bytes,
            cursor: 0,
        }
    }

    /// Attempts to create a new Reader on a sub section of this
    /// readers bytes by taking a slice of the provided `length`
    /// will return None if there is not enough bytes
    pub fn sub(&mut self, length: usize) -> Result<Reader, InvalidMessage> {
        match self.take(length) {
            Some(bytes) => Ok(Reader::init(bytes)),
            None => Err(InvalidMessage::MessageTooShort),
        }
    }

    /// Borrows a slice of all the remaining bytes
    /// that appear after the cursor position.
    ///
    /// Moves the cursor to the end of the buffer length.
    pub fn rest(&mut self) -> &[u8] {
        let rest = &self.buffer[self.cursor..];
        self.cursor = self.buffer.len();
        rest
    }

    /// Attempts to borrow a slice of bytes from the current
    /// cursor position of `length` if there is not enough
    /// bytes remaining after the cursor to take the length
    /// then None is returned instead.
    pub fn take(&mut self, length: usize) -> Option<&[u8]> {
        if self.left() < length {
            return None;
        }
        let current = self.cursor;
        self.cursor += length;
        Some(&self.buffer[current..current + length])
    }

    /// Used to check whether the reader has any content left
    /// after the cursor (cursor has not reached end of buffer)
    pub fn any_left(&self) -> bool {
        self.cursor < self.buffer.len()
    }

    pub fn expect_empty(&self, name: &'static str) -> Result<(), InvalidMessage> {
        match self.any_left() {
            true => Err(InvalidMessage::TrailingData(name)),
            false => Ok(()),
        }
    }

    /// Returns the cursor position which is also the number
    /// of bytes that have been read from the buffer.
    pub fn used(&self) -> usize {
        self.cursor
    }

    /// Returns the number of bytes that are still able to be
    /// read (The number of remaining takes)
    pub fn left(&self) -> usize {
        self.buffer.len() - self.cursor
    }
}

pub(crate) mod byte_buffer {
    use super::SliceBuffer;
    use alloc::vec::Vec;

    #[allow(clippy::len_without_is_empty)]
    pub trait ByteBuffer {
        fn len(&self) -> usize;

        fn get_array_mut<const N: usize>(&mut self, offset: usize) -> &mut [u8; N];
    }

    impl ByteBuffer for Vec<u8> {
        fn len(&self) -> usize {
            Self::len(self)
        }

        fn get_array_mut<const N: usize>(&mut self, offset: usize) -> &mut [u8; N] {
            (&mut self[offset..offset + N])
                .try_into()
                .unwrap()
        }
    }

    impl<'b> ByteBuffer for SliceBuffer<'b> {
        fn len(&self) -> usize {
            self.discard
        }

        fn get_array_mut<const N: usize>(&mut self, mut offset: usize) -> &mut [u8; N] {
            offset += self.discard;
            (&mut self.slice[offset..offset + N])
                .try_into()
                .unwrap()
        }
    }
}

pub trait PushBytes: byte_buffer::ByteBuffer {
    fn push_bytes(&mut self, bytes: &[u8]);
}

pub trait TryPushBytes: byte_buffer::ByteBuffer {
    type Error;

    fn try_push_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

impl<B: PushBytes> TryPushBytes for B {
    type Error = core::convert::Infallible;

    fn try_push_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.push_bytes(bytes);
        Ok(())
    }
}

impl PushBytes for Vec<u8> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

pub(crate) struct NotEnoughBytes {}

pub(crate) struct SliceBuffer<'b> {
    discard: usize,
    slice: &'b mut [u8],
}

impl<'b> TryPushBytes for SliceBuffer<'b> {
    type Error = NotEnoughBytes;

    fn try_push_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let slice = self
            .slice
            .get_mut(self.discard..self.discard + bytes.len())
            .ok_or(NotEnoughBytes {})?;

        slice.copy_from_slice(bytes);
        self.discard += bytes.len();

        Ok(())
    }
}

/// Trait for implementing encoding and decoding functionality
/// on something.
pub trait Codec: Debug + Sized {
    /// Function for encoding itself by appending itself to
    /// the provided buffer of bytes.
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error>;

    /// Function for encoding itself by appending itself to
    /// the provided buffer of bytes.
    fn encode<B: PushBytes>(&self, bytes: &mut B) {
        if let Err(err) = self.try_encode(bytes) {
            match err {}
        }
    }

    /// Function for decoding itself from the provided reader
    /// will return Some if the decoding was successful or
    /// None if it was not.
    fn read(_: &mut Reader) -> Result<Self, InvalidMessage>;

    /// Convenience function for encoding the implementation
    /// into a vec and returning it
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    /// Function for wrapping a call to the read function in
    /// a Reader for the slice of bytes provided
    fn read_bytes(bytes: &[u8]) -> Result<Self, InvalidMessage> {
        let mut reader = Reader::init(bytes);
        Self::read(&mut reader)
    }
}

impl Codec for u8 {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        bytes.try_push_bytes(&[*self])
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        match r.take(1) {
            Some(&[byte]) => Ok(byte),
            _ => Err(InvalidMessage::MissingData("u8")),
        }
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    let out: &mut [u8; 2] = (&mut out[..2]).try_into().unwrap();
    *out = u16::to_be_bytes(v);
}

impl Codec for u16 {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.try_push_bytes(&b16)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        match r.take(2) {
            Some(&[b1, b2]) => Ok(Self::from_be_bytes([b1, b2])),
            _ => Err(InvalidMessage::MissingData("u8")),
        }
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u24(pub u32);

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<u24> for usize {
    #[inline]
    fn from(v: u24) -> Self {
        v.0 as Self
    }
}

impl Codec for u24 {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        let be_bytes = u32::to_be_bytes(self.0);
        bytes.try_push_bytes(&be_bytes[1..])
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        match r.take(3) {
            Some(&[a, b, c]) => Ok(Self(u32::from_be_bytes([0, a, b, c]))),
            _ => Err(InvalidMessage::MissingData("u24")),
        }
    }
}

impl Codec for u32 {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        bytes.try_push_bytes(&Self::to_be_bytes(*self))
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        match r.take(4) {
            Some(&[a, b, c, d]) => Ok(Self::from_be_bytes([a, b, c, d])),
            _ => Err(InvalidMessage::MissingData("u32")),
        }
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v);
}

impl Codec for u64 {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.try_push_bytes(&b64)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        match r.take(8) {
            Some(&[a, b, c, d, e, f, g, h]) => Ok(Self::from_be_bytes([a, b, c, d, e, f, g, h])),
            _ => Err(InvalidMessage::MissingData("u64")),
        }
    }
}

/// Implement `Codec` for lists of elements that implement `TlsListElement`.
///
/// `TlsListElement` provides the size of the length prefix for the list.
impl<T: Codec + TlsListElement + Debug> Codec for Vec<T> {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        let nest = LengthPrefixedBuffer::try_new(T::SIZE_LEN, bytes)?;

        for i in self {
            i.try_encode(nest.buf)?;
        }

        Ok(())
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = match T::SIZE_LEN {
            ListLength::U8 => usize::from(u8::read(r)?),
            ListLength::U16 => usize::from(u16::read(r)?),
            ListLength::U24 { max } => Ord::min(usize::from(u24::read(r)?), max),
        };

        let mut sub = r.sub(len)?;
        let mut ret = Self::new();
        while sub.any_left() {
            ret.push(T::read(&mut sub)?);
        }

        Ok(ret)
    }
}

/// A trait for types that can be encoded and decoded in a list.
///
/// This trait is used to implement `Codec` for `Vec<T>`. Lists in the TLS wire format are
/// prefixed with a length, the size of which depends on the type of the list elements.
/// As such, the `Codec` implementation for `Vec<T>` requires an implementation of this trait
/// for its element type `T`.
pub(crate) trait TlsListElement {
    const SIZE_LEN: ListLength;
}

/// The length of the length prefix for a list.
///
/// The types that appear in lists are limited to three kinds of length prefixes:
/// 1, 2, and 3 bytes. For the latter kind, we require a `TlsListElement` implementer
/// to specify a maximum length.
pub(crate) enum ListLength {
    U8,
    U16,
    U24 { max: usize },
}

/// Tracks encoding a length-delimited structure in a single pass.
pub(crate) struct LengthPrefixedBuffer<'a, B: TryPushBytes> {
    pub(crate) buf: &'a mut B,
    len_offset: usize,
    size_len: ListLength,
}

#[cfg(test)]
impl<'a, B: PushBytes> LengthPrefixedBuffer<'a, B> {
    /// Inserts a dummy length into `buf`, and remembers where it went.
    ///
    /// After this, the body of the length-delimited structure should be appended to `LengthPrefixedBuffer::buf`.
    /// The length header is corrected in `LengthPrefixedBuffer::drop`.
    pub(crate) fn new(size_len: ListLength, buf: &'a mut B) -> LengthPrefixedBuffer<'a, B> {
        match Self::try_new(size_len, buf) {
            Ok(buf) => buf,
            Err(err) => match err {},
        }
    }
}

impl<'a, B: TryPushBytes> LengthPrefixedBuffer<'a, B> {
    /// Inserts a dummy length into `buf`, and remembers where it went.
    ///
    /// After this, the body of the length-delimited structure should be appended to `LengthPrefixedBuffer::buf`.
    /// The length header is corrected in `LengthPrefixedBuffer::drop`.
    pub(crate) fn try_new(
        size_len: ListLength,
        buf: &'a mut B,
    ) -> Result<LengthPrefixedBuffer<'a, B>, B::Error> {
        let len_offset = buf.len();
        buf.try_push_bytes(match size_len {
            ListLength::U8 => &[0xff][..],
            ListLength::U16 => &[0xff, 0xff],
            ListLength::U24 { .. } => &[0xff, 0xff, 0xff],
        })?;

        Ok(Self {
            buf,
            len_offset,
            size_len,
        })
    }
}

impl<'a, B: TryPushBytes> Drop for LengthPrefixedBuffer<'a, B> {
    /// Goes back and corrects the length previously inserted at the start of the structure.
    fn drop(&mut self) {
        match self.size_len {
            ListLength::U8 => {
                let len = self.buf.len() - self.len_offset - 1;
                debug_assert!(len <= 0xff);
                *self.buf.get_array_mut(self.len_offset) = [len as u8];
            }
            ListLength::U16 => {
                let len = self.buf.len() - self.len_offset - 2;
                debug_assert!(len <= 0xffff);
                *self.buf.get_array_mut(self.len_offset) = u16::to_be_bytes(len as u16);
            }
            ListLength::U24 { .. } => {
                let len = self.buf.len() - self.len_offset - 3;
                debug_assert!(len <= 0xff_ffff);
                let len_bytes = u32::to_be_bytes(len as u32);
                let out = self
                    .buf
                    .get_array_mut::<3>(self.len_offset);
                out.copy_from_slice(&len_bytes[1..]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_length_prefixed_buffer_leaves_maximum_length() {
        let mut buf = Vec::new();
        let nested = LengthPrefixedBuffer::new(ListLength::U16, &mut buf);
        nested.buf.push(0xaa);
        assert_eq!(nested.buf, &vec![0xff, 0xff, 0xaa]);
        // <- if the buffer is accidentally read here, there is no possiblity
        //    that the contents of the length-prefixed buffer are interpretted
        //    as a subsequent encoding (perhaps allowing injection of a different
        //    extension)
        drop(nested);
        assert_eq!(buf, vec![0x00, 0x01, 0xaa]);
    }
}
