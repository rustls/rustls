use std::convert::TryInto;
use std::fmt::Debug;

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
    pub fn sub(&mut self, length: usize) -> Option<Reader> {
        self.take(length).map(Reader::init)
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

/// Trait for implementing encoding and decoding functionality
/// on something.
pub trait Codec: Debug + Sized {
    /// Function for encoding itself by appending itself to
    /// the provided vec of bytes.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Function for decoding itself from the provided reader
    /// will return Some if the decoding was successful or
    /// None if it was not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Convenience function for encoding the implementation
    /// into a vec and returning it
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    /// Function for wrapping a call to the read function in
    /// a Reader for the slice of bytes provided
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::init(bytes);
        Self::read(&mut reader)
    }
}

fn decode_u8(bytes: &[u8]) -> Option<u8> {
    let [value]: [u8; 1] = bytes.try_into().ok()?;
    Some(value)
}

impl Codec for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(1).and_then(decode_u8)
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    let out: &mut [u8; 2] = (&mut out[..2]).try_into().unwrap();
    *out = u16::to_be_bytes(v);
}

pub fn decode_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.extend_from_slice(&b16);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(2).and_then(decode_u16)
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u24(pub u32);

impl u24 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [a, b, c]: [u8; 3] = bytes.try_into().ok()?;
        Some(Self(u32::from_be_bytes([0, a, b, c])))
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<u24> for usize {
    #[inline]
    fn from(v: u24) -> Self {
        v.0 as Self
    }
}

impl Codec for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = u32::to_be_bytes(self.0);
        bytes.extend_from_slice(&be_bytes[1..])
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(3).and_then(Self::decode)
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(Self::to_be_bytes(*self))
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(4).and_then(decode_u32)
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v)
}

pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.extend_from_slice(&b64);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(8).and_then(decode_u64)
    }
}

pub fn encode_vec_u8<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    debug_assert!(len <= 0xff);
    bytes[len_offset] = len as u8;
}

pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.extend([0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 2;
    debug_assert!(len <= 0xffff);
    let out: &mut [u8; 2] = (&mut bytes[len_offset..len_offset + 2])
        .try_into()
        .unwrap();
    *out = u16::to_be_bytes(len as u16);
}

pub fn encode_vec_u24<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.extend([0, 0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 3;
    debug_assert!(len <= 0xff_ffff);
    let len_bytes = u32::to_be_bytes(len as u32);
    let out: &mut [u8; 3] = (&mut bytes[len_offset..len_offset + 3])
        .try_into()
        .unwrap();
    out.copy_from_slice(&len_bytes[1..]);
}

pub fn read_vec_u8<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u8::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u16<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u16::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u24_limited<T: Codec>(r: &mut Reader, max_bytes: usize) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = u24::read(r)?.0 as usize;
    if len > max_bytes {
        return None;
    }

    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}
