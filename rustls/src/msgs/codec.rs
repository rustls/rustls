use std::convert::TryInto;
use std::fmt::Debug;

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    pub fn init(bytes: &'a [u8]) -> Reader<'a> {
        Reader {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let ret = &self.buf[self.offs..];
        self.offs = self.buf.len();
        ret
    }

    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        self.offs += len;
        Some(&self.buf[current..current + len])
    }

    pub fn any_left(&self) -> bool {
        self.offs < self.buf.len()
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn sub(&mut self, len: usize) -> Option<Reader<'a>> {
        self.take(len).map(Reader::init)
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec<'a>: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader<'a>) -> Option<Self>;

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(bytes: &'a [u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

// Encoding functions.
fn decode_u8(bytes: &[u8]) -> Option<u8> {
    let [value]: [u8; 1] = bytes.try_into().ok()?;
    Some(value)
}

impl<'a> Codec<'a> for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }
    fn read(r: &mut Reader) -> Option<u8> {
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

impl<'a> Codec<'a> for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.extend_from_slice(&b16);
    }

    fn read(r: &mut Reader) -> Option<u16> {
        r.take(2).and_then(decode_u16)
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct u24(pub u32);

impl u24 {
    pub fn decode(bytes: &[u8]) -> Option<u24> {
        let [a, b, c]: [u8; 3] = bytes.try_into().ok()?;
        Some(u24(u32::from_be_bytes([0, a, b, c])))
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<u24> for usize {
    #[inline]
    fn from(v: u24) -> usize {
        v.0 as usize
    }
}

impl<'a> Codec<'a> for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = u32::to_be_bytes(self.0);
        bytes.extend_from_slice(&be_bytes[1..])
    }

    fn read(r: &mut Reader) -> Option<u24> {
        r.take(3).and_then(u24::decode)
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

impl<'a> Codec<'a> for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(&u32::to_be_bytes(*self))
    }

    fn read(r: &mut Reader) -> Option<u32> {
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

impl<'a> Codec<'a> for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.extend_from_slice(&b64);
    }

    fn read(r: &mut Reader) -> Option<u64> {
        r.take(8).and_then(decode_u64)
    }
}

pub fn encode_vec_u8<'a, T>(bytes: &mut Vec<u8>, items: &[T])
where
    T: Codec<'a>,
{
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xff);
    (sub.len() as u8).encode(bytes);
    bytes.append(&mut sub);
}

pub fn encode_vec_u16<'a, T>(bytes: &mut Vec<u8>, items: &[T])
where
    T: Codec<'a>,
{
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xffff);
    (sub.len() as u16).encode(bytes);
    bytes.append(&mut sub);
}

pub fn encode_vec_u24<'a, T>(bytes: &mut Vec<u8>, items: &[T])
where
    T: Codec<'a>,
{
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xff_ffff);
    u24(sub.len() as u32).encode(bytes);
    bytes.append(&mut sub);
}

pub fn read_vec_u8<'a, T: Codec<'a>>(r: &mut Reader<'a>) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u8::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u16<'a, T: Codec<'a>>(r: &mut Reader<'a>) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u16::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u24_limited<'a, T: Codec<'a>>(
    r: &mut Reader<'a>,
    max_bytes: usize,
) -> Option<Vec<T>> {
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
