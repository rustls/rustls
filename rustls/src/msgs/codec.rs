use std::convert::TryInto;
use std::fmt::Debug;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    pub fn init(bytes: &[u8]) -> Reader {
        Reader {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn rest(&mut self) -> &[u8] {
        let ret = &self.buf[self.offs..];
        self.offs = self.buf.len();
        ret
    }

    pub fn take(&mut self, len: usize) -> Option<&[u8]> {
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

    pub fn sub(&mut self, len: usize) -> Option<Reader> {
        self.take(len).map(Reader::init)
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

// Encoding functions.
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
        bytes.extend(&Self::to_be_bytes(*self))
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

/// Represent a Rust `Vec` together with the length prefix type used to encode it in TLS.
///
/// This implements various traits to make it easy to use in place of a normal `Vec` and to
/// easily convert between `Vec` and `TlsVec` at API boundaries.
#[derive(Clone, Debug)]
pub struct TlsVec<L, T> {
    items: Vec<T>,
    len: PhantomData<L>,
}

impl<L: LengthPrefix, T: Codec> Codec for TlsVec<L, T>
where
    usize: From<L>,
{
    fn encode(&self, bytes: &mut Vec<u8>) {
        let len_offset = bytes.len();
        bytes.extend(L::ZERO_LEN);

        for i in &self.items {
            i.encode(bytes);
        }

        let len = bytes.len() - len_offset - L::BYTES;
        L::write_into(len, len_offset, bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = usize::from(L::read(r)?);
        if len > MAX_VEC_BYTES {
            return None;
        }

        let mut sub = r.sub(len)?;
        let mut items = Vec::with_capacity(len);
        while sub.any_left() {
            items.push(T::read(&mut sub)?);
        }

        Some(Self {
            items,
            len: PhantomData,
        })
    }
}

impl<L, A> FromIterator<A> for TlsVec<L, A> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        Vec::from_iter(iter).into()
    }
}

impl<'a, L, T> IntoIterator for &'a TlsVec<L, T> {
    type Item = &'a T;

    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        (&self.items).iter()
    }
}

impl<L, T> Deref for TlsVec<L, T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<L, T> DerefMut for TlsVec<L, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.items
    }
}

impl<L, T> From<TlsVec<L, T>> for Vec<T> {
    fn from(tls: TlsVec<L, T>) -> Self {
        tls.items
    }
}

impl<L, T> From<Vec<T>> for TlsVec<L, T> {
    fn from(items: Vec<T>) -> Self {
        Self {
            items,
            len: PhantomData,
        }
    }
}

impl<L, T> Default for TlsVec<L, T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            len: Default::default(),
        }
    }
}

const MAX_VEC_BYTES: usize = 0x1_0000;

#[allow(clippy::use_self)]
impl LengthPrefix for u8 {
    fn write_into(len: usize, offset: usize, bytes: &mut [u8]) {
        debug_assert!(len <= 0xff);
        bytes[offset] = len as u8;
    }

    const BYTES: usize = 1;
    const ZERO_LEN: &'static [u8] = &[0];
}

#[allow(clippy::use_self)]
impl LengthPrefix for u16 {
    fn write_into(len: usize, offset: usize, bytes: &mut [u8]) {
        debug_assert!(len <= 0xffff);
        let out: &mut [u8; 2] = (&mut bytes[offset..offset + 2])
            .try_into()
            .unwrap();
        *out = Self::to_be_bytes(len as u16);
    }

    const BYTES: usize = 2;
    const ZERO_LEN: &'static [u8] = &[0, 0];
}

impl LengthPrefix for u24 {
    fn write_into(len: usize, offset: usize, bytes: &mut [u8]) {
        debug_assert!(len <= 0xff_ffff);
        let len_bytes = u32::to_be_bytes(len as u32);
        let out: &mut [u8; 3] = (&mut bytes[offset..offset + 3])
            .try_into()
            .unwrap();
        out.copy_from_slice(&len_bytes[1..]);
    }

    const BYTES: usize = 3;
    const ZERO_LEN: &'static [u8] = &[0, 0, 0];
}

pub trait LengthPrefix: Codec + Copy + Debug {
    fn write_into(len: usize, offset: usize, bytes: &mut [u8]);

    const BYTES: usize;
    const ZERO_LEN: &'static [u8];
}
