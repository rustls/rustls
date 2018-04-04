use std::fmt::Debug;

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
        self.take(len).and_then(|bytes| Some(Reader::init(bytes)))
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(&mut Reader) -> Option<Self>;

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
pub fn decode_u8(bytes: &[u8]) -> Option<u8> {
    Some(bytes[0])
}

impl Codec for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }
    fn read(r: &mut Reader) -> Option<u8> {
        r.take(1).and_then(decode_u8)
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    out[0] = (v >> 8) as u8;
    out[1] = v as u8;
}

pub fn encode_u16(v: u16, bytes: &mut Vec<u8>) {
    let mut b16 = [0u8; 2];
    put_u16(v, &mut b16);
    bytes.extend_from_slice(&b16);
}

pub fn decode_u16(bytes: &[u8]) -> Option<u16> {
    Some(((bytes[0] as u16) << 8) | bytes[1] as u16)
}

pub fn read_u16(r: &mut Reader) -> Option<u16> {
    r.take(2).and_then(decode_u16)
}

pub fn encode_u24(v: u32, bytes: &mut Vec<u8>) {
    bytes.push((v >> 16) as u8);
    bytes.push((v >> 8) as u8);
    bytes.push(v as u8);
}

pub fn decode_u24(bytes: &[u8]) -> Option<u32> {
    Some(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
}

pub fn read_u24(r: &mut Reader) -> Option<u32> {
    r.take(3).and_then(decode_u24)
}

pub fn encode_u32(v: u32, bytes: &mut Vec<u8>) {
    bytes.push((v >> 24) as u8);
    bytes.push((v >> 16) as u8);
    bytes.push((v >> 8) as u8);
    bytes.push(v as u8);
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(((bytes[0] as u32) << 24) | ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) |
         bytes[3] as u32)
}

pub fn read_u32(r: &mut Reader) -> Option<u32> {
    r.take(4).and_then(decode_u32)
}

pub fn encode_u64(v: u64, bytes: &mut Vec<u8>) {
    let mut b64 = [0u8; 8];
    put_u64(v, &mut b64);
    bytes.extend_from_slice(&b64);
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    bytes[0] = (v >> 56) as u8;
    bytes[1] = (v >> 48) as u8;
    bytes[2] = (v >> 40) as u8;
    bytes[3] = (v >> 32) as u8;
    bytes[4] = (v >> 24) as u8;
    bytes[5] = (v >> 16) as u8;
    bytes[6] = (v >> 8) as u8;
    bytes[7] = v as u8;
}

pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    Some(((bytes[0] as u64) << 56) | ((bytes[1] as u64) << 48) | ((bytes[2] as u64) << 40) |
         ((bytes[3] as u64) << 32) | ((bytes[4] as u64) << 24) |
         ((bytes[5] as u64) << 16) |
         ((bytes[6] as u64) << 8) | bytes[7] as u64)
}

pub fn read_u64(r: &mut Reader) -> Option<u64> {
    r.take(8).and_then(decode_u64)
}

pub fn encode_vec_u8<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xff);
    (sub.len() as u8).encode(bytes);
    bytes.append(&mut sub);
}

pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xffff);
    encode_u16(sub.len() as u16, bytes);
    bytes.append(&mut sub);
}

pub fn encode_vec_u24<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let mut sub: Vec<u8> = Vec::new();
    for i in items {
        i.encode(&mut sub);
    }

    debug_assert!(sub.len() <= 0xffffff);
    encode_u24(sub.len() as u32, bytes);
    bytes.append(&mut sub);
}

pub fn read_vec_u8<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = try_ret!(u8::read(r)) as usize;
    let mut sub = try_ret!(r.sub(len));

    while sub.any_left() {
        ret.push(try_ret!(T::read(&mut sub)));
    }

    Some(ret)
}

pub fn read_vec_u16<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = try_ret!(read_u16(r)) as usize;
    let mut sub = try_ret!(r.sub(len));

    while sub.any_left() {
        ret.push(try_ret!(T::read(&mut sub)));
    }

    Some(ret)
}

pub fn read_vec_u24_limited<T: Codec>(r: &mut Reader, max_bytes: usize) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = try_ret!(read_u24(r)) as usize;
    if len > max_bytes {
        return None;
    }

    let mut sub = try_ret!(r.sub(len));

    while sub.any_left() {
        ret.push(try_ret!(T::read(&mut sub)));
    }

    Some(ret)
}
