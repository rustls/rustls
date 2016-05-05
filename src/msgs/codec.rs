use std::fmt::Debug;

/* Read from a byte slice. */
pub struct Reader<'a> {
  buf: &'a [u8],
  offs: usize
}

impl<'a> Reader<'a> {
  pub fn init(bytes: &[u8]) -> Reader {
    Reader { buf: bytes, offs: 0 }
  }
  
  pub fn rest(&self) -> &[u8] {
    &self.buf[self.offs ..]
  }

  pub fn take(&mut self, len: usize) -> Option<&[u8]> {
    if self.left() < len {
      return None
    }

    let current = self.offs;
    self.offs += len;
    Some(&self.buf[current .. current + len])
  }

  pub fn any_left(&self) -> bool {
    self.offs < self.buf.len()
  }

  pub fn left(&self) -> usize {
    self.buf.len() - self.offs
  }

  pub fn sub(&mut self, len: usize) -> Option<Reader> {
    self.take(len).and_then(|bytes| Some(Reader::init(bytes)))
  }
}

/* Things we can encode and read from a Reader. */
pub trait Codec : Debug + Sized {
  fn encode(&self, bytes: &mut Vec<u8>);
  fn read(&mut Reader) -> Option<Self>;
}

/* Encoding functions. */
pub fn encode_u8(v: u8, bytes: &mut Vec<u8>) {
  bytes.push(v);
}

fn decode_u8(bytes: &[u8]) -> Option<u8> {
  Some(bytes[0])
}

pub fn read_u8(r: &mut Reader) -> Option<u8> {
  r.take(1).and_then(decode_u8)
}

pub fn encode_u16(v: u16, bytes: &mut Vec<u8>) {
  bytes.push((v >> 8) as u8);
  bytes.push(v as u8);
}

fn decode_u16(bytes: &[u8]) -> Option<u16> {
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

fn decode_u24(bytes: &[u8]) -> Option<u32> {
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

fn decode_u32(bytes: &[u8]) -> Option<u32> {
  Some(
       ((bytes[0] as u32) << 24) |
       ((bytes[1] as u32) << 16) |
       ((bytes[2] as u32) << 8) |
       bytes[3] as u32
      )
}

pub fn read_u32(r: &mut Reader) -> Option<u32> {
  r.take(4).and_then(decode_u32)
}

pub fn encode_vec_u8<T: Codec>(bytes: &mut Vec<u8>, items: &Vec<T>) {
  let mut sub: Vec<u8> = Vec::new();
  for i in items {
    i.encode(&mut sub);
  }

  assert!(sub.len() <= 0xff);
  encode_u8(sub.len() as u8, bytes);
  bytes.append(&mut sub);
}

pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, items: &Vec<T>) {
  let mut sub: Vec<u8> = Vec::new();
  for i in items {
    i.encode(&mut sub);
  }

  assert!(sub.len() <= 0xffff);
  encode_u16(sub.len() as u16, bytes);
  bytes.append(&mut sub);
}

pub fn encode_vec_u24<T: Codec>(bytes: &mut Vec<u8>, items: &Vec<T>) {
  let mut sub: Vec<u8> = Vec::new();
  for i in items {
    i.encode(&mut sub);
  }

  assert!(sub.len() <= 0xffffff);
  encode_u24(sub.len() as u32, bytes);
  bytes.append(&mut sub);
}

pub fn read_vec_u8<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
  let mut ret: Vec<T> = Vec::new();
  let len = try_ret!(read_u8(r)) as usize;
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

pub fn read_vec_u24<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
  let mut ret: Vec<T> = Vec::new();
  let len = try_ret!(read_u24(r)) as usize;
  let mut sub = try_ret!(r.sub(len));

  while sub.any_left() {
    ret.push(try_ret!(T::read(&mut sub)));
  }

  Some(ret)
}
