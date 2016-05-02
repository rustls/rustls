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

  pub fn take(&mut self, len: usize) -> &[u8] {
    let current = self.offs;
    self.offs += len;
    &self.buf[current .. current + len]
  }

  pub fn any_left(&self) -> bool {
    self.offs < self.buf.len()
  }

  pub fn sub(&mut self, len: usize) -> Reader {
    Reader::init(self.take(len))
  }
}

/* Things we can encode. */
pub trait Codec : Debug {
  fn encode(&self, bytes: &mut Vec<u8>);
  fn decode(&mut Reader) -> Self;
}

/* Encoding functions. */
pub fn encode_u8(v: u8, bytes: &mut Vec<u8>) {
  bytes.push(v);
}

pub fn decode_u8(r: &mut Reader) -> u8 {
  r.take(1)[0]
}

pub fn encode_u16(v: u16, bytes: &mut Vec<u8>) {
  bytes.push((v >> 8) as u8);
  bytes.push(v as u8);
}

pub fn decode_u16(r: &mut Reader) -> u16 {
  let bytes = r.take(2);
  ((bytes[0] as u16) << 8) | bytes[1] as u16
}

pub fn encode_u24(v: u32, bytes: &mut Vec<u8>) {
  bytes.push((v >> 16) as u8);
  bytes.push((v >> 8) as u8);
  bytes.push(v as u8);
}

pub fn decode_u24(r: &mut Reader) -> u32 {
  let bytes = r.take(3);
  ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

pub fn encode_u32(v: u32, bytes: &mut Vec<u8>) {
  bytes.push((v >> 24) as u8);
  bytes.push((v >> 16) as u8);
  bytes.push((v >> 8) as u8);
  bytes.push(v as u8);
}

pub fn decode_u32(r: &mut Reader) -> u32 {
  let bytes = r.take(4);
  ((bytes[0] as u32) << 24) |
    ((bytes[1] as u32) << 16) |
    ((bytes[2] as u32) << 8) |
    bytes[3] as u32
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

pub fn decode_vec_u8<T: Codec>(r: &mut Reader) -> Vec<T> {
  let mut ret: Vec<T> = Vec::new();
  let len = decode_u8(r);
  let mut sub = r.sub(len as usize);

  while sub.any_left() {
    ret.push(T::decode(&mut sub));
  }

  ret
}

pub fn decode_vec_u16<T: Codec>(r: &mut Reader) -> Vec<T> {
  let mut ret: Vec<T> = Vec::new();
  let len = decode_u16(r);
  let mut sub = r.sub(len as usize);

  while sub.any_left() {
    ret.push(T::decode(&mut sub));
  }

  ret
}
