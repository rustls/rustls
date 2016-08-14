use msgs::codec;
use msgs::codec::{Codec, Reader};

/* An externally length'd payload */
#[derive(Debug, Clone)]
pub struct Payload {
  pub body: Box<[u8]>
}

impl Codec for Payload {
  fn encode(&self, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&self.body);
  }

  fn read(r: &mut Reader) -> Option<Payload> {
    Some(Payload { body: r.rest().to_vec().into_boxed_slice() })
  }
}

impl Payload {
  pub fn new(bytes: Vec<u8>) -> Payload {
    Payload { body: bytes.into_boxed_slice() }
  }

  pub fn len(&self) -> usize { self.body.len() }
}

/* An arbitrary, unknown-content, u24-length-prefixed payload */
#[derive(Debug, Clone)]
pub struct PayloadU24 {
  pub body: Box<[u8]>
}

impl PayloadU24 {
  pub fn new(bytes: Vec<u8>) -> PayloadU24 {
    PayloadU24 { body: bytes.into_boxed_slice() }
  }
}

impl Codec for PayloadU24 {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u24(self.body.len() as u32, bytes);
    bytes.extend_from_slice(&self.body);
  }

  fn read(r: &mut Reader) -> Option<PayloadU24> {
    let len = try_ret!(codec::read_u24(r)) as usize;
    let sub = try_ret!(r.sub(len));
    let body = sub.rest().to_vec().into_boxed_slice();
    Some(PayloadU24 { body: body })
  }
}

/* An arbitrary, unknown-content, u16-length-prefixed payload */
#[derive(Debug, Clone)]
pub struct PayloadU16 {
  pub body: Box<[u8]>
}

impl PayloadU16 {
  pub fn new(bytes: Vec<u8>) -> PayloadU16 {
    PayloadU16 { body: bytes.into_boxed_slice() }
  }
}

impl Codec for PayloadU16 {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u16(self.body.len() as u16, bytes);
    bytes.extend_from_slice(&self.body);
  }

  fn read(r: &mut Reader) -> Option<PayloadU16> {
    let len = try_ret!(codec::read_u16(r)) as usize;
    let sub = try_ret!(r.sub(len));
    let body = sub.rest().to_vec().into_boxed_slice();
    Some(PayloadU16 { body: body })
  }
}

/* An arbitrary, unknown-content, u8-length-prefixed payload */
#[derive(Debug, Clone)]
pub struct PayloadU8 {
  pub body: Box<[u8]>
}

impl PayloadU8 {
  pub fn new(bytes: Vec<u8>) -> PayloadU8 {
    PayloadU8 { body: bytes.into_boxed_slice() }
  }
}

impl Codec for PayloadU8 {
  fn encode(&self, bytes: &mut Vec<u8>) {
    codec::encode_u8(self.body.len() as u8, bytes);
    bytes.extend_from_slice(&self.body);
  }

  fn read(r: &mut Reader) -> Option<PayloadU8> {
    let len = try_ret!(codec::read_u8(r)) as usize;
    let sub = try_ret!(r.sub(len));
    let body = sub.rest().to_vec().into_boxed_slice();
    Some(PayloadU8 { body: body })
  }
}

