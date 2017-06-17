use msgs::codec;
use msgs::codec::{Codec, Reader};
use key;
/// An externally length'd payload
#[derive(Debug, Clone, PartialEq)]
pub struct Payload(pub Vec<u8>);

impl Codec for Payload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Payload> {
        Some(Payload(r.rest().to_vec()))
    }
}

impl Payload {
    pub fn new(bytes: Vec<u8>) -> Payload {
        Payload(bytes)
    }

    pub fn empty() -> Payload {
        Payload::new(Vec::new())
    }

    pub fn from_slice(data: &[u8]) -> Payload {
        let mut v = Vec::with_capacity(data.len());
        v.extend_from_slice(data);
        Payload(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Codec for key::Certificate {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_u24(self.0.len() as u32, bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<key::Certificate> {
        let len = try_ret!(codec::read_u24(r)) as usize;
        let mut sub = try_ret!(r.sub(len));
        let body = sub.rest().to_vec();
        Some(key::Certificate(body))
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(bytes: Vec<u8>) -> PayloadU16 {
        PayloadU16(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Codec for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_u16(self.0.len() as u16, bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<PayloadU16> {
        let len = try_ret!(codec::read_u16(r)) as usize;
        let mut sub = try_ret!(r.sub(len));
        let body = sub.rest().to_vec();
        Some(PayloadU16(body))
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadU8(pub Vec<u8>);

impl PayloadU8 {
    pub fn new(bytes: Vec<u8>) -> PayloadU8 {
        PayloadU8(bytes)
    }

    pub fn empty() -> PayloadU8 {
        PayloadU8(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Codec for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_u8(self.0.len() as u8, bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<PayloadU8> {
        let len = try_ret!(codec::read_u8(r)) as usize;
        let mut sub = try_ret!(r.sub(len));
        let body = sub.rest().to_vec();
        Some(PayloadU8(body))
    }
}
