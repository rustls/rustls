use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};

use std::borrow::Cow;

/// An externally length'd payload
#[derive(Debug, PartialEq)]
pub struct Payload<'a>(pub Cow<'a, [u8]>);

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'a>) -> Option<Payload<'a>> {
        Some(Payload::read(r))
    }
}

impl<'a> Payload<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Payload(bytes.into())
    }

    pub fn empty() -> Payload<'static> {
        Payload::new(Vec::new())
    }

    pub fn to_owned(&self) -> Payload<'static> {
        Payload::new(self.0.to_vec())
    }

    pub fn read(r: &mut Reader<'a>) -> Self {
        Self::new(r.rest())
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Debug, PartialEq)]
pub struct PayloadU24<'a>(pub Cow<'a, [u8]>);

impl<'a> PayloadU24<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> PayloadU24<'a> {
        PayloadU24(bytes.into())
    }

    pub fn to_owned(&self) -> PayloadU24<'static> {
        PayloadU24::new(self.0.to_vec())
    }
}

impl<'a> Codec<'a> for PayloadU24<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'a>) -> Option<PayloadU24<'a>> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        Some(PayloadU24::new(sub.rest()))
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Debug, PartialEq)]
pub struct PayloadU16<'a>(pub Cow<'a, [u8]>);

impl<'a> PayloadU16<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> PayloadU16<'a> {
        PayloadU16(bytes.into())
    }

    pub fn empty() -> PayloadU16<'static> {
        PayloadU16::new(Vec::new())
    }

    pub fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }

    pub fn to_owned(&self) -> PayloadU16<'static> {
        PayloadU16::new(self.0.to_vec())
    }
}

impl<'a> Codec<'a> for PayloadU16<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<PayloadU16<'a>> {
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;
        Some(PayloadU16::new(sub.rest()))
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
#[derive(Debug, PartialEq)]
pub struct PayloadU8<'a>(pub Cow<'a, [u8]>);

impl<'a> PayloadU8<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> PayloadU8<'a> {
        PayloadU8(bytes.into())
    }

    pub fn empty() -> PayloadU8<'static> {
        PayloadU8(Vec::new().into())
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0.into_owned()
    }

    pub fn to_owned(&self) -> PayloadU8<'static> {
        PayloadU8::new(self.0.to_vec())
    }
}

impl<'a> Codec<'a> for PayloadU8<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'a>) -> Option<PayloadU8<'a>> {
        let len = u8::read(r)? as usize;
        let mut sub = r.sub(len)?;
        Some(PayloadU8::new(sub.rest()))
    }
}
