use crate::error::InvalidMessage;
use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};

use alloc::vec::Vec;
use core::fmt;

use pki_types::CertificateDer;

use super::codec::PushBytes;

/// An externally length'd payload
#[derive(Clone, Eq, PartialEq)]
pub struct Payload(pub Vec<u8>);

impl Codec for Payload {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        bytes.push_bytes(&self.0)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl Payload {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn read(r: &mut Reader) -> Self {
        Self(r.rest().to_vec())
    }
}

impl<'a> Codec for CertificateDer<'a> {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        codec::u24(self.as_ref().len() as u32).encode(bytes)?;
        bytes.push_bytes(self.as_ref())
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self::from(body))
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU24(pub Vec<u8>);

impl PayloadU24 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Codec for PayloadU24 {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        codec::u24(self.0.len() as u32).encode(bytes)?;
        bytes.push_bytes(&self.0)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body))
    }
}

impl fmt::Debug for PayloadU24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    fn encode_slice<B: PushBytes>(slice: &[u8], bytes: &mut B) -> Result<(), B::Error> {
        (slice.len() as u16).encode(bytes)?;
        bytes.push_bytes(slice)
    }
}

impl Codec for PayloadU16 {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        Self::encode_slice(&self.0, bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body))
    }
}

impl fmt::Debug for PayloadU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub struct PayloadU8(pub Vec<u8>);

impl PayloadU8 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Codec for PayloadU8 {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        (self.0.len() as u8).encode(bytes)?;
        bytes.push_bytes(&self.0)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body))
    }
}

impl fmt::Debug for PayloadU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

// Format an iterator of u8 into a hex string
pub(super) fn hex<'a>(
    f: &mut fmt::Formatter<'_>,
    payload: impl IntoIterator<Item = &'a u8>,
) -> fmt::Result {
    for b in payload {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}
