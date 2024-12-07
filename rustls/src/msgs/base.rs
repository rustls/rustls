use alloc::vec::Vec;
use core::fmt;

use pki_types::CertificateDer;
use zeroize::Zeroize;

use crate::error::InvalidMessage;
use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};

/// An externally length'd payload
#[derive(Clone, Eq, PartialEq)]
pub enum Payload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.bytes());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl<'a> Payload<'a> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    pub fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Borrowed(bytes) => bytes.to_vec(),
            Self::Owned(bytes) => bytes,
        }
    }

    pub fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }
}

impl Payload<'static> {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Owned(bytes.into())
    }

    pub fn empty() -> Self {
        Self::Borrowed(&[])
    }
}

impl<'a> Codec<'a> for CertificateDer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.as_ref().len() as u32).encode(bytes);
        bytes.extend(self.as_ref());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest();
        Ok(Self::from(body))
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.bytes())
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PayloadU24<'a>(pub(crate) Payload<'a>);

impl PayloadU24<'_> {
    pub(crate) fn into_owned(self) -> PayloadU24<'static> {
        PayloadU24(self.0.into_owned())
    }
}

impl<'a> Codec<'a> for PayloadU24<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = self.0.bytes();
        codec::u24(inner.len() as u32).encode(bytes);
        bytes.extend_from_slice(inner);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        Ok(Self(Payload::read(&mut sub)))
    }
}

impl fmt::Debug for PayloadU24<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

    pub fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl Codec<'_> for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
pub struct PayloadU8(pub(crate) Vec<u8>);

impl PayloadU8 {
    pub(crate) fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u8).encode(bytes);
        bytes.extend_from_slice(slice);
    }

    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }
}

impl Codec<'_> for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body))
    }
}

impl Zeroize for PayloadU8 {
    fn zeroize(&mut self) {
        self.0.zeroize();
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
