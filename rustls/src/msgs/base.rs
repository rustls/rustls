use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use zeroize::Zeroize;

use crate::crypto::cipher::Payload;
use crate::error::InvalidMessage;
use crate::msgs::codec::{
    CERTIFICATE_MAX_SIZE_LIMIT, Codec, LengthPrefixedBuffer, ListLength, Reader, TlsListElement,
    U24,
};

impl<'a> Codec<'a> for CertificateDer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let nest = LengthPrefixedBuffer::new(Self::SIZE_LEN, bytes);
        nest.buf.extend(self.as_ref());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = ListLength::NonZeroU24 {
            max: CERTIFICATE_MAX_SIZE_LIMIT,
            empty_error: InvalidMessage::IllegalEmptyList("CertificateDer"),
            too_many_error: InvalidMessage::CertificatePayloadTooLarge,
        }
        .read(r)?;

        let mut sub = r.sub(len)?;
        let body = sub.rest();
        Ok(Self::from(body))
    }
}

impl<'a> Codec<'a> for SubjectPublicKeyInfoDer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let nest = LengthPrefixedBuffer::new(Self::SIZE_LEN, bytes);
        nest.buf.extend(self.as_ref());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = Self::SIZE_LEN.read(r)?;
        let mut sub = r.sub(len)?;
        let body = sub.rest();
        Ok(Self::from(body))
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PayloadU24<'a, C: Cardinality = MaybeEmpty>(Payload<'a>, PhantomData<C>);

impl<C: Cardinality> PayloadU24<'_, C> {
    pub(crate) fn into_owned(self) -> PayloadU24<'static, C> {
        PayloadU24(self.0.into_owned(), PhantomData)
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0.into_owned().into_vec()
    }
}

impl<'a, C: Cardinality> Codec<'a> for PayloadU24<'a, C> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = self.0.bytes();
        debug_assert!(inner.len() >= C::MIN);
        U24(inner.len() as u32).encode(bytes);
        bytes.extend_from_slice(inner);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = U24::read(r)?.0 as usize;
        if len < C::MIN {
            return Err(InvalidMessage::IllegalEmptyList("PayloadU24"));
        }
        let mut sub = r.sub(len)?;
        Ok(Self(Payload::read(&mut sub), PhantomData))
    }
}

impl<'a, C: Cardinality> From<Payload<'a>> for PayloadU24<'a, C> {
    fn from(value: Payload<'a>) -> Self {
        debug_assert!(value.bytes().len() >= C::MIN);
        Self(value, PhantomData)
    }
}

impl<C: Cardinality> AsRef<[u8]> for PayloadU24<'_, C> {
    fn as_ref(&self) -> &[u8] {
        self.0.bytes()
    }
}

impl<C: Cardinality> fmt::Debug for PayloadU24<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
///
/// The `C` type parameter controls whether decoded values may
/// be empty.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PayloadU16<C: Cardinality = MaybeEmpty>(pub(crate) Vec<u8>, PhantomData<C>);

impl<C: Cardinality> PayloadU16<C> {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        debug_assert!(bytes.len() >= C::MIN);
        Self(bytes, PhantomData)
    }
}

impl PayloadU16<MaybeEmpty> {
    pub(crate) fn empty() -> Self {
        Self::new(Vec::new())
    }
}

impl<C: Cardinality> Codec<'_> for PayloadU16<C> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.0.len() >= C::MIN);
        (self.0.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = u16::read(r)? as usize;
        if len < C::MIN {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body, PhantomData))
    }
}

impl<C: Cardinality> fmt::Debug for PayloadU16<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
///
/// `C` controls the minimum length accepted when decoding.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PayloadU8<C: Cardinality = MaybeEmpty>(pub(crate) Vec<u8>, PhantomData<C>);

impl<C: Cardinality> PayloadU8<C> {
    pub(crate) fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u8).encode(bytes);
        bytes.extend_from_slice(slice);
    }

    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        debug_assert!(bytes.len() >= C::MIN);
        Self(bytes, PhantomData)
    }
}

impl PayloadU8<MaybeEmpty> {
    pub(crate) fn empty() -> Self {
        Self(Vec::new(), PhantomData)
    }
}

impl<C: Cardinality> Codec<'_> for PayloadU8<C> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.0.len() >= C::MIN);
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        if len < C::MIN {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Ok(Self(body, PhantomData))
    }
}

impl<C: Cardinality> Zeroize for PayloadU8<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<C: Cardinality> fmt::Debug for PayloadU8<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, &self.0)
    }
}

pub(crate) trait Cardinality: Clone + Eq + PartialEq {
    const MIN: usize;
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MaybeEmpty;

impl Cardinality for MaybeEmpty {
    const MIN: usize = 0;
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NonEmpty;

impl Cardinality for NonEmpty {
    const MIN: usize = 1;
}

// Format an iterator of u8 into a hex string
pub(crate) fn hex<'a>(
    f: &mut fmt::Formatter<'_>,
    payload: impl IntoIterator<Item = &'a u8>,
) -> fmt::Result {
    for b in payload {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}
