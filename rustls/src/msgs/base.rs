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
pub(crate) struct SizedPayload<'a, L, C: Cardinality = MaybeEmpty> {
    pub(crate) inner: Payload<'a>,
    pub(crate) _marker: PhantomData<(L, C)>,
}

impl<L, C: Cardinality> SizedPayload<'_, L, C> {
    pub(crate) fn into_owned(self) -> SizedPayload<'static, L, C> {
        SizedPayload {
            inner: self.inner.into_owned(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.inner.into_owned().into_vec()
    }

    pub(crate) fn as_mut(&mut self) -> Option<&mut [u8]> {
        match &mut self.inner {
            Payload::Owned(vec) => Some(vec.as_mut_slice()),
            Payload::Borrowed(_) => None,
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.inner.bytes().to_vec()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inner.bytes().is_empty()
    }
}

impl<'a, L: PayloadSize<'a>> SizedPayload<'a, L, MaybeEmpty> {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            inner: Payload::Borrowed(&[]),
            _marker: PhantomData,
        }
    }
}

impl<'a, L: PayloadSize<'a>, C: Cardinality> Codec<'a> for SizedPayload<'a, L, C> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = self.inner.bytes();
        debug_assert!(inner.len() >= C::MIN);
        debug_assert!(inner.len() <= L::MAX);
        L::length(inner).encode(bytes);
        bytes.extend_from_slice(inner);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = L::read(r)?.into();
        if len < C::MIN {
            return Err(InvalidMessage::IllegalEmptyList("SizedPayload"));
        }
        let mut sub = r.sub(len)?;
        Ok(Self {
            inner: Payload::read(&mut sub),
            _marker: PhantomData,
        })
    }
}

impl<'a, L: PayloadSize<'a>, C: Cardinality> From<Payload<'a>> for SizedPayload<'a, L, C> {
    fn from(inner: Payload<'a>) -> Self {
        debug_assert!(inner.bytes().len() >= C::MIN);
        debug_assert!(inner.bytes().len() <= L::MAX);
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<'a, L: PayloadSize<'a>, C: Cardinality> From<Vec<u8>> for SizedPayload<'a, L, C> {
    fn from(inner: Vec<u8>) -> Self {
        debug_assert!(inner.len() >= C::MIN);
        debug_assert!(inner.len() <= L::MAX);
        Self {
            inner: Payload::Owned(inner),
            _marker: PhantomData,
        }
    }
}

impl<'a, L: PayloadSize<'a>, C: Cardinality> AsRef<[u8]> for SizedPayload<'a, L, C> {
    fn as_ref(&self) -> &[u8] {
        self.inner.bytes()
    }
}

impl<'a, L: PayloadSize<'a>, C: Cardinality> fmt::Debug for SizedPayload<'a, L, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
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

impl<'a> PayloadSize<'a> for U24 {
    fn length(bytes: &[u8]) -> Self {
        Self(bytes.len() as u32)
    }

    const MAX: usize = 0xFFFFFF;
}

impl<'a> PayloadSize<'a> for u16 {
    fn length(bytes: &[u8]) -> Self {
        bytes.len() as Self
    }

    const MAX: usize = 0xFFFF;
}

pub(crate) trait PayloadSize<'a>: Codec<'a> + Into<usize> {
    fn length(bytes: &[u8]) -> Self;

    const MAX: usize;
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
