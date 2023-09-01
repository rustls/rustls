//! This crate provides types for representing X.509 certificates, keys and other types as
//! commonly used in the rustls ecosystem. It is intended to be used by crates that need to work
//! with such X.509 types, such as [rustls](https://crates.io/crates/rustls),
//! [rustls-webpki](https://crates.io/crates/rustls-webpki),
//! [rustls-pemfile](https://crates.io/crates/rustls-pemfile), and others.
//!
//! Some of these crates used to define their own trivial wrappers around DER-encoded bytes.
//! However, in order to avoid inconvenient dependency edges, these were all disconnected. By
//! using a common low-level crate of types with long-term stable API, we hope to avoid the
//! downsides of unnecessary dependency edges while providing good interoperability between crates.
//!
//! ## DER and PEM
//!
//! Many of the types defined in this crate represent DER-encoded data. DER is a binary encoding of
//! the ASN.1 format commonly used in web PKI specifications. It is a binary encoding, so it is
//! relatively compact when stored in memory. However, as a binary format, it is not very easy to
//! work with for humans and in contexts where binary data is inconvenient. For this reason,
//! many tools and protocols use a ASCII-based encoding of DER, called PEM. In addition to the
//! base64-encoded DER, PEM objects are delimited by header and footer lines which indicate the type
//! of object contained in the PEM blob.
//!
//! The [rustls-pemfile](https://docs.rs/rustls-pemfile) crate can be used to parse PEM files.
//!
//! ## Creating new certificates and keys
//!
//! This crate does not provide any functionality for creating new certificates or keys. However,
//! the [rcgen](https://docs.rs/rcgen) crate can be used to create new certificates and keys.

#![no_std]
#![warn(unreachable_pub, clippy::use_self)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// A DER-encoded X.509 private key, in one of several formats
///
/// See variant inner types for more detailed information.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum PrivateKeyDer<'a> {
    /// An RSA private key
    Pkcs1(PrivatePkcs1KeyDer<'a>),
    /// A Sec1 private key
    Sec1(PrivateSec1KeyDer<'a>),
    /// A PKCS#8 private key
    Pkcs8(PrivatePkcs8KeyDer<'a>),
}

impl<'a> PrivateKeyDer<'a> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_der(&self) -> &[u8] {
        match self {
            PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der(),
            PrivateKeyDer::Sec1(key) => key.secret_sec1_der(),
            PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der(),
        }
    }
}

impl<'a> From<PrivatePkcs1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivatePkcs1KeyDer<'a>) -> Self {
        Self::Pkcs1(key)
    }
}

impl<'a> From<PrivateSec1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivateSec1KeyDer<'a>) -> Self {
        Self::Sec1(key)
    }
}

impl<'a> From<PrivatePkcs8KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivatePkcs8KeyDer<'a>) -> Self {
        Self::Pkcs8(key)
    }
}

/// A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC 3447
///
/// RSA private keys are identified in PEM context as `RSA PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivatePkcs1KeyDer<'a>(Der<'a>);

impl PrivatePkcs1KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_pkcs1_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivatePkcs1KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivatePkcs1KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivatePkcs1KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A Sec1-encoded plaintext private key; as specified in RFC 5915
///
/// Sec1 private keys are identified in PEM context as `EC PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivateSec1KeyDer<'a>(Der<'a>);

impl PrivateSec1KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_sec1_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivateSec1KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivateSec1KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivateSec1KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A DER-encoded plaintext private key; as specified in PKCS#8/RFC 5958
///
/// PKCS#8 private keys are identified in PEM context as `PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivatePkcs8KeyDer<'a>(Der<'a>);

impl PrivatePkcs8KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_pkcs8_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivatePkcs8KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivatePkcs8KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivatePkcs8KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A trust anchor (a.k.a. root CA)
///
/// Traditionally, certificate verification libraries have represented trust anchors as full X.509
/// root certificates. However, those certificates contain a lot more data than is needed for
/// verifying certificates. The [`TrustAnchor`] representation allows an application to store
/// just the essential elements of trust anchors.
#[derive(Clone, Debug, PartialEq)]
pub struct TrustAnchor<'a> {
    /// Value of the `subject` field of the trust anchor
    pub subject: Der<'a>,
    /// Value of the `subjectPublicKeyInfo` field of the trust anchor
    pub subject_public_key_info: Der<'a>,
    /// Value of DER-encoded `NameConstraints`, containing name constraints to the trust anchor, if any
    pub name_constraints: Option<Der<'a>>,
}

impl TrustAnchor<'_> {
    /// Yield a `'static` lifetime of the `TrustAnchor` by allocating owned `Der` variants
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> TrustAnchor<'static> {
        use alloc::borrow::ToOwned;
        TrustAnchor {
            subject: self.subject.as_ref().to_owned().into(),
            subject_public_key_info: self.subject_public_key_info.as_ref().to_owned().into(),
            name_constraints: self
                .name_constraints
                .as_ref()
                .map(|nc| nc.as_ref().to_owned().into()),
        }
    }
}

/// A Certificate Revocation List; as specified in RFC 5280
///
/// Certificate revocation lists are identified in PEM context as `X509 CRL` and when stored in a
/// file usually use a `.crl` extension. For more on PEM files, refer to the crate documentation.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateRevocationListDer<'a>(Der<'a>);

impl AsRef<[u8]> for CertificateRevocationListDer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for CertificateRevocationListDer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for CertificateRevocationListDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der::from(slice))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for CertificateRevocationListDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der::from(vec))
    }
}

/// A DER-encoded X.509 certificate; as specified in RFC 5280
///
/// Certificates are identified in PEM context as `CERTIFICATE` and when stored in a
/// file usually use a `.pem`, `.cer` or `.crt` extension. For more on PEM files, refer to the
/// crate documentation.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateDer<'a>(Der<'a>);

impl AsRef<[u8]> for CertificateDer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for CertificateDer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for CertificateDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der::from(slice))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for CertificateDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der::from(vec))
    }
}

/// DER-encoded data, either owned or borrowed
///
/// This wrapper type is used to represent DER-encoded data in a way that is agnostic to whether
/// the data is owned (by a `Vec<u8>`) or borrowed (by a `&[u8]`). Support for the owned
/// variant is only available when the `alloc` feature is enabled.
#[derive(Clone, PartialEq)]
pub struct Der<'a>(DerInner<'a>);

impl<'a> Der<'a> {
    /// A const constructor to create a `Der` from a borrowed slice
    pub const fn from_slice(der: &'a [u8]) -> Self {
        Self(DerInner::Borrowed(der))
    }
}

impl AsRef<[u8]> for Der<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            #[cfg(feature = "alloc")]
            DerInner::Owned(vec) => vec.as_ref(),
            DerInner::Borrowed(slice) => slice,
        }
    }
}

impl Deref for Der<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for Der<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(DerInner::Borrowed(slice))
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for Der<'static> {
    fn from(vec: Vec<u8>) -> Self {
        Self(DerInner::Owned(vec))
    }
}

impl fmt::Debug for Der<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Der").field(&self.as_ref()).finish()
    }
}

#[derive(Clone, PartialEq)]
enum DerInner<'a> {
    #[cfg(feature = "alloc")]
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}
