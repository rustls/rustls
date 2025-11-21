use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::iter;

use pki_types::{AlgorithmIdentifier, CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};

use super::CryptoProvider;
use crate::client::config::{ClientCredentialResolver, CredentialRequest};
use crate::common_state::CommonState;
use crate::crypto::SignatureScheme;
use crate::enums::CertificateType;
use crate::error::{AlertDescription, ApiMisuse, Error, InvalidMessage, PeerIncompatible};
use crate::msgs::codec::{Codec, Reader};
use crate::server::{ClientHello, ParsedCertificate, ServerCredentialResolver};
use crate::sync::Arc;
use crate::{SignerPublicKey, x509};

/// Server certificate resolver which always resolves to the same identity and key.
///
/// For use with [`ConfigBuilder::with_server_credential_resolver()`] or
/// [`ConfigBuilder::with_client_credential_resolver()`].
///
/// [`ConfigBuilder::with_server_credential_resolver()`]: crate::ConfigBuilder::with_server_credential_resolver
/// [`ConfigBuilder::with_client_credential_resolver()`]: crate::ConfigBuilder::with_client_credential_resolver
#[derive(Debug)]
pub struct SingleCredential {
    credentials: Credentials,
    types: &'static [CertificateType],
}

impl From<Credentials> for SingleCredential {
    fn from(credentials: Credentials) -> Self {
        match &*credentials.identity {
            Identity::X509(_) => Self {
                credentials,
                types: &[CertificateType::X509],
            },
            Identity::RawPublicKey(_) => Self {
                credentials,
                types: &[CertificateType::RawPublicKey],
            },
        }
    }
}

impl ClientCredentialResolver for SingleCredential {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        match (&*self.credentials.identity, request.negotiated_type()) {
            (Identity::X509(_), CertificateType::X509)
            | (Identity::RawPublicKey(_), CertificateType::RawPublicKey) => self
                .credentials
                .signer(request.signature_schemes()),
            _ => None,
        }
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        self.types
    }
}

impl ServerCredentialResolver for SingleCredential {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        self.credentials
            .signer(client_hello.signature_schemes())
            .ok_or(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ))
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        self.types
    }
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response.
///
/// Note: this struct is also used to represent an [RFC 7250] raw public key,
/// when the client/server is configured to use raw public keys instead of
/// certificates.
///
/// [RFC 7250]: https://tools.ietf.org/html/rfc7250
#[non_exhaustive]
#[derive(Debug)]
pub struct Credentials {
    /// The certificate chain or raw public key.
    pub identity: Arc<Identity<'static>>,
    /// The signing key matching the `identity`.
    pub key: Box<dyn SigningKey>,
    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Arc<[u8]>>,
}

impl Credentials {
    /// Create a new [`Credentials`] from a certificate chain and DER-encoded private key.
    ///
    /// Attempt to parse the private key with the given [`CryptoProvider`]'s [`KeyProvider`] and
    /// verify that it matches the public key in the first certificate of the `identity`
    /// if possible (if it is an `X509` identity).
    ///
    /// [`KeyProvider`]: crate::crypto::KeyProvider
    pub fn from_der(
        identity: Arc<Identity<'static>>,
        key: PrivateKeyDer<'static>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        Self::new(
            identity,
            provider
                .key_provider
                .load_private_key(key)?,
        )
    }

    /// Make a new [`Credentials`], with the given identity and key.
    ///
    /// Yields [`Error::InconsistentKeys`] if the `identity` is `X509` and the end-entity certificate's subject
    /// public key info does not match that of the `key`'s public key, or if the `key` does not
    /// have a public key.
    ///
    /// This constructor should be used with all [`SigningKey`] implementations
    /// that can provide a public key, including those provided by rustls itself.
    pub fn new(identity: Arc<Identity<'static>>, key: Box<dyn SigningKey>) -> Result<Self, Error> {
        if let Identity::X509(CertificateIdentity { end_entity, .. }) = &*identity {
            let parsed = ParsedCertificate::try_from(end_entity)?;
            match (key.public_key(), parsed.subject_public_key_info()) {
                (None, _) => return Err(Error::InconsistentKeys(InconsistentKeys::Unknown)),
                (Some(key_spki), cert_spki) if key_spki != cert_spki => {
                    return Err(Error::InconsistentKeys(InconsistentKeys::KeyMismatch));
                }
                _ => {}
            }
        };

        Ok(Self {
            identity,
            key,
            ocsp: None,
        })
    }

    /// Make a new `Credentials` from a raw private key.
    ///
    /// Unlike [`Credentials::new()`], this does not check that the end-entity certificate's
    /// subject key matches `key`'s public key.
    ///
    /// This avoids parsing the end-entity certificate, which is useful when using client
    /// certificates that are not fully standards compliant, but known to usable by the peer.
    pub fn new_unchecked(identity: Arc<Identity<'static>>, key: Box<dyn SigningKey>) -> Self {
        Self {
            identity,
            key,
            ocsp: None,
        }
    }

    /// Attempt to produce a `SelectedCredential` using one of the given signature schemes.
    ///
    /// Calls [`SigningKey::choose_scheme()`] and propagates `cert_chain` and `ocsp`.
    pub fn signer(&self, sig_schemes: &[SignatureScheme]) -> Option<SelectedCredential> {
        Some(SelectedCredential {
            identity: self.identity.clone(),
            signer: self.key.choose_scheme(sig_schemes)?,
            ocsp: self.ocsp.clone(),
        })
    }
}

/// A packaged-together certificate chain and one-time-use signer.
///
/// This is used in the [`ClientCredentialResolver`] and [`ServerCredentialResolver`] traits
/// as the return value of their `resolve()` methods.
#[non_exhaustive]
#[derive(Debug)]
pub struct SelectedCredential {
    /// The certificate chain or raw public key.
    pub identity: Arc<Identity<'static>>,
    /// The signing key matching the `identity`.
    pub signer: Box<dyn Signer>,
    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Arc<[u8]>>,
}

/// A peer's identity, depending on the negotiated certificate type.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identity<'a> {
    /// A standard X.509 certificate chain.
    ///
    /// This is the most common case.
    X509(CertificateIdentity<'a>),
    /// A raw public key, as defined in [RFC 7250](https://tools.ietf.org/html/rfc7250).
    RawPublicKey(SubjectPublicKeyInfoDer<'a>),
}

impl<'a> Identity<'a> {
    /// Create a `PeerIdentity::X509` from a certificate chain.
    ///
    /// Returns `None` if `cert_chain` is empty.
    pub fn from_cert_chain(mut cert_chain: Vec<CertificateDer<'a>>) -> Result<Self, ApiMisuse> {
        let mut iter = cert_chain.drain(..);
        let Some(first) = iter.next() else {
            return Err(ApiMisuse::EmptyCertificateChain);
        };

        Ok(Self::X509(CertificateIdentity {
            end_entity: first,
            intermediates: iter.collect(),
        }))
    }

    pub(crate) fn from_peer(
        mut cert_chain: Vec<CertificateDer<'a>>,
        expected: CertificateType,
        common: &mut CommonState,
    ) -> Result<Option<Self>, Error> {
        let mut iter = cert_chain.drain(..);
        let Some(first) = iter.next() else {
            return Ok(None);
        };

        match expected {
            CertificateType::X509 => Ok(Some(Self::X509(CertificateIdentity {
                end_entity: first,
                intermediates: iter.collect(),
            }))),
            CertificateType::RawPublicKey => match iter.count() {
                0 => Ok(Some(Self::RawPublicKey(
                    SubjectPublicKeyInfoDer::from(first.as_ref()).into_owned(),
                ))),
                _ => Err(common.send_fatal_alert(
                    AlertDescription::BadCertificate,
                    PeerIncompatible::MultipleRawKeys,
                )),
            },
            CertificateType::Unknown(ty) => Err(common.send_fatal_alert(
                AlertDescription::UnsupportedCertificate,
                PeerIncompatible::UnknownCertificateType(ty),
            )),
        }
    }

    /// Convert this `PeerIdentity` into an owned version.
    pub fn into_owned(self) -> Identity<'static> {
        match self {
            Self::X509(id) => Identity::X509(id.into_owned()),
            Self::RawPublicKey(spki) => Identity::RawPublicKey(spki.into_owned()),
        }
    }

    pub(crate) fn as_certificates(&'a self) -> impl Iterator<Item = CertificateDer<'a>> + 'a {
        match self {
            Self::X509(cert) => IdentityCertificateIterator::X509(
                iter::once(CertificateDer::from(cert.end_entity.as_ref())).chain(
                    cert.intermediates
                        .iter()
                        .map(|c| CertificateDer::from(c.as_ref())),
                ),
            ),
            Self::RawPublicKey(spki) => IdentityCertificateIterator::RawPublicKey(iter::once(
                CertificateDer::from(spki.as_ref()),
            )),
        }
    }

    /// Get the public key of this identity as a `SignerPublicKey`.
    pub fn as_signer(&self) -> SignerPublicKey<'_> {
        match self {
            Self::X509(cert) => SignerPublicKey::X509(&cert.end_entity),
            Self::RawPublicKey(spki) => SignerPublicKey::RawPublicKey(spki),
        }
    }
}

impl<'a> Codec<'a> for Identity<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::X509(certificates) => {
                0u8.encode(bytes);
                certificates.end_entity.encode(bytes);
                certificates.intermediates.encode(bytes);
            }
            Self::RawPublicKey(spki) => {
                1u8.encode(bytes);
                spki.encode(bytes);
            }
        }
    }

    fn read(reader: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        match u8::read(reader)? {
            0 => Ok(Self::X509(CertificateIdentity {
                end_entity: CertificateDer::read(reader)?.into_owned(),
                intermediates: Vec::<CertificateDer<'_>>::read(reader)?
                    .into_iter()
                    .collect(),
            })),
            1 => Ok(Self::RawPublicKey(
                SubjectPublicKeyInfoDer::read(reader)?.into_owned(),
            )),
            _ => Err(InvalidMessage::UnexpectedMessage(
                "invalid PeerIdentity discriminant",
            )),
        }
    }
}

enum IdentityCertificateIterator<C, R> {
    X509(C),
    RawPublicKey(R),
}

impl<'a, C, R> Iterator for IdentityCertificateIterator<C, R>
where
    C: Iterator<Item = CertificateDer<'a>>,
    R: Iterator<Item = CertificateDer<'a>>,
{
    type Item = CertificateDer<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::X509(iter) => iter.next(),
            Self::RawPublicKey(iter) => iter.next(),
        }
    }
}

/// Data required to verify the peer's identity.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateIdentity<'a> {
    /// Certificate for the entity being verified.
    pub end_entity: CertificateDer<'a>,
    /// All certificates other than `end_entity` received in the peer's `Certificate` message.
    ///
    /// It is in the same order that the peer sent them and may be empty.
    pub intermediates: Vec<CertificateDer<'a>>,
}

impl<'a> CertificateIdentity<'a> {
    /// Convert this `CertificateIdentity` into an owned version.
    pub fn into_owned(self) -> CertificateIdentity<'static> {
        CertificateIdentity {
            end_entity: self.end_entity.into_owned(),
            intermediates: self
                .intermediates
                .into_iter()
                .map(|cert| cert.into_owned())
                .collect(),
        }
    }
}

/// An abstract signing key.
///
/// This interface is used by rustls to use a private signing key
/// for authentication.  This includes server and client authentication.
///
/// Objects of this type are always used within Rustls as
/// `Arc<dyn SigningKey>`. There are no concrete public structs in Rustls
/// that implement this trait.
///
/// You can obtain a `SigningKey` by calling the [`KeyProvider::load_private_key()`]
/// method, which is usually referenced via [`CryptoProvider::key_provider`].
///
/// The `KeyProvider` method `load_private_key()` is called under the hood by
/// [`ConfigBuilder::with_single_cert()`],
/// [`ConfigBuilder::with_client_auth_cert()`], and
/// [`ConfigBuilder::with_single_cert_with_ocsp()`].
///
/// A signing key created outside of the `KeyProvider` extension trait can be used
/// to create a [`Credentials`], which in turn can be used to create a
/// [`ServerNameResolver`]. Alternately, a `Credentials` can be returned from a
/// custom implementation of the [`ServerCredentialResolver`] or [`ClientCredentialResolver`] traits.
///
/// [`KeyProvider::load_private_key()`]: crate::crypto::KeyProvider::load_private_key
/// [`ConfigBuilder::with_single_cert()`]: crate::ConfigBuilder::with_single_cert
/// [`ConfigBuilder::with_single_cert_with_ocsp()`]: crate::ConfigBuilder::with_single_cert_with_ocsp
/// [`ConfigBuilder::with_client_auth_cert()`]: crate::ConfigBuilder::with_client_auth_cert
/// [`ServerNameResolver`]: crate::server::ServerNameResolver
/// [`ServerCredentialResolver`]: crate::server::ServerCredentialResolver
/// [`ClientCredentialResolver`]: crate::client::ClientCredentialResolver
pub trait SigningKey: Debug + Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice by returning something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// Get the RFC 5280-compliant SubjectPublicKeyInfo (SPKI) of this [`SigningKey`].
    ///
    /// If an implementation does not have the ability to derive this,
    /// it can return `None`.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>>;
}

/// A thing that can sign a message.
pub trait Signer: Debug + Send + Sync {
    /// Signs `message` using the selected scheme.
    ///
    /// `message` is not hashed; the implementer must hash it using the hash function
    /// implicit in [`Self::scheme()`].
    ///
    /// The returned signature format is also defined by [`Self::scheme()`].
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reveals which scheme will be used when you call [`Self::sign()`].
    fn scheme(&self) -> SignatureScheme;
}

/// Convert a public key and algorithm identifier into [`SubjectPublicKeyInfoDer`].
///
/// In the returned encoding, `alg_id` is used as the `algorithm` field, and `public_key` is
/// wrapped inside an ASN.1 `BIT STRING` and then used as the `subjectPublicKey` field.
pub fn public_key_to_spki(
    alg_id: &AlgorithmIdentifier,
    public_key: impl AsRef<[u8]>,
) -> SubjectPublicKeyInfoDer<'static> {
    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    //
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //    algorithm               OBJECT IDENTIFIER,
    //    parameters              ANY DEFINED BY algorithm OPTIONAL  }
    //
    // note that the `pki_types::AlgorithmIdentifier` type is the
    // concatenation of `algorithm` and `parameters`, but misses the
    // outer `Sequence`.

    let mut spki_inner = x509::wrap_in_sequence(alg_id.as_ref());
    spki_inner.extend(&x509::wrap_in_bit_string(public_key.as_ref()));

    let spki = x509::wrap_in_sequence(&spki_inner);

    SubjectPublicKeyInfoDer::from(spki)
}

/// Specific failure cases from [`Credentials::new()`] or a [`crate::crypto::SigningKey`] that cannot produce a corresponding public key.
///
/// [`Credentials::new()`]: crate::crypto::Credentials::new()
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconsistentKeys {
    /// The public key returned by the [`SigningKey`] does not match the public key information in the certificate.
    ///
    /// [`SigningKey`]: crate::crypto::SigningKey
    KeyMismatch,

    /// The [`SigningKey`] cannot produce its corresponding public key.
    ///
    /// [`SigningKey`]: crate::crypto::SigningKey
    Unknown,
}
