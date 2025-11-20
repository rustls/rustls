use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};

use crate::crypto::{Identity, SignatureScheme};
use crate::enums::CertificateType;
use crate::error::{Error, InvalidMessage};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::DistinguishedName;
use crate::sync::Arc;

// Marker types.  These are used to bind the fact some verification
// (certificate chain or handshake signature) has taken place into
// protocol states.  We use this to have the compiler check that there
// are no 'goto fail'-style elisions of important checks before we
// reach the traffic stage.
//
// These types are public, but cannot be directly constructed.  This
// means their origins can be precisely determined by looking
// for their `assertion` constructors.

/// Something that can verify a server certificate chain, and verify
/// signatures made by certificates.
pub trait ServerVerifier: Debug + Send + Sync {
    /// Verify the server's identity.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementer to handle invalid data. It is recommended that the implementer returns
    /// [`Error::InvalidCertificate`] containing [`CertificateError::BadEncoding`] when these cases are encountered.
    ///
    /// [Certificate]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
    /// [`CertificateError::BadEncoding`]: crate::error::CertificateError::BadEncoding
    fn verify_identity(&self, identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error>;

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verify a signature allegedly by the given server certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`: but note the
    /// tighter ECDSA SignatureScheme semantics -- e.g. `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    /// Return true if this verifier will process stapled OCSP responses.
    ///
    /// This controls whether a client will ask the server for a stapled OCSP response.
    /// There is no guarantee the server will provide one.
    fn request_ocsp_response(&self) -> bool;

    /// Returns which [`CertificateType`]s this verifier supports.
    ///
    /// Returning an empty slice will result in an error. The default implementation signals
    /// support for X.509 certificates. Implementations should return the same value every time.
    ///
    /// See [RFC 7250](https://tools.ietf.org/html/rfc7250) for more information.
    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }

    /// Return the [`DistinguishedName`]s of certificate authorities that this verifier trusts.
    ///
    /// If specified, will be sent as the [`certificate_authorities`] extension in ClientHello.
    /// Note that this is only applicable to TLS 1.3.
    ///
    /// [`certificate_authorities`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        None
    }
}

/// Data required to verify a server's identity.
#[non_exhaustive]
#[derive(Debug)]
pub struct ServerIdentity<'a> {
    /// Identity information presented by the server.
    pub identity: &'a Identity<'a>,
    /// The server name the client specified when connecting to the server.
    pub server_name: &'a ServerName<'a>,
    /// OCSP response stapled to the server's `Certificate` message, if any.
    ///
    /// Empty if no OCSP response was received, and that also
    /// covers the case where `request_ocsp_response()` returns false.
    pub ocsp_response: &'a [u8],
    /// Current time against which time-sensitive inputs should be validated.
    pub now: UnixTime,
}

/// Something that can verify a client certificate chain
pub trait ClientVerifier: Debug + Send + Sync {
    /// Verify the client's identity.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementer to handle invalid data. It is recommended that the implementer returns
    /// a [`CertificateError::BadEncoding`] error when these cases are encountered.
    ///
    /// [`CertificateError::BadEncoding`]: crate::error::CertificateError::BadEncoding
    fn verify_identity(&self, identity: &ClientIdentity<'_>) -> Result<PeerVerified, Error>;

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// If and only if the signature is valid, return `Ok(HandshakeSignatureValid)`.
    /// Otherwise, return an error -- rustls will send an alert and abort the
    /// connection.
    ///
    /// This method is only called for TLS1.2 handshakes.  Note that, in TLS1.2,
    /// SignatureSchemes such as `SignatureScheme::ECDSA_NISTP256_SHA256` are not
    /// in fact bound to the specific curve implied in their name.
    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Verify a signature allegedly by the given client certificate.
    ///
    /// This method is only called for TLS1.3 handshakes.
    ///
    /// This method is very similar to `verify_tls12_signature`, but note the
    /// tighter ECDSA SignatureScheme semantics in TLS 1.3. For example,
    /// `SignatureScheme::ECDSA_NISTP256_SHA256`
    /// must only validate signatures using public keys on the right curve --
    /// rustls does not enforce this requirement for you.
    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error>;

    /// Returns the [`DistinguishedName`] [subjects] that the server will hint to clients to
    /// identify acceptable authentication trust anchors.
    ///
    /// These hint values help the client pick a client certificate it believes the server will
    /// accept. The hints must be DER-encoded X.500 distinguished names, per [RFC 5280 A.1]. They
    /// are sent in the [`certificate_authorities`] extension of a [`CertificateRequest`] message
    /// when [ClientVerifier::offer_client_auth] is true. When an empty list is sent the client
    /// should always provide a client certificate if it has one.
    ///
    /// Generally this list should contain the [`DistinguishedName`] of each root trust
    /// anchor in the root cert store that the server is configured to use for authenticating
    /// presented client certificates.
    ///
    /// In some circumstances this list may be customized to include [`DistinguishedName`] entries
    /// that do not correspond to a trust anchor in the server's root cert store. For example,
    /// the server may be configured to trust a root CA that cross-signed an issuer certificate
    /// that the client considers a trust anchor. From the server's perspective the cross-signed
    /// certificate is an intermediate, and not present in the server's root cert store. The client
    /// may have the cross-signed certificate configured as a trust anchor, and be unaware of the
    /// root CA that cross-signed it. If the server's hints list only contained the subjects of the
    /// server's root store the client would consider a client certificate issued by the cross-signed
    /// issuer unacceptable, since its subject was not hinted. To avoid this circumstance the server
    /// should customize the hints list to include the subject of the cross-signed issuer in addition
    /// to the subjects from the root cert store.
    ///
    /// [subjects]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6
    /// [RFC 5280 A.1]: https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
    /// [`CertificateRequest`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
    /// [`certificate_authorities`]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]>;

    /// Return `true` to require a client certificate and `false` to make
    /// client authentication optional.
    /// Defaults to `self.offer_client_auth()`.
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    /// Returns `true` to enable the server to request a client certificate and
    /// `false` to skip requesting a client certificate. Defaults to `true`.
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;

    /// Returns which [`CertificateType`]s this verifier supports.
    ///
    /// Returning an empty slice will result in an error. The default implementation signals
    /// support for X.509 certificates. Implementations should return the same value every time.
    ///
    /// See [RFC 7250](https://tools.ietf.org/html/rfc7250) for more information.
    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }
}

/// Data required to verify a client's identity.
#[non_exhaustive]
#[derive(Debug)]
pub struct ClientIdentity<'a> {
    /// Identity information presented by the client.
    pub identity: &'a Identity<'a>,
    /// Current time against which time-sensitive inputs should be validated.
    pub now: UnixTime,
}

/// Input for message signature verification.
#[non_exhaustive]
#[derive(Debug)]
pub struct SignatureVerificationInput<'a> {
    /// The message is not hashed, and needs hashing during verification.
    pub message: &'a [u8],
    /// The public key to use.
    ///
    /// `signer` has already been validated by the point this is called.
    pub signer: &'a SignerPublicKey<'a>,
    /// The signature scheme and payload.
    pub signature: &'a DigitallySignedStruct,
}

/// Public key used to verify a signature.
///
/// Used as part of [`SignatureVerificationInput`].
#[non_exhaustive]
#[derive(Debug)]
pub enum SignerPublicKey<'a> {
    /// An X.509 certificate for the signing peer.
    X509(&'a CertificateDer<'a>),
    /// A raw public key, as defined in [RFC 7250](https://tools.ietf.org/html/rfc7250).
    RawPublicKey(&'a SubjectPublicKeyInfoDer<'a>),
}

/// Turns off client authentication.
///
/// In contrast to using
/// `WebPkiClientVerifier::builder(roots).allow_unauthenticated().build()`, the `NoClientAuth`
/// `ClientVerifier` will not offer client authentication at all, vs offering but not
/// requiring it.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct NoClientAuth;

impl ClientVerifier for NoClientAuth {
    fn verify_identity(&self, _identity: &ClientIdentity<'_>) -> Result<PeerVerified, Error> {
        unimplemented!();
    }

    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        unimplemented!();
    }

    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        unimplemented!();
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        unimplemented!();
    }

    fn offer_client_auth(&self) -> bool {
        false
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        unimplemented!();
    }
}

/// This type combines a [`SignatureScheme`] and a signature payload produced with that scheme.
#[derive(Debug, Clone)]
pub struct DigitallySignedStruct {
    /// The [`SignatureScheme`] used to produce the signature.
    pub scheme: SignatureScheme,
    sig: PayloadU16,
}

impl DigitallySignedStruct {
    pub(crate) fn new(scheme: SignatureScheme, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }

    /// Get the signature.
    pub fn signature(&self) -> &[u8] {
        &self.sig.0
    }
}

impl Codec<'_> for DigitallySignedStruct {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;

        Ok(Self { scheme, sig })
    }
}

/// Zero-sized marker type representing verification of a signature.
#[derive(Debug)]
pub struct HandshakeSignatureValid(());

impl HandshakeSignatureValid {
    /// Make a `HandshakeSignatureValid`
    pub fn assertion() -> Self {
        Self(())
    }
}

#[derive(Debug)]
pub(crate) struct FinishedMessageVerified(());

impl FinishedMessageVerified {
    pub(crate) fn assertion() -> Self {
        Self(())
    }
}

/// Zero-sized marker type representing verification of the peer's identity.
#[derive(Debug)]
pub struct PeerVerified(());

impl PeerVerified {
    /// Make a `PeerVerified`
    pub fn assertion() -> Self {
        Self(())
    }
}

#[test]
fn assertions_are_debug() {
    use std::format;

    assert_eq!(
        format!("{:?}", PeerVerified::assertion()),
        "PeerVerified(())"
    );
    assert_eq!(
        format!("{:?}", HandshakeSignatureValid::assertion()),
        "HandshakeSignatureValid(())"
    );
    assert_eq!(
        format!("{:?}", FinishedMessageVerified::assertion()),
        "FinishedMessageVerified(())"
    );
}
