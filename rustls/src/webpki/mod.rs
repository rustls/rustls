use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use std::error::Error as StdError;

use crate::error::{CertRevocationListError, CertificateError, Error};

mod anchors;
mod client_verifier;
mod server_verifier;
mod verify;

pub use anchors::RootCertStore;

pub use client_verifier::{ClientCertVerifierBuilder, WebPkiClientVerifier};
pub use server_verifier::{ServerCertVerifierBuilder, WebPkiServerVerifier};

pub use verify::WebPkiSupportedAlgorithms;

// Conditionally exported from crate.
#[allow(unreachable_pub)]
pub use verify::{
    verify_server_cert_signed_by_trust_anchor, verify_server_name, ParsedCertificate,
};

/// An error that can occur when building a certificate verifier.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifierBuilderError {
    /// No root trust anchors were provided.
    NoRootAnchors,
    /// A provided CRL could not be parsed.
    InvalidCrl(CertRevocationListError),
    /// No supported signature verification algorithms were provided.
    ///
    /// Call `with_signature_verification_algorithms` on the builder, or compile
    /// with the `ring` feature.
    NoSupportedAlgorithms,
}

impl From<CertRevocationListError> for VerifierBuilderError {
    fn from(value: CertRevocationListError) -> Self {
        Self::InvalidCrl(value)
    }
}

impl fmt::Display for VerifierBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRootAnchors => write!(f, "no root trust anchors were provided"),
            Self::InvalidCrl(e) => write!(f, "provided CRL could not be parsed: {:?}", e),
            Self::NoSupportedAlgorithms => {
                write!(f, "no signature verification algorithms were provided")
            }
        }
    }
}

impl StdError for VerifierBuilderError {}

fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet => CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey
        | UnsupportedSignatureAlgorithm
        | UnsupportedSignatureAlgorithmForPublicKey => CertificateError::BadSignature.into(),

        InvalidCrlSignatureForPublicKey
        | UnsupportedCrlSignatureAlgorithm
        | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::BadSignature.into()
        }

        _ => CertificateError::Other(Arc::new(error)).into(),
    }
}

fn crl_error(e: webpki::Error) -> CertRevocationListError {
    use webpki::Error::*;
    match e {
        InvalidCrlSignatureForPublicKey
        | UnsupportedCrlSignatureAlgorithm
        | UnsupportedCrlSignatureAlgorithmForPublicKey => CertRevocationListError::BadSignature,
        InvalidCrlNumber => CertRevocationListError::InvalidCrlNumber,
        InvalidSerialNumber => CertRevocationListError::InvalidRevokedCertSerialNumber,
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl,
        MalformedExtensions | BadDer | BadDerTime => CertRevocationListError::ParseError,
        UnsupportedCriticalExtension => CertRevocationListError::UnsupportedCriticalExtension,
        UnsupportedCrlVersion => CertRevocationListError::UnsupportedCrlVersion,
        UnsupportedDeltaCrl => CertRevocationListError::UnsupportedDeltaCrl,
        UnsupportedIndirectCrl => CertRevocationListError::UnsupportedIndirectCrl,
        UnsupportedRevocationReason => CertRevocationListError::UnsupportedRevocationReason,

        _ => CertRevocationListError::Other(Arc::new(e)),
    }
}

fn borrow_crls(
    crls: &Vec<webpki::OwnedCertRevocationList>,
) -> Vec<&dyn webpki::CertRevocationList> {
    #[allow(trivial_casts)] // Cast to &dyn trait is required.
    crls.iter()
        .map(|crl| crl as &dyn webpki::CertRevocationList)
        .collect::<Vec<_>>()
}

mod tests {
    #[test]
    fn pki_crl_errors() {
        use super::{pki_error, CertRevocationListError, CertificateError, Error};

        // CRL signature errors should be turned into BadSignature.
        assert_eq!(
            pki_error(webpki::Error::InvalidCrlSignatureForPublicKey),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );
        assert_eq!(
            pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithm),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );
        assert_eq!(
            pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );

        // Revoked cert errors should be turned into Revoked.
        assert_eq!(
            pki_error(webpki::Error::CertRevoked),
            Error::InvalidCertificate(CertificateError::Revoked),
        );

        // Issuer not CRL signer errors should be turned into IssuerInvalidForCrl
        assert_eq!(
            pki_error(webpki::Error::IssuerNotCrlSigner),
            Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl)
        );
    }

    #[test]
    fn crl_error_from_webpki() {
        use super::{crl_error, CertRevocationListError::*};

        let testcases = &[
            (webpki::Error::InvalidCrlSignatureForPublicKey, BadSignature),
            (
                webpki::Error::UnsupportedCrlSignatureAlgorithm,
                BadSignature,
            ),
            (
                webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey,
                BadSignature,
            ),
            (webpki::Error::InvalidCrlNumber, InvalidCrlNumber),
            (
                webpki::Error::InvalidSerialNumber,
                InvalidRevokedCertSerialNumber,
            ),
            (webpki::Error::IssuerNotCrlSigner, IssuerInvalidForCrl),
            (webpki::Error::MalformedExtensions, ParseError),
            (webpki::Error::BadDer, ParseError),
            (webpki::Error::BadDerTime, ParseError),
            (
                webpki::Error::UnsupportedCriticalExtension,
                UnsupportedCriticalExtension,
            ),
            (webpki::Error::UnsupportedCrlVersion, UnsupportedCrlVersion),
            (webpki::Error::UnsupportedDeltaCrl, UnsupportedDeltaCrl),
            (
                webpki::Error::UnsupportedIndirectCrl,
                UnsupportedIndirectCrl,
            ),
            (
                webpki::Error::UnsupportedRevocationReason,
                UnsupportedRevocationReason,
            ),
        ];
        for t in testcases {
            assert_eq!(crl_error(t.0), t.1);
        }

        assert!(matches!(
            crl_error(webpki::Error::NameConstraintViolation),
            Other(_)
        ));
    }
}
