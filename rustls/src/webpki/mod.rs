use alloc::sync::Arc;

use crate::error::{CertRevocationListError, CertificateError, Error};

mod anchors;
mod client_verifier_builder;
mod verify;

pub use anchors::{RootCertStore, TrustAnchorWithDn};

pub use client_verifier_builder::{ClientCertVerifierBuilder, ClientCertVerifierBuilderError};

pub use verify::{WebPkiClientVerifier, WebPkiSupportedAlgorithms};

// Conditionally exported from crate.
#[allow(unreachable_pub)]
pub use verify::{
    verify_server_cert_signed_by_trust_anchor, verify_server_name, ParsedCertificate,
    WebPkiServerVerifier,
};

fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet => CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),
        CertRevoked => CertificateError::Revoked.into(),
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
