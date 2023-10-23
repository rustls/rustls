#[cfg(feature = "logging")]
use crate::log::trace;
use alloc::sync::Arc;
use alloc::vec::Vec;

use pki_types::{CertificateDer, UnixTime};

use crate::verify::{
    DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use crate::webpki::verify::{
    verify_signed_struct, verify_tls13, ParsedCertificate, SUPPORTED_SIG_ALGS,
};
use crate::webpki::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use crate::{Error, RootCertStore, ServerName, SignatureScheme, WebPkiSupportedAlgorithms};

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
pub struct WebPkiServerVerifier {
    roots: Arc<RootCertStore>,
    supported: WebPkiSupportedAlgorithms,
}

#[allow(unreachable_pub)]
impl WebPkiServerVerifier {
    /// Constructs a new `WebPkiServerVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    #[cfg(feature = "ring")]
    pub fn new(roots: impl Into<Arc<RootCertStore>>) -> Self {
        Self::new_with_algorithms(roots, SUPPORTED_SIG_ALGS)
    }

    /// Constructs a new `WebPkiServerVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    /// `supported` is the set of supported algorithms that will be used for
    /// certificate verification and TLS handshake signature verification.
    pub fn new_with_algorithms(
        roots: impl Into<Arc<RootCertStore>>,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots: roots.into(),
            supported,
        }
    }

    /// A full implementation of `ServerCertVerifier::verify_tls12_signature` or
    /// `ClientCertVerifier::verify_tls12_signature`.
    #[cfg(feature = "ring")]
    pub fn default_verify_tls12_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::verify_tls13_signature` or
    /// `ClientCertVerifier::verify_tls13_signature`.
    #[cfg(feature = "ring")]
    pub fn default_verify_tls13_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::supported_verify_schemes()` or
    /// `ClientCertVerifier::supported_verify_schemes()`.
    #[cfg(feature = "ring")]
    pub fn default_supported_verify_schemes() -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }
}

impl ServerCertVerifier for WebPkiServerVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    /// - Valid for DNS entry
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported.all,
        )?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
