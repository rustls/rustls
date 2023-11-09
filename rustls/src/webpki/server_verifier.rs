#[cfg(feature = "logging")]
use crate::log::trace;
use alloc::sync::Arc;
use alloc::vec::Vec;

use pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use webpki::{CertRevocationList, RevocationCheckDepth, UnknownStatusPolicy};

#[cfg(feature = "ring")]
use crate::crypto::ring::SUPPORTED_SIG_ALGS;
use crate::verify::{
    DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use crate::webpki::verify::{
    verify_server_cert_signed_by_trust_anchor_impl, verify_signed_struct, verify_tls13,
    ParsedCertificate,
};
use crate::webpki::{parse_crls, verify_server_name, VerifierBuilderError};
use crate::{Error, RootCertStore, ServerName, SignatureScheme, WebPkiSupportedAlgorithms};

/// A builder for configuring a `webpki` server certificate verifier.
///
/// For more information, see the [`WebPkiServerVerifier`] documentation.
#[derive(Debug, Clone)]
pub struct ServerCertVerifierBuilder {
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    supported_algs: Option<WebPkiSupportedAlgorithms>,
}

impl ServerCertVerifierBuilder {
    pub(crate) fn new(roots: Arc<RootCertStore>) -> Self {
        Self {
            roots,
            crls: Vec::new(),
            revocation_check_depth: RevocationCheckDepth::Chain,
            unknown_revocation_policy: UnknownStatusPolicy::Deny,
            supported_algs: None,
        }
    }

    /// Verify the revocation state of presented client certificates against the provided
    /// certificate revocation lists (CRLs). Calling `with_crls` multiple times appends the
    /// given CRLs to the existing collection.
    pub fn with_crls(
        mut self,
        crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>,
    ) -> Self {
        self.crls.extend(crls);
        self
    }

    /// Only check the end entity certificate revocation status when using CRLs.
    ///
    /// If CRLs are provided using [`with_crls`][Self::with_crls] only check the end entity
    /// certificate's revocation status. Overrides the default behavior of checking revocation
    /// status for each certificate in the verified chain built to a trust anchor
    /// (excluding the trust anchor itself).
    ///
    /// If no CRLs are provided then this setting has no effect. Neither the end entity certificate
    /// or any intermediates will have revocation status checked.
    pub fn only_check_end_entity_revocation(mut self) -> Self {
        self.revocation_check_depth = RevocationCheckDepth::EndEntity;
        self
    }

    /// Allow unknown certificate revocation status when using CRLs.
    ///
    /// If CRLs are provided with [`with_crls`][Self::with_crls] and it isn't possible to
    /// determine the revocation status of a certificate, do not treat it as an error condition.
    /// Overrides the default behavior where unknown revocation status is considered an error.
    ///
    /// If no CRLs are provided then this setting has no effect as revocation status checks
    /// are not performed.
    pub fn allow_unknown_revocation_status(mut self) -> Self {
        self.unknown_revocation_policy = UnknownStatusPolicy::Allow;
        self
    }

    /// Sets which signature verification algorithms are enabled.
    ///
    /// If this is called multiple times, the last call wins.
    pub fn with_signature_verification_algorithms(
        mut self,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        self.supported_algs = Some(supported_algs);
        self
    }

    /// Build a server certificate verifier, allowing control over the root certificates to use as
    /// trust anchors, and to control how server certificate revocation checking is performed.
    ///
    /// If the `ring` crate feature is supplied, and `with_signature_verification_algorithms` was not
    /// called on the builder, a default set of signature verification algorithms is used.
    ///
    /// Once built, the provided `Arc<dyn ServerCertVerifier>` can be used with a Rustls
    /// [crate::server::ServerConfig] to configure client certificate validation using
    /// [`with_client_cert_verifier`][crate::ConfigBuilder<ClientConfig, WantsVerifier>::with_client_cert_verifier].
    ///
    /// # Errors
    /// This function will return a `CertVerifierBuilderError` if:
    /// 1. No trust anchors have been provided.
    /// 2. DER encoded CRLs have been provided that can not be parsed successfully.
    /// 3. No signature verification algorithms were set and the `ring` feature is not enabled.
    #[cfg_attr(not(feature = "ring"), allow(unused_mut))]
    pub fn build(mut self) -> Result<Arc<dyn ServerCertVerifier>, VerifierBuilderError> {
        if self.roots.is_empty() {
            return Err(VerifierBuilderError::NoRootAnchors);
        }

        #[cfg(feature = "ring")]
        if self.supported_algs.is_none() {
            self.supported_algs = Some(SUPPORTED_SIG_ALGS);
        }

        let supported_algs = self
            .supported_algs
            .ok_or(VerifierBuilderError::NoSupportedAlgorithms)?;

        Ok(Arc::new(WebPkiServerVerifier::new(
            self.roots,
            parse_crls(self.crls)?,
            self.revocation_check_depth,
            self.unknown_revocation_policy,
            supported_algs,
        )))
    }
}

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
pub struct WebPkiServerVerifier {
    roots: Arc<RootCertStore>,
    crls: Vec<CertRevocationList<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    supported: WebPkiSupportedAlgorithms,
}

#[allow(unreachable_pub)]
impl WebPkiServerVerifier {
    /// Create builder to build up the `webpki` server certificate verifier configuration.
    /// Server certificates will be verified using the trust anchors found in the provided `roots`.
    ///
    /// For more information, see the [`ServerCertVerifierBuilder`] documentation.
    pub fn builder(roots: Arc<RootCertStore>) -> ServerCertVerifierBuilder {
        ServerCertVerifierBuilder::new(roots)
    }

    /// Short-cut for creating a `WebPkiServerVerifier` that does not perform certificate revocation
    /// checking, avoiding the need to use a builder.
    #[cfg(feature = "ring")]
    pub(crate) fn new_without_revocation(roots: impl Into<Arc<RootCertStore>>) -> Self {
        Self::new(
            roots,
            Vec::default(),
            RevocationCheckDepth::Chain,
            UnknownStatusPolicy::Allow,
            SUPPORTED_SIG_ALGS,
        )
    }

    /// Constructs a new `WebPkiServerVerifier`.
    ///
    /// * `roots` is the set of trust anchors to trust for issuing server certs.
    /// * `crls` are a vec of owned certificate revocation lists (CRLs) to use for
    ///   client certificate validation.
    /// * `revocation_check_depth` controls which certificates have their revocation status checked
    ///   when `crls` are provided.
    /// * `unknown_revocation_policy` controls how certificates with an unknown revocation status
    ///   are handled when `crls` are provided.
    /// * `supported` is the set of supported algorithms that will be used for
    ///   certificate verification and TLS handshake signature verification.
    pub(crate) fn new(
        roots: impl Into<Arc<RootCertStore>>,
        crls: Vec<CertRevocationList<'static>>,
        revocation_check_depth: RevocationCheckDepth,
        unknown_revocation_policy: UnknownStatusPolicy,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots: roots.into(),
            crls,
            revocation_check_depth,
            unknown_revocation_policy,
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
    /// - Signed by a trusted `RootCertStore` CA
    /// - Not Expired
    /// - Valid for DNS entry
    /// - Valid revocation status (if applicable).
    ///
    /// Depending on the verifier's configuration revocation status checking may be performed for
    /// each certificate in the chain to a root CA (excluding the root itself), or only the
    /// end entity certificate. Similarly, unknown revocation status may be treated as an error
    /// or allowed based on configuration.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        let crl_refs = self.crls.iter().collect::<Vec<_>>();

        let revocation = if self.crls.is_empty() {
            None
        } else {
            // Note: unwrap here is safe because RevocationOptionsBuilder only errors when given
            //       empty CRLs.
            Some(
                webpki::RevocationOptionsBuilder::new(crl_refs.as_slice())
                    // Note: safe to unwrap here - new is only fallible if no CRLs are provided
                    //       and we verify this above.
                    .unwrap()
                    .with_depth(self.revocation_check_depth)
                    .with_status_policy(self.unknown_revocation_policy)
                    .build(),
            )
        };

        // Note: we use the crate-internal `_impl` fn here in order to provide revocation
        // checking information, if applicable.
        verify_server_cert_signed_by_trust_anchor_impl(
            &cert,
            &self.roots,
            intermediates,
            revocation,
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

#[cfg(all(test, feature = "ring"))]
mod tests {
    use std::sync::Arc;

    use pki_types::{CertificateDer, CertificateRevocationListDer};

    use super::{VerifierBuilderError, WebPkiServerVerifier};
    use crate::RootCertStore;

    fn load_crls(crls_der: &[&[u8]]) -> Vec<CertificateRevocationListDer<'static>> {
        crls_der
            .iter()
            .map(|pem_bytes| {
                rustls_pemfile::crls(&mut &pem_bytes[..])
                    .next()
                    .unwrap()
                    .unwrap()
            })
            .collect()
    }

    fn test_crls() -> Vec<CertificateRevocationListDer<'static>> {
        load_crls(&[
            include_bytes!("../../../test-ca/ecdsa/client.revoked.crl.pem").as_slice(),
            include_bytes!("../../../test-ca/rsa/client.revoked.crl.pem").as_slice(),
        ])
    }

    fn load_roots(roots_der: &[&[u8]]) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots_der.iter().for_each(|der| {
            roots
                .add(CertificateDer::from(der.to_vec()))
                .unwrap()
        });
        roots.into()
    }

    fn test_roots() -> Arc<RootCertStore> {
        load_roots(&[
            include_bytes!("../../../test-ca/ecdsa/ca.der").as_slice(),
            include_bytes!("../../../test-ca/rsa/ca.der").as_slice(),
        ])
    }

    #[test]
    fn test_with_invalid_crls() {
        // Trying to build a server verifier with invalid CRLs should error at build time.
        let result = WebPkiServerVerifier::builder(test_roots())
            .with_crls(vec![CertificateRevocationListDer::from(vec![0xFF])])
            .build();
        assert!(matches!(result, Err(VerifierBuilderError::InvalidCrl(_))));
    }

    #[test]
    fn test_with_crls_multiple_calls() {
        // We should be able to call `with_crls` on a server verifier multiple times.
        let initial_crls = test_crls();
        let extra_crls =
            load_crls(&[
                include_bytes!("../../../test-ca/eddsa/client.revoked.crl.pem").as_slice(),
            ]);

        let builder = WebPkiServerVerifier::builder(test_roots())
            .with_crls(initial_crls.clone())
            .with_crls(extra_crls.clone());

        // There should be the expected number of crls.
        assert_eq!(builder.crls.len(), initial_crls.len() + extra_crls.len());
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_builder_no_roots() {
        // Trying to create a server verifier builder with no trust anchors should fail at build time
        let result = WebPkiServerVerifier::builder(RootCertStore::empty().into()).build();
        assert!(matches!(result, Err(VerifierBuilderError::NoRootAnchors)));
    }

    #[test]
    fn test_server_verifier_ee_only() {
        // We should be able to build a server cert. verifier that only checks the EE cert.
        let builder =
            WebPkiServerVerifier::builder(test_roots()).only_check_end_entity_revocation();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_server_verifier_allow_unknown() {
        // We should be able to build a server cert. verifier that allows unknown revocation
        // status.
        let builder = WebPkiServerVerifier::builder(test_roots()).allow_unknown_revocation_status();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_server_verifier_allow_unknown_ee_only() {
        // We should be able to build a server cert. verifier that allows unknown revocation
        // status and only checks the EE cert.
        let builder = WebPkiServerVerifier::builder(test_roots())
            .allow_unknown_revocation_status()
            .only_check_end_entity_revocation();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }
}
