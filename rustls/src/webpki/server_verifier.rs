use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use pki_types::CertificateRevocationListDer;
use webpki::{CertRevocationList, ExpirationPolicy, RevocationCheckDepth, UnknownStatusPolicy};

use crate::crypto::{CryptoProvider, Identity, SignatureScheme, WebPkiSupportedAlgorithms};
use crate::error::ApiMisuse;
use crate::sync::Arc;
use crate::verify::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
    SignatureVerificationInput,
};
use crate::webpki::verify::{
    ParsedCertificate, verify_identity_signed_by_trust_anchor_impl, verify_tls12_signature,
    verify_tls13_signature,
};
use crate::webpki::{VerifierBuilderError, parse_crls, verify_server_name};
#[cfg(doc)]
use crate::{ConfigBuilder, ServerConfig, crypto};
use crate::{DynHasher, Error, RootCertStore};

/// A builder for configuring a `webpki` server certificate verifier.
///
/// For more information, see the [`WebPkiServerVerifier`] documentation.
#[derive(Debug, Clone)]
pub struct ServerVerifierBuilder {
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerVerifierBuilder {
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots,
            crls: Vec::new(),
            revocation_check_depth: RevocationCheckDepth::Chain,
            unknown_revocation_policy: UnknownStatusPolicy::Deny,
            revocation_expiration_policy: ExpirationPolicy::Ignore,
            supported_algs,
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

    /// Enforce the CRL nextUpdate field (i.e. expiration)
    ///
    /// If CRLs are provided with [`with_crls`][Self::with_crls] and the verification time is
    /// beyond the time in the CRL nextUpdate field, it is expired and treated as an error condition.
    /// Overrides the default behavior where expired CRLs are not treated as an error condition.
    ///
    /// If no CRLs are provided then this setting has no effect as revocation status checks
    /// are not performed.
    pub fn enforce_revocation_expiration(mut self) -> Self {
        self.revocation_expiration_policy = ExpirationPolicy::Enforce;
        self
    }

    /// Build a server certificate verifier, allowing control over the root certificates to use as
    /// trust anchors, and to control how server certificate revocation checking is performed.
    ///
    /// If `with_signature_verification_algorithms` was not called on the builder, a default set of
    /// signature verification algorithms is used, controlled by the selected [`crypto::CryptoProvider`].
    ///
    /// Once built, the provided `Arc<dyn ServerVerifier>` can be used with a Rustls
    /// [`ServerConfig`] to configure client certificate validation using
    /// [`with_client_cert_verifier`][ConfigBuilder<ClientConfig, WantsVerifier>::with_client_cert_verifier].
    ///
    /// # Errors
    /// This function will return a [`VerifierBuilderError`] if:
    /// 1. No trust anchors have been provided.
    /// 2. DER encoded CRLs have been provided that can not be parsed successfully.
    pub fn build(self) -> Result<WebPkiServerVerifier, VerifierBuilderError> {
        if self.roots.is_empty() {
            return Err(VerifierBuilderError::NoRootAnchors);
        }

        Ok(WebPkiServerVerifier::new(
            self.roots,
            parse_crls(self.crls)?,
            self.revocation_check_depth,
            self.unknown_revocation_policy,
            self.revocation_expiration_policy,
            self.supported_algs,
        ))
    }
}

/// Default `ServerVerifier`, see the trait impl for more information.
#[derive(Debug, Hash)]
pub struct WebPkiServerVerifier {
    roots: Arc<RootCertStore>,
    crls: Vec<CertRevocationList<'static>>,
    revocation_check_depth: RevocationCheckDepth,
    unknown_revocation_policy: UnknownStatusPolicy,
    revocation_expiration_policy: ExpirationPolicy,
    supported: WebPkiSupportedAlgorithms,
}

impl WebPkiServerVerifier {
    /// Create a builder for the `webpki` server certificate verifier configuration using
    /// a specified [`CryptoProvider`].
    ///
    /// Server certificates will be verified using the trust anchors found in the provided `roots`.
    ///
    /// The cryptography used comes from the specified [`CryptoProvider`].
    ///
    /// For more information, see the [`ServerVerifierBuilder`] documentation.
    pub fn builder(roots: Arc<RootCertStore>, provider: &CryptoProvider) -> ServerVerifierBuilder {
        ServerVerifierBuilder::new(roots, provider.signature_verification_algorithms)
    }

    /// Short-cut for creating a `WebPkiServerVerifier` that does not perform certificate revocation
    /// checking, avoiding the need to use a builder.
    pub(crate) fn new_without_revocation(
        roots: impl Into<Arc<RootCertStore>>,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self::new(
            roots,
            Vec::default(),
            RevocationCheckDepth::Chain,
            UnknownStatusPolicy::Allow,
            ExpirationPolicy::Ignore,
            supported_algs,
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
        revocation_expiration_policy: ExpirationPolicy,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots: roots.into(),
            crls,
            revocation_check_depth,
            unknown_revocation_policy,
            revocation_expiration_policy,
            supported,
        }
    }
}

impl ServerVerifier for WebPkiServerVerifier {
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
    fn verify_identity(&self, identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        let certificates = match identity.identity {
            Identity::X509(certificates) => certificates,
            Identity::RawPublicKey(_) => {
                return Err(ApiMisuse::UnverifiableCertificateType.into());
            }
        };

        let cert = ParsedCertificate::try_from(&certificates.end_entity)?;
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
                    .with_expiration_policy(self.revocation_expiration_policy)
                    .build(),
            )
        };

        // Note: we use the crate-internal `_impl` fn here in order to provide revocation
        // checking information, if applicable.
        verify_identity_signed_by_trust_anchor_impl(
            &cert,
            &self.roots,
            &certificates.intermediates,
            revocation,
            identity.now,
            self.supported.all,
        )?;

        verify_server_name(&cert, identity.server_name)?;
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(input, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(input, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        self.hash(&mut DynHasher(h));
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::{println, vec};

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, CertificateRevocationListDer};

    use super::{VerifierBuilderError, WebPkiServerVerifier};
    use crate::sync::Arc;
    use crate::{RootCertStore, TEST_PROVIDERS};

    fn load_crls(crls_der: &[&[u8]]) -> Vec<CertificateRevocationListDer<'static>> {
        crls_der
            .iter()
            .map(|pem_bytes| CertificateRevocationListDer::from_pem_slice(pem_bytes).unwrap())
            .collect()
    }

    fn test_crls() -> Vec<CertificateRevocationListDer<'static>> {
        load_crls(&[
            include_bytes!("../../../test-ca/ecdsa-p256/client.revoked.crl.pem").as_slice(),
            include_bytes!("../../../test-ca/rsa-2048/client.revoked.crl.pem").as_slice(),
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
            include_bytes!("../../../test-ca/ecdsa-p256/ca.der").as_slice(),
            include_bytes!("../../../test-ca/rsa-2048/ca.der").as_slice(),
        ])
    }

    #[test]
    fn test_with_invalid_crls() {
        for provider in TEST_PROVIDERS {
            // Trying to build a server verifier with invalid CRLs should error at build time.
            let result = WebPkiServerVerifier::builder(test_roots(), provider)
                .with_crls(vec![CertificateRevocationListDer::from(vec![0xFF])])
                .build();
            assert!(matches!(result, Err(VerifierBuilderError::InvalidCrl(_))));
        }
    }

    #[test]
    fn test_with_crls_multiple_calls() {
        // We should be able to call `with_crls` on a server verifier multiple times.
        let initial_crls = test_crls();
        let extra_crls =
            load_crls(&[
                include_bytes!("../../../test-ca/eddsa/client.revoked.crl.pem").as_slice(),
            ]);

        for provider in TEST_PROVIDERS {
            let builder = WebPkiServerVerifier::builder(test_roots(), provider)
                .with_crls(initial_crls.clone())
                .with_crls(extra_crls.clone());

            // There should be the expected number of crls.
            assert_eq!(builder.crls.len(), initial_crls.len() + extra_crls.len());
            // The builder should be Debug.
            println!("{builder:?}");
            builder.build().unwrap();
        }
    }

    #[test]
    fn test_builder_no_roots() {
        for provider in TEST_PROVIDERS {
            // Trying to create a server verifier builder with no trust anchors should fail at build time
            let result =
                WebPkiServerVerifier::builder(RootCertStore::empty().into(), provider).build();
            assert!(matches!(result, Err(VerifierBuilderError::NoRootAnchors)));
        }
    }

    #[test]
    fn test_server_verifier_ee_only() {
        for provider in TEST_PROVIDERS {
            // We should be able to build a server cert. verifier that only checks the EE cert.
            let builder = WebPkiServerVerifier::builder(test_roots(), provider)
                .only_check_end_entity_revocation();
            // The builder should be Debug.
            println!("{builder:?}");
            builder.build().unwrap();
        }
    }

    #[test]
    fn test_server_verifier_allow_unknown() {
        for provider in TEST_PROVIDERS {
            // We should be able to build a server cert. verifier that allows unknown revocation
            // status.
            let builder = WebPkiServerVerifier::builder(test_roots(), provider)
                .allow_unknown_revocation_status();
            // The builder should be Debug.
            println!("{builder:?}");
            builder.build().unwrap();
        }
    }

    #[test]
    fn test_server_verifier_allow_unknown_ee_only() {
        for provider in TEST_PROVIDERS {
            // We should be able to build a server cert. verifier that allows unknown revocation
            // status and only checks the EE cert.
            let builder = WebPkiServerVerifier::builder(test_roots(), provider)
                .allow_unknown_revocation_status()
                .only_check_end_entity_revocation();
            // The builder should be Debug.
            println!("{builder:?}");
            builder.build().unwrap();
        }
    }

    #[test]
    fn test_server_verifier_enforce_expiration() {
        for provider in TEST_PROVIDERS {
            // We should be able to build a server cert. verifier that allows unknown revocation
            // status.
            let builder = WebPkiServerVerifier::builder(test_roots(), provider)
                .enforce_revocation_expiration();
            // The builder should be Debug.
            println!("{builder:?}");
            builder.build().unwrap();
        }
    }
}
