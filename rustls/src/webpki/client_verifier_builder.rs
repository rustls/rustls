use std::sync::Arc;

use pki_types::CertificateRevocationListDer;
use webpki::BorrowedCertRevocationList;

use super::verify::{AnonymousClientPolicy, WebPkiClientVerifier, WebPkiSupportedAlgorithms};
use crate::verify::ClientCertVerifier;
use crate::{CertRevocationListError, RootCertStore};

/// A builder for configuring a `webpki` client certificate verifier.
///
/// For more information, see the [`WebPkiClientVerifier`] documentation.
#[derive(Debug, Clone)]
pub struct ClientCertVerifierBuilder {
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    anon_policy: AnonymousClientPolicy,
    supported_algs: Option<WebPkiSupportedAlgorithms>,
}

impl ClientCertVerifierBuilder {
    pub(crate) fn new(roots: Arc<RootCertStore>) -> Self {
        Self {
            roots,
            crls: Vec::new(),
            anon_policy: AnonymousClientPolicy::Deny,
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

    /// Allow unauthenticated clients to connect.
    ///
    /// Clients that offer a client certificate issued by a trusted root, and clients that offer no
    /// client certificate will be allowed to connect.
    pub fn allow_unauthenticated(mut self) -> Self {
        self.anon_policy = AnonymousClientPolicy::Allow;
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

    /// Build a client certificate verifier. The built verifier will be used for the server to offer
    /// client certificate authentication, to control how offered client certificates are validated,
    /// and to determine what to do with anonymous clients that do not respond to the client
    /// certificate authentication offer with a client certificate.
    ///
    /// If the `ring` crate feature is supplied, and `with_signature_verification_algorithms` was not
    /// called on the builder, a default set of signature verification algorithms is used.
    ///
    /// Once built, the provided `Arc<dyn ClientCertVerifier>` can be used with a Rustls
    /// [crate::server::ServerConfig] to configure client certificate validation using
    /// [`with_client_cert_verifier`][crate::ConfigBuilder<ClientConfig, WantsVerifier>::with_client_cert_verifier].
    ///
    /// # Errors
    /// This function will return a `ClientCertVerifierBuilderError` if:
    /// 1. No trust anchors have been provided.
    /// 2. DER encoded CRLs have been provided that can not be parsed successfully.
    /// 3. No signature verification algorithms were set and the `ring` feature is not enabled.
    pub fn build(mut self) -> Result<Arc<dyn ClientCertVerifier>, ClientCertVerifierBuilderError> {
        if self.roots.is_empty() {
            return Err(ClientCertVerifierBuilderError::NoRootAnchors);
        }

        #[cfg(feature = "ring")]
        if self.supported_algs.is_none() {
            self.supported_algs = Some(super::verify::SUPPORTED_SIG_ALGS);
        }

        let supported_algs = self
            .supported_algs
            .ok_or(ClientCertVerifierBuilderError::NoSupportedAlgorithms)?;

        Ok(Arc::new(WebPkiClientVerifier::new(
            self.roots,
            self.crls
                .into_iter()
                .map(|der_crl| {
                    BorrowedCertRevocationList::from_der(der_crl.as_ref())
                        .and_then(|crl| crl.to_owned())
                        .map_err(CertRevocationListError::from)
                })
                .collect::<Result<Vec<_>, CertRevocationListError>>()?,
            self.anon_policy,
            supported_algs,
        )))
    }
}

/// One or more root trust anchors must be provided to create a [ClientCertVerifierBuilder].
/// If you wish to disable client authentication, then use [WebPkiClientVerifier::no_client_auth]
/// instead of constructing a builder.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ClientCertVerifierBuilderError {
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

impl From<CertRevocationListError> for ClientCertVerifierBuilderError {
    fn from(value: CertRevocationListError) -> Self {
        Self::InvalidCrl(value)
    }
}

#[cfg(all(test, feature = "ring"))]
mod tests {
    use crate::server::ClientCertVerifierBuilderError;
    use crate::webpki::verify::WebPkiClientVerifier;
    use crate::RootCertStore;

    use pki_types::{CertificateDer, CertificateRevocationListDer};

    use std::sync::Arc;

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
    fn test_noauth() {
        // We should be able to build a verifier that turns off client authentication.
        WebPkiClientVerifier::no_client_auth();
    }

    #[test]
    fn test_required_auth() {
        // We should be able to build a verifier that requires client authentication, and does
        // no revocation checking.
        let builder = WebPkiClientVerifier::builder(test_roots());
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_optional_auth() {
        // We should be able to build a verifier that allows client authentication, and anonymous
        // access, and does no revocation checking.
        let builder = WebPkiClientVerifier::builder(test_roots()).allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_without_crls_required_auth() {
        // We should be able to build a verifier that requires client authentication, and does
        // no revocation checking, that hasn't been configured to determine how to handle
        // unauthenticated clients yet.
        let builder = WebPkiClientVerifier::builder(test_roots());
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_without_crls_opptional_auth() {
        // We should be able to build a verifier that allows client authentication,
        // and anonymous access, that does no revocation checking.
        let builder = WebPkiClientVerifier::builder(test_roots()).allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_with_invalid_crls() {
        // Trying to build a verifier with invalid CRLs should error at build time.
        let result = WebPkiClientVerifier::builder(test_roots())
            .with_crls(vec![CertificateRevocationListDer::from(vec![0xFF])])
            .build();
        assert!(matches!(
            result,
            Err(ClientCertVerifierBuilderError::InvalidCrl(_))
        ));
    }

    #[test]
    fn test_with_crls_multiple_calls() {
        // We should be able to call `with_crls` multiple times.
        let initial_crls = test_crls();
        let extra_crls =
            load_crls(&[
                include_bytes!("../../../test-ca/eddsa/client.revoked.crl.pem").as_slice(),
            ]);
        let builder = WebPkiClientVerifier::builder(test_roots())
            .with_crls(initial_crls.clone())
            .with_crls(extra_crls.clone());

        // There should be the expected number of crls.
        assert_eq!(builder.crls.len(), initial_crls.len() + extra_crls.len());
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_with_crls_required_auth_implicit() {
        // We should be able to build a verifier that requires client authentication, and that does
        // revocation checking with CRLs, and that does not allow any anonymous access.
        let builder = WebPkiClientVerifier::builder(test_roots()).with_crls(test_crls());
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_with_crls_optional_auth() {
        // We should be able to build a verifier that supports client authentication, that does
        // revocation checking with CRLs, and that allows anonymous access.
        let builder = WebPkiClientVerifier::builder(test_roots())
            .with_crls(test_crls())
            .allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build().unwrap();
    }

    #[test]
    fn test_builder_no_roots() {
        // Trying to create a builder with no trust anchors should fail at build time
        let result = WebPkiClientVerifier::builder(RootCertStore::empty().into()).build();
        assert!(matches!(
            result,
            Err(ClientCertVerifierBuilderError::NoRootAnchors)
        ));
    }
}
