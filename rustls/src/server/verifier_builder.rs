use std::{fmt, sync::Arc};

use crate::server::UnparsedCertRevocationList;
use crate::verify::{
    AnonymousClientsPolicy, ClientCertVerifier, NoClientAuth, WebpkiClientVerifier,
};
use crate::{CertRevocationListError, RootCertStore};

/// A builder for configuring a `webpki` client certificate verifier.
///
/// For more information, see the [`WebpkiClientVerifier`] documentation.
#[derive(Clone)]
pub struct ClientCertVerifierBuilder<State> {
    pub(crate) state: State,
}

impl<State: fmt::Debug> fmt::Debug for ClientCertVerifierBuilder<State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_name = std::any::type_name::<State>();
        let (_, param) = state_name
            .rsplit_once("::")
            .unwrap_or(("", "Unknown"));
        f.debug_struct(&format!("ClientCertVerifierBuilder<{}>", param))
            .field("state", &self.state)
            .finish()
    }
}

/// A client certificate verifier builder state where the caller must decide whether to perform
/// client certificate authentication using a [RootCertStore], or not.
///
/// For more information, see the [`WebpkiClientVerifier`] documentation.
#[derive(Clone, Debug)]
pub struct WantsClientAuthentication(pub(crate) ());

impl ClientCertVerifierBuilder<WantsClientAuthentication> {
    /// Disable client certificate authentication. No client certificate authentication will be
    /// done, allowing unauthenticated client access to the server.
    pub fn allow_unauthenticated(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::new(NoClientAuth {})
    }

    /// Verify that if a client offers a client certificate, that it is issued by a trust anchor
    /// present in the provided [RootCertStore].
    ///
    /// All clients must provide a client certificate unless you further allow unauthenticated
    /// clients by calling [allow_unauthenticated()][ClientCertVerifierBuilder<WantsCrls>::allow_unauthenticated]
    /// on the returned builder.
    pub fn with_roots(&self, roots: RootCertStore) -> ClientCertVerifierBuilder<WantsCrls> {
        ClientCertVerifierBuilder {
            state: WantsCrls { roots },
        }
    }
}

/// A client certificate verifier builder state where clients are verified using a [RootCertStore]
/// and the caller must now decide whether to perform certificate revocation list (CRL) checking,
/// and whether to allow unauthenticated clients in addition to those that supply a valid client
/// certificate.
///
/// For more information, see the [`WebpkiClientVerifier`] documentation.
#[derive(Clone, Debug)]
pub struct WantsCrls {
    roots: RootCertStore,
}

impl ClientCertVerifierBuilder<WantsCrls> {
    /// Build a client certificate that will allow clients that present a client certificate
    /// that is issued by a trusted CA, or anonymous clients that do not offer a client certificate
    /// at all. No revocation checking with CRLS will be done. This is useful for servers that
    /// expect both authenticated an unauthenticated clients and impose their own authentication
    /// and authorization.
    pub fn allow_unauthenticated(self) -> ClientCertVerifierBuilder<ClientAuthenticationOptional> {
        ClientCertVerifierBuilder {
            state: ClientAuthenticationOptional {
                roots: self.state.roots,
                crls: Vec::default(),
            },
        }
    }

    /// Build a client certificate verifier that will require all clients to present a client
    /// certificate that is issued by a trusted CA. No revocation checking with CRLs will be done.
    /// No anonymous clients will be allowed to access the server.
    ///
    /// Note that not providing CRLs means that clients accessing the server with revoked
    /// credentials will not be denied access.
    pub fn without_crls(self) -> ClientCertVerifierBuilder<WantsUnauthenticatedPolicy> {
        ClientCertVerifierBuilder {
            state: WantsUnauthenticatedPolicy {
                roots: self.state.roots,
                crls: Vec::default(),
            },
        }
    }

    /// Build a client certificate verifier that will require all clients to present a client
    /// certificate that is issued by a trusted CA. The revocation state of the client
    /// certificate will be checked against the provided certificate revocation lists (CRLs).
    ///
    /// All clients must provide a client certificate unless you further allow unauthenticated
    /// clients by calling
    /// [allow_unauthenticated()][ClientCertVerifierBuilder<WantsUnauthenticatedPolicy>::allow_unauthenticated]
    /// on the returned builder.
    pub fn with_crls(
        self,
        crls: impl IntoIterator<Item = UnparsedCertRevocationList>,
    ) -> Result<ClientCertVerifierBuilder<WantsUnauthenticatedPolicy>, CertRevocationListError>
    {
        let crls = crls
            .into_iter()
            .map(|der_crl| der_crl.parse())
            .collect::<Result<Vec<_>, CertRevocationListError>>()?;

        Ok(ClientCertVerifierBuilder {
            state: WantsUnauthenticatedPolicy {
                roots: self.state.roots,
                crls,
            },
        })
    }
}

/// A client certificate verifier builder state where clients are verified using a [RootCertStore]
/// and optionally may have their revocation status checked via CRLs. The caller must now decide
/// whether or not to allow unauthenticated clients in addition to those that supply a valid client
/// certificate.
///
/// For more information, see the [`WebpkiClientVerifier`] documentation.
#[derive(Debug, Clone)]
pub struct WantsUnauthenticatedPolicy {
    roots: RootCertStore,
    crls: Vec<webpki::OwnedCertRevocationList>,
}

impl ClientCertVerifierBuilder<WantsUnauthenticatedPolicy> {
    /// Build a client certificate verifier that will require all clients to present a client
    /// certificate that is issued by a trusted CA. If configured, revocation checking with CRLs
    /// will be done. No anonymous clients will be allowed to access the server.
    pub fn require_authentication(self) -> Arc<dyn ClientCertVerifier> {
        Arc::new(WebpkiClientVerifier::new(
            self.state.roots,
            self.state.crls,
            AnonymousClientsPolicy::Forbid,
        ))
    }

    /// Build a client certificate verifier that allows all clients that present a client
    /// certificate that is issued by a trusted CA, and anonymous clients that do not offer a
    /// client certificate at all. If configured, revocation checking with CRLs
    /// will be done when a client presents a certificate.
    pub fn allow_unauthenticated(self) -> ClientCertVerifierBuilder<ClientAuthenticationOptional> {
        ClientCertVerifierBuilder {
            state: ClientAuthenticationOptional {
                roots: self.state.roots,
                crls: self.state.crls,
            },
        }
    }
}

/// A client certificate verifier builder state where the server will allow clients that present
/// a client certificate that is issued by a trusted CA, and anonymous clients that do not offer a
/// client certificate at all. If configured, revocation checking with CRLs will be done when a
/// client presents a certificate.
#[derive(Debug, Clone)]
pub struct ClientAuthenticationOptional {
    roots: RootCertStore,
    crls: Vec<webpki::OwnedCertRevocationList>,
}

impl ClientCertVerifierBuilder<ClientAuthenticationOptional> {
    /// Build a client certificate verifier that allow all clients that present a client
    /// certificate that is issued by a trusted CA, and anonymous clients that do not offer a
    /// client certificate at all. If configured, revocation checking with CRLs
    /// will be done when a client presents a certificate.
    pub fn build(self) -> Arc<dyn ClientCertVerifier> {
        Arc::new(WebpkiClientVerifier::new(
            self.state.roots,
            self.state.crls,
            AnonymousClientsPolicy::Allow,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        server::UnparsedCertRevocationList, verify::WebpkiClientVerifier, CertRevocationListError,
        Certificate, RootCertStore,
    };

    fn test_crls() -> Vec<UnparsedCertRevocationList> {
        [
            include_bytes!("../../../test-ca/ecdsa/client.revoked.crl.pem").as_slice(),
            include_bytes!("../../../test-ca/rsa/client.revoked.crl.pem").as_slice(),
        ]
        .iter()
        .map(|pem_bytes| {
            UnparsedCertRevocationList(
                rustls_pemfile::crls(&mut &pem_bytes[..])
                    .unwrap()
                    .first()
                    .unwrap()
                    .to_vec(),
            )
        })
        .collect()
    }

    fn test_roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        [
            include_bytes!("../../../test-ca/ecdsa/ca.der").as_slice(),
            include_bytes!("../../../test-ca/rsa/ca.der").as_slice(),
        ]
        .iter()
        .for_each(|der| {
            roots
                .add(&Certificate(der.to_vec()))
                .unwrap()
        });
        roots
    }

    #[test]
    fn test_noauth() {
        // We should be able to build a verifier that does no client authentication.
        WebpkiClientVerifier::builder().allow_unauthenticated();
    }

    #[test]
    fn test_optional_auth() {
        // We should be able to build a verifier that allows client authentication, and anonymous
        // access, and does no revocation checking.
        let builder = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build();
    }

    #[test]
    fn test_without_crls_required_auth() {
        // We should be able to build a verifier that requires client authentication, and does
        // no revocation checking, that hasn't been configured to determine how to handle
        // unauthenticated clients yet.
        let builder = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .without_crls();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.require_authentication();
    }

    #[test]
    fn test_without_crls_opptional_auth() {
        // We should be able to build a verifier that allows client authentication,
        // and anonymous access, that does no revocation checking.
        let builder = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .without_crls()
            .allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build();
    }

    #[test]
    fn test_with_invalid_crls() {
        // Trying to build a verifier with invalid CRLs should error.
        let result = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .with_crls(vec![UnparsedCertRevocationList(vec![0xFF])]);
        assert!(matches!(result, Err(CertRevocationListError::ParseError)));
    }

    #[test]
    fn test_with_crls_required_auth_implicit() {
        // We should be able to build a verifier that requires client authentication, and that does
        // revocation checking with CRLs, and that does not allow any anonymous access.
        let builder = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .with_crls(test_crls())
            .unwrap();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.require_authentication();
    }

    #[test]
    fn test_with_crls_optional_auth() {
        // We should be able to build a verifier that supports client authentication, that does
        // revocation checking with CRLs, and that allows anonymous access.
        let builder = WebpkiClientVerifier::builder()
            .with_roots(test_roots())
            .with_crls(test_crls())
            .unwrap()
            .allow_unauthenticated();
        // The builder should be Debug.
        println!("{:?}", builder);
        builder.build();
    }
}
