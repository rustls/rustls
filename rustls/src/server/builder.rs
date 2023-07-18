use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::key;
use crate::kx::SupportedKxGroup;
use crate::server::handy;
use crate::server::{ResolvesServerCert, ServerConfig};
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::versions;
use crate::NoKeyLog;

use std::marker::PhantomData;
use std::sync::Arc;

impl<C: CryptoProvider> ConfigBuilder<ServerConfig<C>, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn verify::ClientCertVerifier>,
    ) -> ConfigBuilder<ServerConfig<C>, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier: client_cert_verifier,
            },
            side: PhantomData,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig<C>, WantsServerCert> {
        self.with_client_cert_verifier(verify::NoClientAuth::boxed())
    }
}

/// A config builder state where the caller must supply how to provide a server certificate to
/// the connecting peer.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsServerCert {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ClientCertVerifier>,
}

impl<C: CryptoProvider> ConfigBuilder<ServerConfig<C>, WantsServerCert> {
    /// Sets a single certificate chain and matching private key.  This
    /// certificate and key is used for all subsequent connections,
    /// irrespective of things like SNI hostname.
    ///
    /// Note that the end-entity certificate must have the
    /// [Subject Alternative Name](https://tools.ietf.org/html/rfc6125#section-4.1)
    /// extension to describe, e.g., the valid DNS name. The `commonName` field is
    /// disregarded.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<ServerConfig<C>, Error> {
        let resolver = handy::AlwaysResolvesChain::new(cert_chain, &key_der)?;
        Ok(self.with_cert_resolver(Arc::new(resolver)))
    }

    /// Sets a single certificate chain, matching private key, OCSP
    /// response and SCTs.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    /// `ocsp` is a DER-encoded OCSP response.  Ignored if zero length.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
        ocsp: Vec<u8>,
    ) -> Result<ServerConfig<C>, Error> {
        let resolver = handy::AlwaysResolvesChain::new_with_extras(cert_chain, &key_der, ocsp)?;
        Ok(self.with_cert_resolver(Arc::new(resolver)))
    }

    /// Sets a custom [`ResolvesServerCert`].
    pub fn with_cert_resolver(self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig<C> {
        ServerConfig {
            cipher_suites: self.state.cipher_suites,
            kx_groups: self.state.kx_groups,
            verifier: self.state.verifier,
            cert_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            session_storage: handy::ServerSessionMemoryCache::new(256),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: self.state.versions,
            key_log: Arc::new(NoKeyLog {}),
            #[cfg(feature = "secret_extraction")]
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 4,
            provider: PhantomData,
        }
    }
}
