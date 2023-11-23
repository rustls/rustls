use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::msgs::handshake::CertificateChain;
use crate::server::handy;
use crate::server::{ResolvesServerCert, ServerConfig};
use crate::verify::{ClientCertVerifier, NoClientAuth};
use crate::versions;
use crate::NoKeyLog;

use pki_types::{CertificateDer, PrivateKeyDer};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                provider: self.state.provider,
                versions: self.state.versions,
                verifier: client_cert_verifier,
            },
            side: PhantomData,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        self.with_client_cert_verifier(Arc::new(NoClientAuth))
    }
}

/// A config builder state where the caller must supply how to provide a server certificate to
/// the connecting peer.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsServerCert {
    provider: Arc<CryptoProvider>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn ClientCertVerifier>,
}

impl ConfigBuilder<ServerConfig, WantsServerCert> {
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
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support all three encodings,
    /// but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let private_key = self
            .state
            .provider
            .key_provider
            .load_private_key(key_der)?;
        let resolver = handy::AlwaysResolvesChain::new(private_key, CertificateChain(cert_chain));
        Ok(self.with_cert_resolver(Arc::new(resolver)))
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support all three encodings,
    /// but other `CryptoProviders` may not.
    /// `ocsp` is a DER-encoded OCSP response.  Ignored if zero length.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert_with_ocsp(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<ServerConfig, Error> {
        let private_key = self
            .state
            .provider
            .key_provider
            .load_private_key(key_der)?;
        let resolver = handy::AlwaysResolvesChain::new_with_extras(
            private_key,
            CertificateChain(cert_chain),
            ocsp,
        );
        Ok(self.with_cert_resolver(Arc::new(resolver)))
    }

    /// Sets a custom [`ResolvesServerCert`].
    pub fn with_cert_resolver(self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
        ServerConfig {
            provider: self.state.provider,
            verifier: self.state.verifier,
            cert_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            session_storage: handy::ServerSessionMemoryCache::new(256),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: self.state.versions,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 4,
        }
    }
}
