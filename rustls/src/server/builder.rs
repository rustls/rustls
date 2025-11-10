use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::PrivateKeyDer;

use super::server_conn::InvalidSniPolicy;
use super::{ServerConfig, ServerCredentialResolver, handy};
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::crypto::{Credentials, Identity, SingleCredential};
use crate::error::Error;
use crate::sync::Arc;
use crate::verify::{ClientVerifier, NoClientAuth};
use crate::{NoKeyLog, compress};

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                verifier: client_cert_verifier,
            },
            provider: self.provider,
            time_provider: self.time_provider,
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
    verifier: Arc<dyn ClientVerifier>,
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
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert(
        self,
        identity: Arc<Identity<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let credentials = Credentials::from_der(identity, key_der, self.crypto_provider())?;
        self.with_server_credential_resolver(Arc::new(SingleCredential::from(credentials)))
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    /// `ocsp` is a DER-encoded OCSP response.  Ignored if zero length.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert_with_ocsp(
        self,
        identity: Arc<Identity<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Arc<[u8]>,
    ) -> Result<ServerConfig, Error> {
        let mut credentials = Credentials::from_der(identity, key_der, self.crypto_provider())?;
        if !ocsp.is_empty() {
            credentials.ocsp = Some(ocsp);
        }
        self.with_server_credential_resolver(Arc::new(SingleCredential::from(credentials)))
    }

    /// Sets a custom [`ServerCredentialResolver`].
    pub fn with_server_credential_resolver(
        self,
        cert_resolver: Arc<dyn ServerCredentialResolver>,
    ) -> Result<ServerConfig, Error> {
        self.provider.consistency_check()?;
        Ok(ServerConfig {
            provider: self.provider,
            verifier: self.state.verifier,
            cert_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            #[cfg(feature = "std")]
            session_storage: handy::ServerSessionMemoryCache::new(256),
            #[cfg(not(feature = "std"))]
            session_storage: Arc::new(handy::NoServerSessionStorage {}),
            ticketer: None,
            alpn_protocols: Vec::new(),
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 2,
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            invalid_sni_policy: InvalidSniPolicy::default(),
        })
    }
}
