use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::{ResolvesServerCert, ResolvesServerIdentity, ResolvesServerRpk, ServerConfig, handy};
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::error::Error;
use crate::server::server_conn::{ResolvesServerCertCompat, ResolvesServerRpkWrapper};
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::verify::{
    ClientCertVerifier, ClientCertVerifierCompat, ClientIdVerifier, ClientRpkVerifier,
    ClientRpkVerifierWrapper, NoClientAuth,
};
use crate::{NoKeyLog, compress, versions};

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerIdentity> {
        self.with_client_id_verifier(Arc::new(ClientCertVerifierCompat::from(
            client_cert_verifier,
        )))
    }

    /// Choose how to verify client certificates.
    pub fn with_client_rpk_verifier(
        self,
        client_rpk_verifier: Arc<dyn ClientRpkVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerIdentity> {
        self.with_client_id_verifier(Arc::new(ClientRpkVerifierWrapper::from(client_rpk_verifier)))
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerIdentity> {
        self.with_client_cert_verifier(Arc::new(NoClientAuth))
    }

    /// Choose how to verify client identities.
    pub fn with_client_id_verifier(
        self,
        client_id_verifier: Arc<dyn ClientIdVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerIdentity> {
        ConfigBuilder {
            state: WantsServerIdentity {
                versions: self.state.versions,
                verifier: client_id_verifier,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }
}

/// A config builder state where the caller must supply how to provide a server certificate to
/// the connecting peer.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsServerIdentity {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn ClientIdVerifier>,
}

impl ConfigBuilder<ServerConfig, WantsServerIdentity> {
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
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        Ok(self.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
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
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Result<ServerConfig, Error> {
        let mut certified_key =
            CertifiedKey::from_der(cert_chain, key_der, self.crypto_provider())?;
        certified_key.ocsp = Some(ocsp);
        Ok(self.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Sets a custom [`ResolvesServerCert`].
    pub fn with_cert_resolver(self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
        self.with_identity_resolver(Arc::new(ResolvesServerCertCompat::from(cert_resolver)))
    }

    /// Sets a custom [`ResolvesServerRpk`].
    pub fn with_rpk_resolver(self, rpk_resolver: Arc<dyn ResolvesServerRpk>) -> ServerConfig {
        self.with_identity_resolver(Arc::new(ResolvesServerRpkWrapper::from(rpk_resolver)))
    }

    /// Sets a custom [`ResolvesServerIdentity`].
    pub fn with_identity_resolver(
        self,
        id_resolver: Arc<dyn ResolvesServerIdentity>,
    ) -> ServerConfig {
        ServerConfig {
            provider: self.provider,
            verifier: self.state.verifier,
            id_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            #[cfg(feature = "std")]
            session_storage: handy::ServerSessionMemoryCache::new(256),
            #[cfg(not(feature = "std"))]
            session_storage: Arc::new(handy::NoServerSessionStorage {}),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: self.state.versions,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 2,
            #[cfg(feature = "tls12")]
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
        }
    }
}
