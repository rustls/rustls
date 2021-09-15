use crate::anchors;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::error::Error;
use crate::key;
use crate::keylog::NoKeyLog;
use crate::kx::SupportedKxGroup;
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::versions;

use std::marker::PhantomData;
use std::sync::Arc;

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_root_certificates(
        self,
        root_store: anchors::RootCertStore,
    ) -> ConfigBuilder<ClientConfig, WantsTransparencyPolicy> {
        ConfigBuilder {
            state: WantsTransparencyPolicy {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                root_store,
            },
            side: PhantomData::default(),
        }
    }

    #[cfg(feature = "dangerous_configuration")]
    /// Set a custom certificate verifier.
    pub fn with_custom_certificate_verifier(
        self,
        verifier: Arc<dyn verify::ServerCertVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier,
            },
            side: PhantomData::default(),
        }
    }
}

pub struct WantsTransparencyPolicy {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    root_store: anchors::RootCertStore,
}

impl ConfigBuilder<ClientConfig, WantsTransparencyPolicy> {
    /// Do not verify server certificates against a Certificate Transparency log.
    pub fn without_certificate_transparency_logs(
        self,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        self.with_logs(&[])
    }

    /// Set Certificate Transparency logs to use for server certificate validation.
    pub fn with_certificate_transparency_logs(
        self,
        ct_logs: &'static [&'static sct::Log],
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        self.with_logs(ct_logs)
    }

    fn with_logs(
        self,
        ct_logs: &'static [&'static sct::Log],
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier: Arc::new(verify::WebPkiVerifier::new(self.state.root_store, ct_logs)),
            },
            side: PhantomData,
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
pub struct WantsClientCert {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<ClientConfig, Error> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        ClientConfig {
            cipher_suites: self.state.cipher_suites,
            kx_groups: self.state.kx_groups,
            alpn_protocols: Vec::new(),
            session_storage: handy::ClientSessionMemoryCache::new(256),
            max_fragment_size: None,
            client_auth_cert_resolver,
            enable_tickets: true,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_early_data: false,
        }
    }
}
