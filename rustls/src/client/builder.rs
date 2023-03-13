use crate::anchors;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::crypto::{CryptoProvider, KeyExchange};
use crate::error::Error;
use crate::key;
use crate::suites::SupportedCipherSuite;
use crate::verify::{self, CertificateTransparencyPolicy};
use crate::versions;
use crate::NoKeyLog;

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::SystemTime;

impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsVerifier<C>> {
    /// Choose how to verify client certificates.
    pub fn with_root_certificates(
        self,
        root_store: anchors::RootCertStore,
    ) -> ConfigBuilder<ClientConfig<C>, WantsTransparencyPolicyOrClientCert<C>> {
        ConfigBuilder {
            state: WantsTransparencyPolicyOrClientCert {
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
    ) -> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
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

/// A config builder state where the caller needs to supply a certificate transparency policy or
/// client certificate resolver.
///
/// In this state, the caller can optionally enable certificate transparency, or ignore CT and
/// invoke one of the methods related to client certificates (as in the [`WantsClientCert`] state).
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsTransparencyPolicyOrClientCert<C: CryptoProvider> {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static <C::KeyExchange as KeyExchange>::SupportedGroup>,
    versions: versions::EnabledVersions,
    root_store: anchors::RootCertStore,
}

impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsTransparencyPolicyOrClientCert<C>> {
    /// Set Certificate Transparency logs to use for server certificate validation.
    ///
    /// Because Certificate Transparency logs are sharded on a per-year basis and can be trusted or
    /// distrusted relatively quickly, rustls stores a validation deadline. Server certificates will
    /// be validated against the configured CT logs until the deadline expires. After the deadline,
    /// certificates will no longer be validated, and a warning message will be logged. The deadline
    /// may vary depending on how often you deploy builds with updated dependencies.
    pub fn with_certificate_transparency_logs(
        self,
        logs: &'static [&'static sct::Log],
        validation_deadline: SystemTime,
    ) -> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
        self.with_logs(Some(CertificateTransparencyPolicy::new(
            logs,
            validation_deadline,
        )))
    }

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
    ) -> Result<ClientConfig<C>, Error> {
        self.with_logs(None)
            .with_single_cert(cert_chain, key_der)
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig<C> {
        self.with_logs(None)
            .with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig<C> {
        self.with_logs(None)
            .with_client_cert_resolver(client_auth_cert_resolver)
    }

    fn with_logs(
        self,
        ct_policy: Option<CertificateTransparencyPolicy>,
    ) -> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier: Arc::new(verify::WebPkiVerifier::new(
                    self.state.root_store,
                    ct_policy,
                )),
            },
            side: PhantomData,
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsClientCert<C: CryptoProvider> {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static <<C as CryptoProvider>::KeyExchange as KeyExchange>::SupportedGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
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
    ) -> Result<ClientConfig<C>, Error> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig<C> {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig<C> {
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
            #[cfg(feature = "secret_extraction")]
            enable_secret_extraction: false,
            enable_early_data: false,
            provider: PhantomData,
        }
    }
}
