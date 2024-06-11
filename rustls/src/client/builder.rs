use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{handy, ClientConfig, EchMode, ResolvesClientCert};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::msgs::handshake::CertificateChain;
use crate::time_provider::TimeProvider;
use crate::versions::TLS13;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{compress, verify, versions, WantsVersions};

impl ConfigBuilder<ClientConfig, WantsVersions> {
    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This implicitly selects TLS 1.3 as the only supported protocol version to meet the
    /// requirement to support ECH.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(
        self,
        mode: EchMode,
    ) -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, Error> {
        let mut res = self.with_protocol_versions(&[&TLS13][..])?;
        res.state.client_ech_mode = Some(mode);
        Ok(res)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .state
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                provider: self.state.provider,
                versions: self.state.versions,
                verifier,
                time_provider: self.state.time_provider,
                client_ech_mode: self.state.client_ech_mode,
            },
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use alloc::sync::Arc;
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::{verify, ClientConfig, ConfigBuilder, WantsVerifier};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    provider: self.cfg.state.provider,
                    versions: self.cfg.state.versions,
                    verifier,
                    time_provider: self.cfg.state.time_provider,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                },
                side: PhantomData,
            }
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    provider: Arc<CryptoProvider>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    time_provider: Arc<dyn TimeProvider>,
    client_ech_mode: Option<EchMode>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support all three encodings,
    /// but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let private_key = self
            .state
            .provider
            .key_provider
            .load_private_key(key_der)?;
        let resolver =
            handy::AlwaysResolvesClientCert::new(private_key, CertificateChain(cert_chain))?;
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
            provider: self.state.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems: cfg!(feature = "fips"),
            time_provider: self.state.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
        }
    }
}
