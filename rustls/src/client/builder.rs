use crate::versions::TLS13;
#[cfg(feature = "impit")]
use crate::{KeyLog, KeyLogFile};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
#[cfg(feature = "impit")]
use std::vec;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{handy, ClientConfig, EchMode, ResolvesClientCert};
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::msgs::handshake::CertificateChain;
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
        #[cfg(not(feature = "impit"))]
        let mut res = self.with_protocol_versions(&[&TLS13][..])?;
        #[cfg(feature = "impit")]
        let mut res = self.with_safe_default_protocol_versions()?; // It's alright to send the ECH with TLS 1.2, worst case, the server will ignore it.

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
                versions: self.state.versions,
                verifier,
                client_ech_mode: self.state.client_ech_mode,
            },
            provider: self.provider,
            time_provider: self.time_provider,
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
                    versions: self.cfg.state.versions,
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

#[cfg(feature = "impit")]
#[derive(Debug, Clone)]
/// Emulate a browser's behavior.
pub enum BrowserType {
    /// Emulate Chrome's behavior.
    Chrome,
    /// Emulate Firefox's behavior.
    Firefox,
}

#[cfg(feature = "impit")]
/// Struct holding the browser emulator configuration.
#[derive(Debug, Clone)]
pub struct BrowserEmulator {
    /// Emulated browser, e.g. Chrome or Firefox
    pub browser_type: BrowserType,
    /// Browser version
    pub version: u8,
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Enable a browser emulator.
    #[cfg(feature = "impit")]
    pub fn with_browser_emulator(
        self,
        browser_emulator: &BrowserEmulator,
    ) -> ConfigBuilder<ClientConfig, WantsClientCertWithBrowserEmulationEnabled> {
        ConfigBuilder {
            state: WantsClientCertWithBrowserEmulationEnabled {
                versions: self.state.versions,
                verifier: self.state.verifier,
                client_ech_mode: self.state.client_ech_mode,
                browser_emulator: browser_emulator.clone(),
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let private_key = self
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
            provider: self.provider,
            alpn_protocols: Vec::new(),
            #[cfg(feature = "impit")]
            browser_emulation: None,
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
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[cfg(feature = "impit")]
#[derive(Clone)]
pub struct WantsClientCertWithBrowserEmulationEnabled {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
    browser_emulator: BrowserEmulator,
}

#[cfg(feature = "impit")]
impl ConfigBuilder<ClientConfig, WantsClientCertWithBrowserEmulationEnabled> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let private_key = self
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
        let (alpn_protocols, cert_compressors, cert_decompressors) =
            match self.state.browser_emulator {
                BrowserEmulator {
                    browser_type: BrowserType::Chrome,
                    version: _,
                } => (
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                    vec![crate::compress::BROTLI_COMPRESSOR],
                    vec![crate::compress::BROTLI_DECOMPRESSOR],
                ),
                BrowserEmulator {
                    browser_type: BrowserType::Firefox,
                    version: _,
                } => (vec![b"h2".to_vec(), b"http/1.1".to_vec()], vec![], vec![]),
            };

        let key_log: Arc<dyn KeyLog> = match self.state.browser_emulator {
            _ => Arc::new(KeyLogFile::new()),
        };

        ClientConfig {
            browser_emulation: Some(self.state.browser_emulator),
            provider: self.provider,
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            alpn_protocols,
            key_log,
            cert_compressors,
            cert_decompressors,
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            ech_mode: self.state.client_ech_mode,
        }
    }
}
