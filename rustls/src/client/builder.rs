use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::crypto::{CryptoProvider, KeyExchange};
#[cfg(feature = "ring")]
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::suites::SupportedCipherSuite;
use crate::{verify, versions, webpki};

use super::client_conn::Resumption;

use pki_types::{CertificateDer, PrivateKeyDer};

use alloc::sync::Arc;
use core::marker::PhantomData;

impl<C: CryptoProvider> ConfigBuilder<ClientConfig<C>, WantsVerifier<C>> {
    #[cfg(feature = "ring")]
    /// Choose how to verify server certificates.
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig<C>, WantsClientCert<C>> {
        ConfigBuilder {
            state: WantsClientCert {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                versions: self.state.versions,
                verifier: Arc::new(webpki::WebPkiServerVerifier::new(root_store)),
            },
            side: PhantomData,
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
    #[cfg(feature = "ring")]
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig<C>, Error> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    #[cfg(feature = "ring")]
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    #[deprecated(since = "0.21.4", note = "Use `with_client_auth_cert` instead")]
    pub fn with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig<C>, Error> {
        self.with_client_auth_cert(cert_chain, key_der)
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
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
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
