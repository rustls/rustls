use crate::anchors;
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::error::Error;
use crate::key;
use crate::keylog::NoKeyLog;
use crate::kx::SupportedKxGroup;
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::versions;

use std::sync::Arc;

/// A client config in progress, where the next step is to configure how
/// to validate server certificates (typically with a set root certificates).
pub struct ConfigWantsServerVerifier {
    pub(crate) cipher_suites: Vec<SupportedCipherSuite>,
    pub(crate) kx_groups: Vec<&'static SupportedKxGroup>,
    pub(crate) versions: versions::EnabledVersions,
}

impl ConfigWantsServerVerifier {
    /// Choose how to verify client certificates.
    pub fn with_root_certificates(
        self,
        root_store: anchors::RootCertStore,
        ct_logs: &'static [&'static sct::Log],
    ) -> ConfigWantsClientCert {
        let verifier = Arc::new(verify::WebPkiVerifier::new(root_store, ct_logs));

        ConfigWantsClientCert {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
            verifier,
        }
    }

    #[cfg(feature = "dangerous_configuration")]
    /// Set a custom certificate verifier.
    pub fn with_custom_certificate_verifier(
        self,
        verifier: Arc<dyn verify::ServerCertVerifier>,
    ) -> ConfigWantsClientCert {
        ConfigWantsClientCert {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
            verifier,
        }
    }
}

/// A config builder for a client, where we want to know whether and how a
/// client certificate should be provided.
pub struct ConfigWantsClientCert {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ConfigWantsClientCert {
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
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            alpn_protocols: Vec::new(),
            session_storage: handy::ClientSessionMemoryCache::new(256),
            max_fragment_size: None,
            client_auth_cert_resolver,
            enable_tickets: true,
            versions: self.versions,
            enable_sni: true,
            verifier: self.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_early_data: false,
        }
    }
}
