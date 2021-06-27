use crate::error::Error;
use crate::key;
use crate::keylog::NoKeyLog;
use crate::kx::SupportedKxGroup;
use crate::server::handy;
use crate::server::{ResolvesServerCert, ServerConfig};
use crate::suites::SupportedCipherSuite;
use crate::verify;
use crate::versions;

use std::sync::Arc;

/// A server config in progress, where the next step is to configure whether
/// and how to authenticate clients.
pub struct ConfigWantsClientVerifier {
    pub(crate) cipher_suites: Vec<SupportedCipherSuite>,
    pub(crate) kx_groups: Vec<&'static SupportedKxGroup>,
    pub(crate) versions: versions::EnabledVersions,
}

impl ConfigWantsClientVerifier {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn verify::ClientCertVerifier>,
    ) -> ConfigWantsServerCert {
        ConfigWantsServerCert {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
            verifier: client_cert_verifier,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigWantsServerCert {
        self.with_client_cert_verifier(verify::NoClientAuth::new())
    }
}

/// A config builder for a server, where we want to know how to provide a
/// server certificate to a connecting peer.
pub struct ConfigWantsServerCert {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ClientCertVerifier>,
}

impl ConfigWantsServerCert {
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
    ) -> Result<ServerConfig, Error> {
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
    /// `scts` is an `SignedCertificateTimestampList` encoding (see RFC6962)
    /// and is ignored if empty.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert_with_ocsp_and_sct(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
        ocsp: Vec<u8>,
        scts: Vec<u8>,
    ) -> Result<ServerConfig, Error> {
        let resolver =
            handy::AlwaysResolvesChain::new_with_extras(cert_chain, &key_der, ocsp, scts)?;
        Ok(self.with_cert_resolver(Arc::new(resolver)))
    }

    /// Sets a custom [`ResolvesServerCert`].
    pub fn with_cert_resolver(self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
        ServerConfig {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            verifier: self.verifier,
            cert_resolver,
            ignore_client_order: false,
            max_fragment_size: None,
            session_storage: handy::ServerSessionMemoryCache::new(256),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: self.versions,
            key_log: Arc::new(NoKeyLog {}),
            #[cfg(feature = "quic")]
            max_early_data_size: 0,
        }
    }
}
