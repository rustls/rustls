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

/// Building a [`ServerConfig`] in a linker-friendly way.
///
/// Linker-friendly: meaning unused cipher suites, protocol
/// versions, key exchange mechanisms, etc. can be discarded
/// by the linker as they'll be unreferenced.
///
/// Example:
///
/// ```no_run
/// # use rustls::ConfigBuilder;
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ConfigBuilder::with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_safe_default_protocol_versions()
///     .for_server()
///     .unwrap()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// This may be shortened to:
///
/// ```no_run
/// # use rustls::ConfigBuilder;
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ConfigBuilder::with_safe_defaults()
///     .for_server()
///     .unwrap()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// # Resulting [`ServerConfig`] defaults
/// * [`ServerConfig::max_fragment_size`]: the default is `None`: TLS packets are not fragmented to a specific size.
/// * [`ServerConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ServerConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ServerConfig::key_log`]: key material is not logged.
pub struct ServerConfigBuilder {
    pub(crate) cipher_suites: Vec<SupportedCipherSuite>,
    pub(crate) kx_groups: Vec<&'static SupportedKxGroup>,
    pub(crate) versions: versions::EnabledVersions,
}

impl ServerConfigBuilder {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn verify::ClientCertVerifier>,
    ) -> ServerConfigBuilderWithClientAuth {
        ServerConfigBuilderWithClientAuth {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
            verifier: client_cert_verifier,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ServerConfigBuilderWithClientAuth {
        self.with_client_cert_verifier(verify::NoClientAuth::new())
    }
}

/// A [`ServerConfigBuilder`] where we know the cipher suites, key exchange
/// groups, enabled versions, and client auth policy.
pub struct ServerConfigBuilderWithClientAuth {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ClientCertVerifier>,
}

impl ServerConfigBuilderWithClientAuth {
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
