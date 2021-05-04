use crate::error::Error;
use crate::key;
use crate::keylog::NoKeyLog;
use crate::kx::{SupportedKxGroup, ALL_KX_GROUPS};
use crate::server::handy;
use crate::server::{ResolvesServerCert, ServerConfig};
use crate::suites::{SupportedCipherSuite, DEFAULT_CIPHERSUITES};
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
/// ```ignore
/// ServerConfigBuilder::new()
///     .with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .build();
/// ```
///
/// This may be shortened to:
///
/// ```ignore
/// ServerConfigBuilder::with_safe_default_crypto()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .build();
/// ```
///
/// The types used here fit together like this:
///
/// 1. Get a [`ServerConfigBuilder`] with [`ServerConfigBuilder::new()`].
///    You must make a decision on which cipher suites to use, typically
///    by calling [`ServerConfigBuilder::with_safe_default_cipher_suites()`].
/// 2. You now have a [`ServerConfigBuilderWithSuites`].  You must make a decision
///    on key exchange groups: typically by calling [`ServerConfigBuilderWithSuites::with_safe_default_kx_groups()`].
/// 3. You now have a [`ServerConfigBuilderWithKxGroups`].  You must make
///    a decision on how and whether to use client authentication.  Perhaps
///    you call [`ServerConfigBuilderWithKxGroups::with_no_client_auth()`].
/// 4. You now have a [`ServerConfigBuilderWithClientAuth`].  You must
///    now provide server authentication credentials.  If you have just a single
///    key and certificate chain, you might call [`ServerConfigBuilderWithClientAuth::with_single_cert()`].
/// 5. You now have a [`ServerConfig`].  This object has a number
///    of defaults you can change.
///
/// # [`ServerConfig`] defaults
/// * [`ServerConfig::mtu`]: the default is `None`: TLS packets are not fragmented to fit in single IP packet.
/// * [`ServerConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ServerConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ServerConfig::versions`]: both TLS1.2 and TLS1.3 are supported.
/// * [`ServerConfig::key_log`]: key material is not logged.
pub struct ServerConfigBuilder {}

impl ServerConfigBuilder {
    /// Start building a [`ServerConfig`].
    pub fn new() -> ServerConfigBuilder {
        ServerConfigBuilder {}
    }

    /// Start building a [`ServerConfig`], and accept defaults for underlying
    /// cryptography.
    ///
    /// These are safe defaults, useful for 99% of applications.
    ///
    /// With the returned object, you must still make decisions on
    /// client authentication and provide server credentials -- rustls
    /// can't provide useful defaults for these.
    pub fn with_safe_default_crypto() -> ServerConfigBuilderWithKxGroups {
        ServerConfigBuilder::new()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
    }

    /// Choose a specific set of cipher suites.
    pub fn with_cipher_suites(
        self,
        cipher_suites: &[&'static SupportedCipherSuite],
    ) -> ServerConfigBuilderWithSuites {
        ServerConfigBuilderWithSuites {
            cipher_suites: cipher_suites.to_vec(),
        }
    }

    /// Choose the default set of cipher suites.
    ///
    /// Note that this default provides only high-quality suites: there is no need
    /// to filter out low-, export- or NULL-strength cipher suites: rustls does not
    /// implement these.
    pub fn with_safe_default_cipher_suites(self) -> ServerConfigBuilderWithSuites {
        self.with_cipher_suites(DEFAULT_CIPHERSUITES)
    }
}

/// A [`ServerConfigBuilder`] where we know the cipher suites.
pub struct ServerConfigBuilderWithSuites {
    cipher_suites: Vec<&'static SupportedCipherSuite>,
}

impl ServerConfigBuilderWithSuites {
    /// Choose a specific set of key exchange groups.
    pub fn with_kx_groups(
        self,
        kx_groups: &[&'static SupportedKxGroup],
    ) -> ServerConfigBuilderWithKxGroups {
        ServerConfigBuilderWithKxGroups {
            cipher_suites: self.cipher_suites,
            kx_groups: kx_groups.to_vec(),
        }
    }

    /// Choose the default set of key exchange groups.
    ///
    /// This is a safe default: rustls doesn't implement any poor-quality groups.
    pub fn with_safe_default_kx_groups(self) -> ServerConfigBuilderWithKxGroups {
        self.with_kx_groups(&ALL_KX_GROUPS)
    }
}

/// A [`ServerConfigBuilder`] where we know the cipher suites and key exchange
/// groups.
pub struct ServerConfigBuilderWithKxGroups {
    cipher_suites: Vec<&'static SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
}

/// Reduce typing for the most common case.
impl Default for ServerConfigBuilderWithKxGroups {
    fn default() -> Self {
        ServerConfigBuilder::with_safe_default_crypto()
    }
}

impl ServerConfigBuilderWithKxGroups {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn verify::ClientCertVerifier>,
    ) -> ServerConfigBuilderWithClientAuth {
        ServerConfigBuilderWithClientAuth {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            verifier: client_cert_verifier,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ServerConfigBuilderWithClientAuth {
        ServerConfigBuilderWithClientAuth {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            verifier: verify::NoClientAuth::new(),
        }
    }
}

/// A [`ServerConfigBuilder`] where we know the cipher suites, key exchange
/// groups, and client auth policy.
pub struct ServerConfigBuilderWithClientAuth {
    cipher_suites: Vec<&'static SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
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
            mtu: None,
            session_storage: handy::ServerSessionMemoryCache::new(256),
            ticketer: Arc::new(handy::NeverProducesTickets {}),
            alpn_protocols: Vec::new(),
            versions: versions::EnabledVersions::new(&[&versions::TLS12, &versions::TLS13]),
            key_log: Arc::new(NoKeyLog {}),
            #[cfg(feature = "quic")]
            max_early_data_size: 0,
        }
    }
}
