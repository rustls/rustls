use crate::error::Error;
use crate::kx::{SupportedKxGroup, ALL_KX_GROUPS};
use crate::suites::{SupportedCipherSuite, DEFAULT_CIPHERSUITES};
use crate::versions;

use std::marker::PhantomData;

/// Building a [`ServerConfig`] or [`ClientConfig`] in a linker-friendly way.
///
/// Linker-friendly: meaning unused cipher suites, protocol
/// versions, key exchange mechanisms, etc. can be discarded
/// by the linker as they'll be unreferenced.
///
/// Example, to make a [`ServerConfig`]:
///
/// ```no_run
/// # use rustls::ServerConfig;
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ServerConfig::builder()
///     .with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_safe_default_protocol_versions()
///     .unwrap()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// This may be shortened to:
///
/// ```no_run
/// # use rustls::ServerConfig;
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ServerConfig::builder()
///     .with_safe_defaults()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// To make a [`ClientConfig`]:
///
/// ```no_run
/// # use rustls::ClientConfig;
/// # let root_certs = rustls::RootCertStore::empty();
/// # let trusted_ct_logs = &[];
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ClientConfig::builder()
///     .with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_safe_default_protocol_versions()
///     .unwrap()
///     .with_root_certificates(root_certs, trusted_ct_logs)
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// This may be shortened to:
///
/// ```
/// # use rustls::ClientConfig;
/// # let root_certs = rustls::RootCertStore::empty();
/// # let trusted_ct_logs = &[];
/// ClientConfig::builder()
///     .with_safe_defaults()
///     .with_root_certificates(root_certs, trusted_ct_logs)
///     .with_no_client_auth();
/// ```
///
///
/// The types used here fit together like this:
///
/// 1. Call [`ClientConfig::builder()`] or [`ServerConfig::builder()`] to initialize a builder.
/// 1. You must make a decision on which cipher suites to use, typically
///    by calling [`ConfigWantsCipherSuites::with_safe_default_cipher_suites()`].
/// 2. Now you must make a decision
///    on key exchange groups: typically by calling [`ConfigWantsKxGroups::with_safe_default_kx_groups()`].
/// 3. Now you must make
///    a decision on which protocol versions to support, typically by calling
///    [`ConfigWantsVersions::with_safe_default_protocol_versions()`].
/// 5. Now see [`ConfigWantsServerVerifier`] or [`ConfigWantsClientVerifier`] for further steps.
///
/// [`ServerConfig`]: crate::ServerConfig
/// [`ClientConfig`]: crate::ClientConfig
/// [`ClientConfig::builder()`]: crate::ClientConfig::builder()
/// [`ServerConfig::builder()`]: crate::ServerConfig::builder()
/// [`ConfigWantsServerVerifier`]: crate::ConfigWantsServerVerifier
/// [`ConfigWantsClientVerifier`]: crate::ConfigWantsClientVerifier

/// A config builder where we want to know the cipher suites.
pub struct ConfigWantsCipherSuites<S: ConfigSide>(pub(crate) PhantomData<S>);

impl<S: ConfigSide> ConfigWantsCipherSuites<S> {
    /// Start side-specific config with defaults for underlying cryptography.
    ///
    /// These are safe defaults, useful for 99% of applications.
    pub fn with_safe_defaults(&self) -> S::Builder {
        S::Builder::validated(
            DEFAULT_CIPHERSUITES.to_vec(),
            ALL_KX_GROUPS.to_vec(),
            versions::DEFAULT_VERSIONS,
        )
    }

    /// Choose a specific set of cipher suites.
    pub fn with_cipher_suites(
        &self,
        cipher_suites: &[SupportedCipherSuite],
    ) -> ConfigWantsKxGroups<S> {
        ConfigWantsKxGroups {
            cipher_suites: cipher_suites.to_vec(),
            side: PhantomData::default(),
        }
    }

    /// Choose the default set of cipher suites.
    ///
    /// Note that this default provides only high-quality suites: there is no need
    /// to filter out low-, export- or NULL-strength cipher suites: rustls does not
    /// implement these.
    pub fn with_safe_default_cipher_suites(&self) -> ConfigWantsKxGroups<S> {
        self.with_cipher_suites(DEFAULT_CIPHERSUITES)
    }
}

/// A config builder where we want to know which key exchange groups to use.
pub struct ConfigWantsKxGroups<S: ConfigSide> {
    cipher_suites: Vec<SupportedCipherSuite>,
    side: PhantomData<S>,
}

impl<S: ConfigSide> ConfigWantsKxGroups<S> {
    /// Choose a specific set of key exchange groups.
    pub fn with_kx_groups(self, kx_groups: &[&'static SupportedKxGroup]) -> ConfigWantsVersions<S> {
        ConfigWantsVersions {
            cipher_suites: self.cipher_suites,
            kx_groups: kx_groups.to_vec(),
            side: PhantomData::default(),
        }
    }

    /// Choose the default set of key exchange groups.
    ///
    /// This is a safe default: rustls doesn't implement any poor-quality groups.
    pub fn with_safe_default_kx_groups(self) -> ConfigWantsVersions<S> {
        self.with_kx_groups(&ALL_KX_GROUPS)
    }
}

/// A config builder where we want to know the TLS versions.
pub struct ConfigWantsVersions<S: ConfigSide> {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    side: PhantomData<S>,
}

impl<S: ConfigSide> ConfigWantsVersions<S> {
    /// Accept the default protocol versions: both TLS1.2 and TLS1.3 are enabled.
    pub fn with_safe_default_protocol_versions(self) -> Result<S::Builder, Error> {
        self.with_protocol_versions(versions::DEFAULT_VERSIONS)
    }

    /// Use a specific set of protocol versions.
    pub fn with_protocol_versions(
        self,
        versions: &[&'static versions::SupportedProtocolVersion],
    ) -> Result<S::Builder, Error> {
        let mut any_usable_suite = false;
        for suite in &self.cipher_suites {
            if versions.contains(&suite.version()) {
                any_usable_suite = true;
                break;
            }
        }

        if !any_usable_suite {
            return Err(Error::General("no usable cipher suites configured".into()));
        }

        if self.kx_groups.is_empty() {
            return Err(Error::General("no kx groups configured".into()));
        }

        Ok(S::Builder::validated(
            self.cipher_suites,
            self.kx_groups,
            versions,
        ))
    }
}

/// Helper trait to abstract config builders over building a [`ClientConfig`] or [`ServerConfig`].
///
/// [`ClientConfig`]: crate::ClientConfig
/// [`ServerConfig`]: crate::ServerConfig
pub trait ConfigSide: sealed::Sealed {
    /// Refer to side-specific builder type
    type Builder: BuilderSide;
}

#[allow(unreachable_pub)]
pub trait BuilderSide: sealed::Sealed + Sized {
    fn validated(
        cipher_suites: Vec<SupportedCipherSuite>,
        kx_groups: Vec<&'static SupportedKxGroup>,
        versions: &[&'static versions::SupportedProtocolVersion],
    ) -> Self;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::ClientConfig {}
    impl Sealed for crate::ServerConfig {}
    impl Sealed for crate::ConfigWantsClientVerifier {}
    impl Sealed for crate::ConfigWantsServerVerifier {}
}
