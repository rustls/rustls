use crate::client::builder::ClientConfigBuilder;
use crate::error::Error;
use crate::kx::{SupportedKxGroup, ALL_KX_GROUPS};
use crate::server::builder::ServerConfigBuilder;
use crate::suites::{SupportedCipherSuite, DEFAULT_CIPHERSUITES};
use crate::versions;

/// Building a [`ServerConfig`] or [`ClientConfig`] in a linker-friendly way.
///
/// Linker-friendly: meaning unused cipher suites, protocol
/// versions, key exchange mechanisms, etc. can be discarded
/// by the linker as they'll be unreferenced.
///
/// Example, to make a [`ServerConfig`]:
///
/// ```
/// # use rustls::ConfigBuilder;
/// ConfigBuilder::with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_safe_default_protocol_versions()
///     .for_server()
///     .unwrap();
/// ```
///
/// This may be shortened to:
///
/// ```
/// # use rustls::ConfigBuilder;
/// ConfigBuilder::with_safe_defaults()
///     .for_server()
///     .unwrap();
/// ```
///
/// The types used here fit together like this:
///
/// 1. You must make a decision on which cipher suites to use, typically
///    by calling [`ConfigBuilder::with_safe_default_cipher_suites()`].
/// 2. You now have a [`ConfigBuilderWithSuites`].  You must make a decision
///    on key exchange groups: typically by calling [`ConfigBuilderWithSuites::with_safe_default_kx_groups()`].
/// 3. You now have a [`ConfigBuilderWithKxGroups`].  You must make
///    a decision on which protocol versions to support, typically by calling
///    [`ConfigBuilderWithKxGroups::with_safe_default_protocol_versions()`].
/// 4. You now have a [`ConfigBuilderWithVersions`] and need to decide whether to
///    make a [`ServerConfig`] or [`ClientConfig`] -- call [`ConfigBuilderWithVersions::for_server()`]
///    or [`ConfigBuilderWithVersions::for_client()`] respectively.
/// 5. Now see [`ServerConfigBuilder`] or [`ClientConfigBuilder`] for further steps.
///
/// [`ServerConfig`]: crate::ServerConfig
/// [`ClientConfig`]: crate::ClientConfig
pub struct ConfigBuilder;

impl ConfigBuilder {
    /// Start building a [`ServerConfig`] or [`ClientConfig`], and accept
    /// defaults for underlying cryptography.
    ///
    /// These are safe defaults, useful for 99% of applications.
    ///
    /// [`ServerConfig`]: crate::ServerConfig
    /// [`ClientConfig`]: crate::ClientConfig
    pub fn with_safe_defaults() -> ConfigBuilderWithVersions {
        ConfigBuilder::with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
    }

    /// Choose a specific set of cipher suites.
    pub fn with_cipher_suites(cipher_suites: &[SupportedCipherSuite]) -> ConfigBuilderWithSuites {
        ConfigBuilderWithSuites {
            cipher_suites: cipher_suites.to_vec(),
        }
    }

    /// Choose the default set of cipher suites.
    ///
    /// Note that this default provides only high-quality suites: there is no need
    /// to filter out low-, export- or NULL-strength cipher suites: rustls does not
    /// implement these.
    pub fn with_safe_default_cipher_suites() -> ConfigBuilderWithSuites {
        Self::with_cipher_suites(DEFAULT_CIPHERSUITES)
    }
}

/// A [`ConfigBuilder`] where we know the cipher suites.
pub struct ConfigBuilderWithSuites {
    cipher_suites: Vec<SupportedCipherSuite>,
}

impl ConfigBuilderWithSuites {
    /// Choose a specific set of key exchange groups.
    pub fn with_kx_groups(
        self,
        kx_groups: &[&'static SupportedKxGroup],
    ) -> ConfigBuilderWithKxGroups {
        ConfigBuilderWithKxGroups {
            cipher_suites: self.cipher_suites,
            kx_groups: kx_groups.to_vec(),
        }
    }

    /// Choose the default set of key exchange groups.
    ///
    /// This is a safe default: rustls doesn't implement any poor-quality groups.
    pub fn with_safe_default_kx_groups(self) -> ConfigBuilderWithKxGroups {
        self.with_kx_groups(&ALL_KX_GROUPS)
    }
}

/// A [`ConfigBuilder`] where we know the cipher suites and key exchange
/// groups.
pub struct ConfigBuilderWithKxGroups {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
}

impl ConfigBuilderWithKxGroups {
    /// Accept the default protocol versions: both TLS1.2 and TLS1.3 are enabled.
    pub fn with_safe_default_protocol_versions(self) -> ConfigBuilderWithVersions {
        self.with_protocol_versions(versions::DEFAULT_VERSIONS)
    }

    /// Use a specific set of protocol versions.
    pub fn with_protocol_versions(
        self,
        versions: &[&'static versions::SupportedProtocolVersion],
    ) -> ConfigBuilderWithVersions {
        ConfigBuilderWithVersions {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: versions::EnabledVersions::new(versions),
        }
    }
}

/// A [`ConfigBuilder`] where we know the cipher suites, key exchange groups,
/// and protocol versions.
pub struct ConfigBuilderWithVersions {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    versions: versions::EnabledVersions,
}

impl ConfigBuilderWithVersions {
    fn validate(&self) -> Result<(), Error> {
        let mut any_usable_suite = false;
        for suite in &self.cipher_suites {
            if self
                .versions
                .contains(suite.version().version)
            {
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

        Ok(())
    }

    /// Continue building a `ClientConfig`.
    ///
    /// This may fail, if the previous selections are contradictory or
    /// not useful (for example, if no protocol versions are enabled).
    pub fn for_client(self) -> Result<ClientConfigBuilder, Error> {
        self.validate()?;
        Ok(ClientConfigBuilder {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
        })
    }

    /// Continue building a `ServerConfig`.
    ///
    /// This may fail, if the previous selections are contradictory or
    /// not useful (for example, if no protocol versions are enabled).
    pub fn for_server(self) -> Result<ServerConfigBuilder, Error> {
        self.validate()?;
        Ok(ServerConfigBuilder {
            cipher_suites: self.cipher_suites,
            kx_groups: self.kx_groups,
            versions: self.versions,
        })
    }
}
