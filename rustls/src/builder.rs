use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::error::Error;
use crate::suites::SupportedCipherSuite;
use crate::versions;

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

/// A [builder] for [`ServerConfig`] or [`ClientConfig`] values.
///
/// To get one of these, call [`ServerConfig::builder()`] or [`ClientConfig::builder()`].
///
/// To build a config, you must make at least three decisions (in order):
///
/// - Which protocol primitives should be supported (cipher suites, key exchange groups, protocol versions)?
/// - How should this client or server verify certificates provided by its peer?
/// - What certificates should this client or server present to its peer?
///
/// For settings besides these, see the fields of [`ServerConfig`] and [`ClientConfig`].
///
/// The usual choice for protocol primitives is to call
/// [`ConfigBuilder::with_safe_defaults`], which will choose rustls' defaults for cipher suites, key
/// exchange groups and protocol versions:
///
/// ```
/// # #[cfg(feature = "ring")] {
/// use rustls::{ClientConfig, ServerConfig};
/// ClientConfig::builder()
///     .with_safe_defaults()
/// //  ...
/// # ;
///
/// ServerConfig::builder()
///     .with_safe_defaults()
/// //  ...
/// # ;
/// # }
/// ```
///
/// If you override the default for one protocol primitive (for instance supporting only TLS 1.3),
/// you will need to explicitly specify configuration for all three. That configuration may simply
/// be "use the default."
///
/// ```no_run
/// # #[cfg(feature = "ring")] {
/// # use rustls::ServerConfig;
/// ServerConfig::builder()
///     .with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .with_protocol_versions(&[&rustls::version::TLS13])
///     .unwrap()
/// //  ...
/// # ;
/// # }
/// ```
///
/// Overriding a default introduces a `Result` that must be unwrapped,
/// because the config builder checks for consistency of the choices made. For instance, it's an error to
/// configure only TLS 1.2 cipher suites while specifying that TLS 1.3 should be the only supported protocol
/// version.
///
/// If you configure a smaller set of protocol primitives than the default, you may get a smaller binary,
/// since the code for the unused ones can be optimized away at link time.
///
/// After choosing protocol primitives, you must choose (a) how to verify certificates and (b) what certificates
/// (if any) to send to the peer. The methods to do this are specific to whether you're building a ClientConfig
/// or a ServerConfig, as tracked by the [`ConfigSide`] type parameter on the various impls of ConfigBuilder.
///
/// # ClientConfig certificate configuration
///
/// For a client, _certificate verification_ must be configured either by calling one of:
///  - [`ConfigBuilder::with_root_certificates`] or
///  - [`ConfigBuilder::dangerous()`] and [`DangerousClientConfigBuilder::with_custom_certificate_verifier`]
///
/// Next, _certificate sending_ (also known as "client authentication", "mutual TLS", or "mTLS") must be configured
/// or disabled using one of:
/// - [`ConfigBuilder::with_no_client_auth`] - to not send client authentication (most common)
/// - [`ConfigBuilder::with_client_auth_cert`] - to always send a specific certificate
/// - [`ConfigBuilder::with_client_cert_resolver`] - to send a certificate chosen dynamically
///
/// For example:
///
/// ```
/// # #[cfg(feature = "ring")] {
/// # use rustls::ClientConfig;
/// # let root_certs = rustls::RootCertStore::empty();
/// ClientConfig::builder()
///     .with_safe_defaults()
///     .with_root_certificates(root_certs)
///     .with_no_client_auth();
/// # }
/// ```
///
/// # ServerConfig certificate configuration
///
/// For a server, _certificate verification_ must be configured by calling one of:
/// - [`ConfigBuilder::with_no_client_auth`] - to not require client authentication (most common)
/// - [`ConfigBuilder::with_client_cert_verifier`] - to use a custom verifier
///
/// Next, _certificate sending_ must be configured by calling one of:
/// - [`ConfigBuilder::with_single_cert`] - to send a specific certificate
/// - [`ConfigBuilder::with_single_cert_with_ocsp`] - to send a specific certificate, plus stapled OCSP
/// - [`ConfigBuilder::with_cert_resolver`] - to send a certificate chosen dynamically
///
/// For example:
///
/// ```no_run
/// # #[cfg(feature = "ring")] {
/// # use rustls::ServerConfig;
/// # let certs = vec![];
/// # let private_key = pki_types::PrivateKeyDer::from(
/// #    pki_types::PrivatePkcs8KeyDer::from(vec![])
/// # );
/// ServerConfig::builder()
///     .with_safe_defaults()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// # }
/// ```
///
/// # Types
///
/// ConfigBuilder uses the [typestate] pattern to ensure at compile time that each required
/// configuration item is provided exactly once. This is tracked in the `State` type parameter,
/// which can have these values:
///
/// - [`WantsCipherSuites`]
/// - [`WantsKxGroups`]
/// - [`WantsVersions`]
/// - [`WantsVerifier`]
/// - [`WantsClientCert`]
/// - [`WantsServerCert`]
///
/// The other type parameter is `Side`, which is either `ServerConfig` or `ClientConfig`
/// depending on whether the ConfigBuilder was built with [`ServerConfig::builder()`] or
/// [`ClientConfig::builder()`].
///
/// You won't need to write out either of these type parameters explicitly. If you write a
/// correct chain of configuration calls they will be used automatically. If you write an
/// incorrect chain of configuration calls you will get an error message from the compiler
/// mentioning some of these types.
///
/// Additionally, ServerConfig and ClientConfig carry a private field containing a
/// `&'static dyn `[`CryptoProvider`], from [`ClientConfig::builder_with_provider()`] or
/// [`ServerConfig::builder_with_provider()`]. This determines which cryptographic backend
/// is used. The default is [`RING`].
///
/// [builder]: https://rust-unofficial.github.io/patterns/patterns/creational/builder.html
/// [typestate]: http://cliffle.com/blog/rust-typestate/
/// [`ServerConfig`]: crate::ServerConfig
/// [`ServerConfig::builder`]: crate::ServerConfig::builder
/// [`ClientConfig`]: crate::ClientConfig
/// [`ClientConfig::builder()`]: crate::ClientConfig::builder()
/// [`ServerConfig::builder()`]: crate::ServerConfig::builder()
/// [`ClientConfig::builder_with_provider()`]: crate::ClientConfig::builder_with_provider()
/// [`ServerConfig::builder_with_provider()`]: crate::ServerConfig::builder_with_provider()
/// [`ConfigBuilder<ClientConfig, WantsVerifier>`]: struct.ConfigBuilder.html#impl-3
/// [`ConfigBuilder<ServerConfig, WantsVerifier>`]: struct.ConfigBuilder.html#impl-6
/// [`WantsClientCert`]: crate::client::WantsClientCert
/// [`WantsServerCert`]: crate::server::WantsServerCert
/// [`RING`]: crate::crypto::ring::RING
/// [`DangerousClientConfigBuilder::with_custom_certificate_verifier`]: crate::client::danger::DangerousClientConfigBuilder::with_custom_certificate_verifier
#[derive(Clone)]
pub struct ConfigBuilder<Side: ConfigSide, State> {
    pub(crate) state: State,
    pub(crate) side: PhantomData<Side>,
}

impl<Side: ConfigSide, State: fmt::Debug> fmt::Debug for ConfigBuilder<Side, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side_name = core::any::type_name::<Side>();
        let (ty, _) = side_name
            .split_once('<')
            .unwrap_or((side_name, ""));
        let (_, name) = ty.rsplit_once("::").unwrap_or(("", ty));

        f.debug_struct(&format!("ConfigBuilder<{}, _>", name,))
            .field("state", &self.state)
            .finish()
    }
}

/// Config builder state where the caller must supply cipher suites.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsCipherSuites(pub(crate) &'static dyn CryptoProvider);

impl<S: ConfigSide> ConfigBuilder<S, WantsCipherSuites> {
    /// Start side-specific config with defaults for underlying cryptography.
    ///
    /// If used, this will enable all safe supported cipher suites (`default_cipher_suites()` as specified by the
    /// `CryptoProvider` type), all safe supported key exchange groups ([`CryptoProvider::default_kx_groups()`]) and all safe supported
    /// protocol versions ([`DEFAULT_VERSIONS`]).
    ///
    /// These are safe defaults, useful for 99% of applications.
    ///
    /// [`DEFAULT_VERSIONS`]: versions::DEFAULT_VERSIONS
    pub fn with_safe_defaults(self) -> ConfigBuilder<S, WantsVerifier> {
        ConfigBuilder {
            state: WantsVerifier {
                cipher_suites: self
                    .state
                    .0
                    .default_cipher_suites()
                    .to_vec(),
                kx_groups: self
                    .state
                    .0
                    .default_kx_groups()
                    .to_vec(),
                provider: self.state.0,
                versions: versions::EnabledVersions::new(versions::DEFAULT_VERSIONS),
            },
            side: self.side,
        }
    }

    /// Choose a specific set of cipher suites.
    ///
    /// These can be different from the cipher suites implemented by the `CryptoProvider`.
    /// Because the cipher suites provided by `ring` and `aws_lc_rs` have the same names,
    /// make sure any `use` statements are importing from the provider that you want to use.
    pub fn with_cipher_suites(
        self,
        cipher_suites: &[SupportedCipherSuite],
    ) -> ConfigBuilder<S, WantsKxGroups> {
        ConfigBuilder {
            state: WantsKxGroups {
                cipher_suites: cipher_suites.to_vec(),
                provider: self.state.0,
            },
            side: self.side,
        }
    }

    /// Choose the default set of cipher suites as specified by the `CryptoProvider`.
    ///
    /// The intention is that this default provides only high-quality suites: there is no need
    /// to filter out low-, export- or NULL-strength cipher suites: rustls does not
    /// implement these.  But the precise details are controlled by what is implemented by the
    /// `CryptoProvider`.
    pub fn with_safe_default_cipher_suites(self) -> ConfigBuilder<S, WantsKxGroups> {
        let default = self.state.0.default_cipher_suites();
        self.with_cipher_suites(default)
    }
}

/// Config builder state where the caller must supply key exchange groups.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsKxGroups {
    cipher_suites: Vec<SupportedCipherSuite>,
    provider: &'static dyn CryptoProvider,
}

impl<S: ConfigSide> ConfigBuilder<S, WantsKxGroups> {
    /// Choose a specific set of key exchange groups.
    ///
    /// These can be different from the key exchange groups implemented by the `CryptoProvider`.
    /// Because the cipher suites provided by `ring` and `aws_lc_rs` have the same names,
    /// make sure any `use` statements are importing from the provider that you want to use.
    pub fn with_kx_groups(
        self,
        kx_groups: &[&'static dyn SupportedKxGroup],
    ) -> ConfigBuilder<S, WantsVersions> {
        ConfigBuilder {
            state: WantsVersions {
                cipher_suites: self.state.cipher_suites,
                kx_groups: kx_groups.to_vec(),
                provider: self.state.provider,
            },
            side: self.side,
        }
    }

    /// Choose the default set of key exchange groups ([`CryptoProvider::default_kx_groups`]).
    ///
    /// This is a safe default: rustls doesn't implement any poor-quality groups.
    pub fn with_safe_default_kx_groups(self) -> ConfigBuilder<S, WantsVersions> {
        let default = self.state.provider.default_kx_groups();
        self.with_kx_groups(default)
    }
}

/// Config builder state where the caller must supply TLS protocol versions.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsVersions {
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
    provider: &'static dyn CryptoProvider,
}

impl<S: ConfigSide> ConfigBuilder<S, WantsVersions> {
    /// Accept the default protocol versions: both TLS1.2 and TLS1.3 are enabled.
    pub fn with_safe_default_protocol_versions(
        self,
    ) -> Result<ConfigBuilder<S, WantsVerifier>, Error> {
        self.with_protocol_versions(versions::DEFAULT_VERSIONS)
    }

    /// Use a specific set of protocol versions.
    pub fn with_protocol_versions(
        self,
        versions: &[&'static versions::SupportedProtocolVersion],
    ) -> Result<ConfigBuilder<S, WantsVerifier>, Error> {
        let mut any_usable_suite = false;
        for suite in &self.state.cipher_suites {
            if versions.contains(&suite.version()) {
                any_usable_suite = true;
                break;
            }
        }

        if !any_usable_suite {
            return Err(Error::General("no usable cipher suites configured".into()));
        }

        if self.state.kx_groups.is_empty() {
            return Err(Error::General("no kx groups configured".into()));
        }

        Ok(ConfigBuilder {
            state: WantsVerifier {
                cipher_suites: self.state.cipher_suites,
                kx_groups: self.state.kx_groups,
                provider: self.state.provider,
                versions: versions::EnabledVersions::new(versions),
            },
            side: self.side,
        })
    }
}

/// Config builder state where the caller must supply a verifier.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsVerifier {
    pub(crate) cipher_suites: Vec<SupportedCipherSuite>,
    pub(crate) kx_groups: Vec<&'static dyn SupportedKxGroup>,
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) versions: versions::EnabledVersions,
}

/// Helper trait to abstract [`ConfigBuilder`] over building a [`ClientConfig`] or [`ServerConfig`].
///
/// [`ClientConfig`]: crate::ClientConfig
/// [`ServerConfig`]: crate::ServerConfig
pub trait ConfigSide: sealed::Sealed {}

impl ConfigSide for crate::ClientConfig {}
impl ConfigSide for crate::ServerConfig {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::ClientConfig {}
    impl Sealed for crate::ServerConfig {}
}
