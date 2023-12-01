use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::versions;

use alloc::format;
use core::fmt;
use core::marker::PhantomData;
use std::sync::Arc;

#[cfg(doc)]
use crate::{ClientConfig, ServerConfig};

/// A [builder] for [`ServerConfig`] or [`ClientConfig`] values.
///
/// To get one of these, call [`ServerConfig::builder()`] or [`ClientConfig::builder()`].
///
/// To build a config, you must make at least two decisions (in order):
///
/// - How should this client or server verify certificates provided by its peer?
/// - What certificates should this client or server present to its peer?
///
/// For settings besides these, see the fields of [`ServerConfig`] and [`ClientConfig`].
///
/// The usual choice for protocol primitives is to call
/// [`ClientConfig::builder`]/[`ServerConfig::builder`]
/// which will use rustls' default cryptographic provider and safe defaults for ciphersuites and
/// supported protocol versions.
///
/// ```
/// # #[cfg(feature = "ring")] {
/// use rustls::{ClientConfig, ServerConfig};
/// ClientConfig::builder()
/// //  ...
/// # ;
///
/// ServerConfig::builder()
/// //  ...
/// # ;
/// # }
/// ```
///
/// You may also override the choice of protocol versions:
///
/// ```no_run
/// # #[cfg(feature = "ring")] {
/// # use rustls::ServerConfig;
/// ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
/// //  ...
/// # ;
/// # }
/// ```
///
/// Overriding the default cryptographic provider introduces a `Result` that must be unwrapped,
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
/// [`CryptoProvider`], from [`ClientConfig::builder_with_provider()`] or
/// [`ServerConfig::builder_with_provider()`]. This determines which cryptographic backend
/// is used. The default is [`ring::provider`].
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
/// [`ring::provider`]: crate::crypto::ring::default_provider
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

/// Config builder state where the caller must supply TLS protocol versions.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsVersions {
    pub(crate) provider: Arc<CryptoProvider>,
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
        for suite in &self.state.provider.cipher_suites {
            if versions.contains(&suite.version()) {
                any_usable_suite = true;
                break;
            }
        }

        if !any_usable_suite {
            return Err(Error::General("no usable cipher suites configured".into()));
        }

        if self.state.provider.kx_groups.is_empty() {
            return Err(Error::General("no kx groups configured".into()));
        }

        Ok(ConfigBuilder {
            state: WantsVerifier {
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
    pub(crate) provider: Arc<CryptoProvider>,
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
