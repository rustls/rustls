use alloc::format;
use core::fmt;
use core::marker::PhantomData;

use crate::client::EchMode;
use crate::crypto::CryptoProvider;
use crate::sync::Arc;
use crate::time_provider::TimeProvider;
#[cfg(doc)]
use crate::{ClientConfig, ServerConfig};

/// A [builder] for [`ServerConfig`] or [`ClientConfig`] values.
///
/// To get one of these, call [`ServerConfig::builder()`] or [`ClientConfig::builder()`].
///
/// To build a config, you must make at least three decisions (in order):
///
/// - What crypto provider do you want to use?
/// - How should this client or server verify certificates provided by its peer?
/// - What certificates should this client or server present to its peer?
///
/// For settings besides these, see the fields of [`ServerConfig`] and [`ClientConfig`].
///
/// The rustls project recommends the crypto provider based on aws-lc-rs for production use.
/// This can be selected by passing in [`crate::crypto::aws_lc_rs::DEFAULT_PROVIDER`],
/// which includes safe defaults for cipher suites and protocol versions.
///
/// ```
/// # #[cfg(feature = "aws-lc-rs")] {
/// # use std::sync::Arc;
/// use rustls::{ClientConfig, ServerConfig};
/// use rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER;
/// ClientConfig::builder(Arc::new(DEFAULT_PROVIDER))
/// //  ...
/// # ;
///
/// ServerConfig::builder(Arc::new(DEFAULT_PROVIDER))
/// //  ...
/// # ;
/// # }
/// ```
///
/// After choosing the `CryptoProvider`, you must choose (a) how to verify certificates and (b) what certificates
/// (if any) to send to the peer. The methods to do this are specific to whether you're building a ClientConfig
/// or a ServerConfig, as tracked by the [`ConfigSide`] type parameter on the various impls of ConfigBuilder.
///
/// A `Result<ClientConfig, Error>` or `Result<ServerConfig, Error>` is the outcome of the builder process.
/// The error is used to report consistency problems with the configuration. For example, it's an error
/// to have a `CryptoProvider` that has no cipher suites.
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
/// - [`ConfigBuilder::with_server_credential_resolver`] - to send a certificate chosen dynamically
///
/// For example:
///
/// ```
/// # #[cfg(feature = "aws-lc-rs")] {
/// # use std::sync::Arc;
/// # use rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER;
/// # use rustls::ClientConfig;
/// # let root_certs = rustls::RootCertStore::empty();
/// ClientConfig::builder(Arc::new(DEFAULT_PROVIDER))
///     .with_root_certificates(root_certs)
///     .with_no_client_auth()
///     .unwrap();
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
/// - [`ConfigBuilder::with_server_credential_resolver`] - to send a certificate chosen dynamically
///
/// For example:
///
/// ```no_run
/// # #[cfg(feature = "aws-lc-rs")] {
/// # use std::sync::Arc;
/// # use rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER;
/// # use rustls::crypto::Identity;
/// # use rustls::ServerConfig;
/// # let certs = vec![];
/// # let private_key = pki_types::PrivateKeyDer::from(
/// #    pki_types::PrivatePkcs8KeyDer::from(vec![])
/// # );
/// ServerConfig::builder(Arc::new(DEFAULT_PROVIDER))
///     .with_no_client_auth()
///     .with_single_cert(Arc::new(Identity::from_cert_chain(certs).unwrap()), private_key)
///     .expect("bad certificate/key/provider");
/// # }
/// ```
///
/// # Types
///
/// ConfigBuilder uses the [typestate] pattern to ensure at compile time that each required
/// configuration item is provided exactly once. This is tracked in the `State` type parameter,
/// which can have these values:
///
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
/// [`CryptoProvider`], from [`ClientConfig::builder()`] or
/// [`ServerConfig::builder()`]. This determines which cryptographic backend
/// is used.
///
/// [builder]: https://rust-unofficial.github.io/patterns/patterns/creational/builder.html
/// [typestate]: http://cliffle.com/blog/rust-typestate/
/// [`ServerConfig`]: crate::ServerConfig
/// [`ServerConfig::builder`]: crate::ServerConfig::builder
/// [`ClientConfig`]: crate::ClientConfig
/// [`ClientConfig::builder()`]: crate::ClientConfig::builder()
/// [`ServerConfig::builder()`]: crate::ServerConfig::builder()
/// [`ClientConfig::builder()`]: crate::ClientConfig::builder()
/// [`ServerConfig::builder()`]: crate::ServerConfig::builder()
/// [`ConfigBuilder<ClientConfig, WantsVerifier>`]: struct.ConfigBuilder.html#impl-3
/// [`ConfigBuilder<ServerConfig, WantsVerifier>`]: struct.ConfigBuilder.html#impl-6
/// [`WantsClientCert`]: crate::client::WantsClientCert
/// [`WantsServerCert`]: crate::server::WantsServerCert
/// [`CryptoProvider::get_default`]: crate::crypto::CryptoProvider::get_default
/// [`DangerousClientConfigBuilder::with_custom_certificate_verifier`]: crate::client::danger::DangerousClientConfigBuilder::with_custom_certificate_verifier
#[derive(Clone)]
pub struct ConfigBuilder<Side: ConfigSide, State> {
    pub(crate) state: State,
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) time_provider: Arc<dyn TimeProvider>,
    pub(crate) side: PhantomData<Side>,
}

impl<Side: ConfigSide, State> ConfigBuilder<Side, State> {
    /// Return the crypto provider used to construct this builder.
    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }
}

impl<Side: ConfigSide, State: fmt::Debug> fmt::Debug for ConfigBuilder<Side, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side_name = core::any::type_name::<Side>();
        let (ty, _) = side_name
            .split_once('<')
            .unwrap_or((side_name, ""));
        let (_, name) = ty.rsplit_once("::").unwrap_or(("", ty));

        f.debug_struct(&format!("ConfigBuilder<{name}, _>",))
            .field("state", &self.state)
            .finish()
    }
}

/// Config builder state where the caller must supply a verifier.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsVerifier {
    pub(crate) client_ech_mode: Option<EchMode>,
}

/// Helper trait to abstract [`ConfigBuilder`] over building a [`ClientConfig`] or [`ServerConfig`].
///
/// [`ClientConfig`]: crate::ClientConfig
/// [`ServerConfig`]: crate::ServerConfig
pub trait ConfigSide: crate::sealed::Sealed {}

impl ConfigSide for crate::ClientConfig {}
impl ConfigSide for crate::ServerConfig {}

impl crate::sealed::Sealed for crate::ClientConfig {}
impl crate::sealed::Sealed for crate::ServerConfig {}
