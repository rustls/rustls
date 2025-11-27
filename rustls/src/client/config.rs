use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use pki_types::{PrivateKeyDer, ServerName, UnixTime};

use super::ech::EchMode;
#[cfg(feature = "std")]
use super::handy::ClientSessionMemoryCache;
use super::handy::{FailResolveClientCert, NoClientSessionStorage};
use crate::builder::{ConfigBuilder, WantsVerifier};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::kx::NamedGroup;
use crate::crypto::{
    CipherSuite, Credentials, CryptoProvider, Identity, SelectedCredential, SignatureScheme,
    SingleCredential,
};
use crate::enums::{CertificateType, ProtocolVersion};
use crate::error::{ApiMisuse, Error};
use crate::key_log::NoKeyLog;
use crate::msgs::persist;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
#[cfg(feature = "std")]
use crate::time_provider::DefaultTimeProvider;
use crate::time_provider::TimeProvider;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{DistinguishedName, KeyLog, compress, verify};

/// Common configuration for (typically) all connections made by a program.
///
/// Making one of these is cheap, though one of the inputs may be expensive: gathering trust roots
/// from the operating system to add to the [`RootCertStore`] passed to `with_root_certificates()`
/// (the rustls-native-certs crate is often used for this) may take on the order of a few hundred
/// milliseconds.
///
/// These must be created via the [`ClientConfig::builder()`] or [`ClientConfig::builder()`]
/// function.
///
/// Note that using [`ConfigBuilder<ClientConfig, WantsVersions>::with_ech()`] will produce a common
/// configuration specific to the provided [`crate::client::EchConfig`] that may not be appropriate
/// for all connections made by the program. In this case the configuration should only be shared
/// by connections intended for domains that offer the provided [`crate::client::EchConfig`] in
/// their DNS zone.
///
/// # Defaults
///
/// * [`ClientConfig::max_fragment_size`]: the default is `None` (meaning 16kB).
/// * [`ClientConfig::resumption`]: supports resumption with up to 256 server names, using session
///   ids or tickets, with a max of eight tickets per server.
/// * [`ClientConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ClientConfig::key_log`]: key material is not logged.
/// * [`ClientConfig::cert_decompressors`]: depends on the crate features, see [`compress::default_cert_decompressors()`].
/// * [`ClientConfig::cert_compressors`]: depends on the crate features, see [`compress::default_cert_compressors()`].
/// * [`ClientConfig::cert_compression_cache`]: caches the most recently used 4 compressions
///
/// [`RootCertStore`]: crate::RootCertStore
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How and when the client can resume a previous session.
    ///
    /// # Sharing `resumption` between `ClientConfig`s
    /// In a program using many `ClientConfig`s it may improve resumption rates
    /// (which has a significant impact on connection performance) if those
    /// configs share a single `Resumption`.
    ///
    /// However, resumption is only allowed between two `ClientConfig`s if their
    /// `client_auth_cert_resolver` (ie, potential client authentication credentials)
    /// and `verifier` (ie, server certificate verification settings) are
    /// the same (according to `Arc::ptr_eq`).
    ///
    /// To illustrate, imagine two `ClientConfig`s `A` and `B`.  `A` fully validates
    /// the server certificate, `B` does not.  If `A` and `B` shared a resumption store,
    /// it would be possible for a session originated by `B` to be inserted into the
    /// store, and then resumed by `A`.  This would give a false impression to the user
    /// of `A` that the server certificate is fully validated.
    pub resumption: Resumption,

    /// The maximum size of plaintext input to be emitted in a single TLS record.
    /// A value of None is equivalent to the [TLS maximum] of 16 kB.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from [ClientConnection::new].
    ///
    /// Setting this value to a little less than the TCP MSS may improve latency
    /// for stream-y workloads.
    ///
    /// [TLS maximum]: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    /// [ClientConnection::new]: crate::client::ClientConnection::new
    pub max_fragment_size: Option<usize>,

    /// Whether to send the Server Name Indication (SNI) extension
    /// during the client handshake.
    ///
    /// The default is true.
    pub enable_sni: bool,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Allows traffic secrets to be extracted after the handshake,
    /// e.g. for kTLS setup.
    pub enable_secret_extraction: bool,

    /// Whether to send data on the first flight ("early data") in
    /// TLS 1.3 handshakes.
    ///
    /// The default is false.
    pub enable_early_data: bool,

    /// If set to `true`, requires the server to support the extended
    /// master secret extraction method defined in [RFC 7627].
    ///
    /// The default is `true` if the `fips` crate feature is enabled,
    /// `false` otherwise.
    ///
    /// It must be set to `true` to meet FIPS requirement mentioned in section
    /// **D.Q Transition of the TLS 1.2 KDF to Support the Extended Master
    /// Secret** from [FIPS 140-3 IG.pdf].
    ///
    /// [RFC 7627]: https://datatracker.ietf.org/doc/html/rfc7627
    /// [FIPS 140-3 IG.pdf]: https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
    pub require_ems: bool,

    /// Provides the current system time
    pub time_provider: Arc<dyn TimeProvider>,

    /// Source of randomness and other crypto.
    pub(crate) provider: Arc<CryptoProvider>,

    /// How to verify the server certificate chain.
    pub(super) verifier: Arc<dyn verify::ServerVerifier>,

    /// How to decide what client auth certificate/keys to use.
    pub(super) client_auth_cert_resolver: Arc<dyn ClientCredentialResolver>,

    /// How to decompress the server's certificate chain.
    ///
    /// If this is non-empty, the [RFC8779] certificate compression
    /// extension is offered, and any compressed certificates are
    /// transparently decompressed during the handshake.
    ///
    /// This only applies to TLS1.3 connections.  It is ignored for
    /// TLS1.2 connections.
    ///
    /// [RFC8779]: https://datatracker.ietf.org/doc/rfc8879/
    pub cert_decompressors: Vec<&'static dyn compress::CertDecompressor>,

    /// How to compress the client's certificate chain.
    ///
    /// If a server supports this extension, and advertises support
    /// for one of the compression algorithms included here, the
    /// client certificate will be compressed according to [RFC8779].
    ///
    /// This only applies to TLS1.3 connections.  It is ignored for
    /// TLS1.2 connections.
    ///
    /// [RFC8779]: https://datatracker.ietf.org/doc/rfc8879/
    pub cert_compressors: Vec<&'static dyn compress::CertCompressor>,

    /// Caching for compressed certificates.
    ///
    /// This is optional: [`compress::CompressionCache::Disabled`] gives
    /// a cache that does no caching.
    pub cert_compression_cache: Arc<compress::CompressionCache>,

    /// How to offer Encrypted Client Hello (ECH). The default is to not offer ECH.
    pub(super) ech_mode: Option<EchMode>,
}

impl ClientConfig {
    /// Create a builder for a client configuration with a specific [`CryptoProvider`].
    ///
    /// This will use the provider's configured ciphersuites.
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    #[cfg(feature = "std")]
    pub fn builder(provider: Arc<CryptoProvider>) -> ConfigBuilder<Self, WantsVerifier> {
        Self::builder_with_details(provider, Arc::new(DefaultTimeProvider))
    }

    /// Create a builder for a client configuration with no default implementation details.
    ///
    /// This API must be used by `no_std` users.
    ///
    /// You must provide a specific [`TimeProvider`].
    ///
    /// You must provide a specific [`CryptoProvider`].
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    pub fn builder_with_details(
        provider: Arc<CryptoProvider>,
        time_provider: Arc<dyn TimeProvider>,
    ) -> ConfigBuilder<Self, WantsVerifier> {
        ConfigBuilder {
            state: WantsVerifier {
                client_ech_mode: None,
            },
            provider,
            time_provider,
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig<'_> {
        danger::DangerousClientConfig { cfg: self }
    }

    /// Return true if connections made with this `ClientConfig` will
    /// operate in FIPS mode.
    ///
    /// This is different from [`CryptoProvider::fips()`]: [`CryptoProvider::fips()`]
    /// is concerned only with cryptography, whereas this _also_ covers TLS-level
    /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
    pub fn fips(&self) -> bool {
        let mut is_fips = self.provider.fips() && self.require_ems;

        if let Some(ech_mode) = &self.ech_mode {
            is_fips = is_fips && ech_mode.fips();
        }

        is_fips
    }

    /// Return the crypto provider used to construct this client configuration.
    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }

    /// Return the resolver for this client configuration.
    ///
    /// This is the object that determines which credentials to use for client
    /// authentication.
    pub fn resolver(&self) -> &Arc<dyn ClientCredentialResolver> {
        &self.client_auth_cert_resolver
    }

    /// Return the resolver for this client configuration.
    ///
    /// This is the object that determines which credentials to use for client
    /// authentication.
    pub fn verifier(&self) -> &Arc<dyn verify::ServerVerifier> {
        &self.verifier
    }

    pub(super) fn needs_key_share(&self) -> bool {
        self.supports_version(ProtocolVersion::TLSv1_3)
    }

    pub(crate) fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.provider.supports_version(v)
    }

    pub(super) fn find_cipher_suite(&self, suite: CipherSuite) -> Option<SupportedCipherSuite> {
        self.provider
            .iter_cipher_suites()
            .find(|&scs| scs.suite() == suite)
    }

    pub(super) fn current_time(&self) -> Result<UnixTime, Error> {
        self.time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)
    }
}

/// A trait for the ability to store client session data, so that sessions
/// can be resumed in future connections.
///
/// Generally all data in this interface should be treated as
/// **highly sensitive**, containing enough key material to break all security
/// of the corresponding session.
///
/// `set_`, `insert_`, `remove_` and `take_` operations are mutating; this isn't
/// expressed in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common choice.
pub trait ClientSessionStore: fmt::Debug + Send + Sync {
    /// Remember what `NamedGroup` the given server chose.
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup);

    /// This should return the value most recently passed to `set_kx_hint`
    /// for the given `server_name`.
    ///
    /// If `None` is returned, the caller chooses the first configured group,
    /// and an extra round trip might happen if that choice is unsatisfactory
    /// to the server.
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup>;

    /// Remember a TLS1.2 session.
    ///
    /// At most one of these can be remembered at a time, per `server_name`.
    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: persist::Tls12ClientSessionValue,
    );

    /// Get the most recently saved TLS1.2 session for `server_name` provided to `set_tls12_session`.
    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<persist::Tls12ClientSessionValue>;

    /// Remove and forget any saved TLS1.2 session for `server_name`.
    fn remove_tls12_session(&self, server_name: &ServerName<'static>);

    /// Remember a TLS1.3 ticket that might be retrieved later from `take_tls13_ticket`, allowing
    /// resumption of this session.
    ///
    /// This can be called multiple times for a given session, allowing multiple independent tickets
    /// to be valid at once.  The number of times this is called is controlled by the server, so
    /// implementations of this trait should apply a reasonable bound of how many items are stored
    /// simultaneously.
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: persist::Tls13ClientSessionValue,
    );

    /// Return a TLS1.3 ticket previously provided to `add_tls13_ticket`.
    ///
    /// Implementations of this trait must return each value provided to `add_tls13_ticket` _at most once_.
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<persist::Tls13ClientSessionValue>;
}

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ClientCredentialResolver: fmt::Debug + Send + Sync {
    /// Resolve a client certificate chain/private key to use as the client's identity.
    ///
    /// The `SelectedCredential` returned from this method contains an identity and a
    /// one-time-use [`Signer`] wrapping the private key. This is usually obtained via a
    /// [`Credentials`], on which an implementation can call [`Credentials::signer()`].
    /// An implementation can either store long-lived [`Credentials`] values, or instantiate
    /// them as needed using one of its constructors.
    ///
    /// Return `None` to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    ///
    /// [RFC 5280 A.1]: https://www.rfc-editor.org/rfc/rfc5280#appendix-A.1
    ///
    /// [`Credentials`]: crate::crypto::Credentials
    /// [`Credentials::signer()`]: crate::crypto::Credentials::signer
    /// [`Signer`]: crate::crypto::Signer
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential>;

    /// Returns which [`CertificateType`]s this resolver supports.
    ///
    /// Should return the empty slice if the resolver does not have any credentials to send.
    /// Implementations should return the same value every time.
    ///
    /// See [RFC 7250](https://tools.ietf.org/html/rfc7250) for more information.
    fn supported_certificate_types(&self) -> &'static [CertificateType];
}

/// Context from the server to inform client credential selection.
pub struct CredentialRequest<'a> {
    pub(super) negotiated_type: CertificateType,
    pub(super) root_hint_subjects: &'a [DistinguishedName],
    pub(super) signature_schemes: &'a [SignatureScheme],
}

impl CredentialRequest<'_> {
    /// List of certificate authority subject distinguished names provided by the server.
    ///
    /// If the list is empty, the client should send whatever certificate it has. The hints
    /// are expected to be DER-encoded X.500 distinguished names, per [RFC 5280 A.1]. Note that
    /// the encoding comes from the server and has not been validated by rustls.
    ///
    /// See [`DistinguishedName`] for more information on decoding with external crates like
    /// `x509-parser`.
    ///
    /// [`DistinguishedName`]: crate::DistinguishedName
    pub fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.root_hint_subjects
    }

    /// Get the compatible signature schemes.
    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    /// The negotiated certificate type.
    ///
    /// If the server does not support [RFC 7250], this will be `CertificateType::X509`.
    ///
    /// [RFC 7250]: https://tools.ietf.org/html/rfc7250
    pub fn negotiated_type(&self) -> CertificateType {
        self.negotiated_type
    }
}

/// Configuration for how/when a client is allowed to resume a previous session.
#[derive(Clone, Debug)]
pub struct Resumption {
    /// How we store session data or tickets. The default is to use an in-memory
    /// [super::handy::ClientSessionMemoryCache].
    pub(super) store: Arc<dyn ClientSessionStore>,

    /// What mechanism is used for resuming a TLS 1.2 session.
    pub(super) tls12_resumption: Tls12Resumption,
}

impl Resumption {
    /// Create a new `Resumption` that stores data for the given number of sessions in memory.
    ///
    /// This is the default `Resumption` choice, and enables resuming a TLS 1.2 session with
    /// a session id or RFC 5077 ticket.
    #[cfg(feature = "std")]
    pub fn in_memory_sessions(num: usize) -> Self {
        Self {
            store: Arc::new(ClientSessionMemoryCache::new(num)),
            tls12_resumption: Tls12Resumption::SessionIdOrTickets,
        }
    }

    /// Use a custom [`ClientSessionStore`] implementation to store sessions.
    ///
    /// By default, enables resuming a TLS 1.2 session with a session id or RFC 5077 ticket.
    pub fn store(store: Arc<dyn ClientSessionStore>) -> Self {
        Self {
            store,
            tls12_resumption: Tls12Resumption::SessionIdOrTickets,
        }
    }

    /// Disable all use of session resumption.
    pub fn disabled() -> Self {
        Self {
            store: Arc::new(NoClientSessionStorage),
            tls12_resumption: Tls12Resumption::Disabled,
        }
    }

    /// Configure whether TLS 1.2 sessions may be resumed, and by what mechanism.
    ///
    /// This is meaningless if you've disabled resumption entirely, which is the case in `no-std`
    /// contexts.
    pub fn tls12_resumption(mut self, tls12: Tls12Resumption) -> Self {
        self.tls12_resumption = tls12;
        self
    }
}

impl Default for Resumption {
    /// Create an in-memory session store resumption with up to 256 server names, allowing
    /// a TLS 1.2 session to resume with a session id or RFC 5077 ticket.
    fn default() -> Self {
        #[cfg(feature = "std")]
        let ret = Self::in_memory_sessions(256);

        #[cfg(not(feature = "std"))]
        let ret = Self::disabled();

        ret
    }
}

/// What mechanisms to support for resuming a TLS 1.2 session.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tls12Resumption {
    /// Disable 1.2 resumption.
    Disabled,
    /// Support 1.2 resumption using session ids only.
    SessionIdOnly,
    /// Support 1.2 resumption using session ids or RFC 5077 tickets.
    ///
    /// See[^1] for why you might like to disable RFC 5077 by instead choosing the `SessionIdOnly`
    /// option. Note that TLS 1.3 tickets do not have those issues.
    ///
    /// [^1]: <https://words.filippo.io/we-need-to-talk-about-session-tickets/>
    SessionIdOrTickets,
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                verifier,
                client_ech_mode: self.state.client_ech_mode,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This requires TLS 1.3 as the only supported protocol version to meet the requirement
    /// to support ECH.  At the end, the config building process will return an error if either
    /// TLS1.3 _is not_ supported by the provider, or TLS1.2 _is_ supported.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(mut self, mode: EchMode) -> Self {
        self.state.client_ech_mode = Some(mode);
        self
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    verifier: Arc<dyn verify::ServerVerifier>,
    client_ech_mode: Option<EchMode>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        identity: Arc<Identity<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let credentials = Credentials::from_der(identity, key_der, &self.provider)?;
        self.with_client_credential_resolver(Arc::new(SingleCredential::from(credentials)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> Result<ClientConfig, Error> {
        self.with_client_credential_resolver(Arc::new(FailResolveClientCert {}))
    }

    /// Sets a custom [`ClientCredentialResolver`].
    pub fn with_client_credential_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ClientCredentialResolver>,
    ) -> Result<ClientConfig, Error> {
        self.provider.consistency_check()?;

        if self.state.client_ech_mode.is_some() {
            match (
                self.provider
                    .tls12_cipher_suites
                    .is_empty(),
                self.provider
                    .tls13_cipher_suites
                    .is_empty(),
            ) {
                (_, true) => return Err(ApiMisuse::EchRequiresTls13Support.into()),
                (false, _) => return Err(ApiMisuse::EchForbidsTls12Support.into()),
                (true, false) => {}
            };
        }

        Ok(ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
        })
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::client::config::ClientConfig;
    use crate::sync::Arc;
    use crate::verify::ServerVerifier;
    use crate::{ConfigBuilder, WantsVerifier};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfig<'a> {
        /// The underlying ClientConfig
        pub(super) cfg: &'a mut ClientConfig,
    }

    impl DangerousClientConfig<'_> {
        /// Overrides the default `ServerVerifier` with something else.
        pub fn set_certificate_verifier(&mut self, verifier: Arc<dyn ServerVerifier>) {
            self.cfg.verifier = verifier;
        }
    }

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub(super) cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn ServerVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}
