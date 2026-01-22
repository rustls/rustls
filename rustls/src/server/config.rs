use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use pki_types::{DnsName, FipsStatus, PrivateKeyDer, UnixTime};

use super::handy;
use super::hs::ClientHelloInput;
use crate::builder::{ConfigBuilder, WantsVerifier};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::kx::NamedGroup;
use crate::crypto::{
    CipherSuite, Credentials, CryptoProvider, Identity, SelectedCredential, SignatureScheme,
    SingleCredential, TicketProducer,
};
use crate::enums::{ApplicationProtocol, CertificateType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::ServerNamePayload;
use crate::sync::Arc;
#[cfg(feature = "std")]
use crate::time_provider::DefaultTimeProvider;
use crate::time_provider::TimeProvider;
use crate::verify::{ClientVerifier, DistinguishedName, NoClientAuth};
use crate::{KeyLog, NoKeyLog, compress};

/// Common configuration for a set of server sessions.
///
/// Making one of these is cheap, though one of the inputs may be expensive: gathering trust roots
/// from the operating system to add to the [`RootCertStore`] passed to a `ClientVerifier`
/// builder may take on the order of a few hundred milliseconds.
///
/// These must be created via the [`ServerConfig::builder()`] or [`ServerConfig::builder()`]
/// function.
///
/// # Defaults
///
/// * [`ServerConfig::max_fragment_size`]: the default is `None` (meaning 16kB).
/// * [`ServerConfig::session_storage`]: if the `std` feature is enabled, the default stores 256
///   sessions in memory. If the `std` feature is not enabled, the default is to not store any
///   sessions. In a no-std context, by enabling the `hashbrown` feature you may provide your
///   own `session_storage` using [`ServerSessionMemoryCache`] and a `crate::lock::MakeMutex`
///   implementation.
/// * [`ServerConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ServerConfig::key_log`]: key material is not logged.
/// * [`ServerConfig::send_tls13_tickets`]: 2 tickets are sent.
/// * [`ServerConfig::cert_compressors`]: depends on the crate features, see [`compress::default_cert_compressors()`].
/// * [`ServerConfig::cert_compression_cache`]: caches the most recently used 4 compressions
/// * [`ServerConfig::cert_decompressors`]: depends on the crate features, see [`compress::default_cert_decompressors()`].
///
/// # Sharing resumption storage between `ServerConfig`s
///
/// In a program using many `ServerConfig`s it may improve resumption rates
/// (which has a significant impact on connection performance) if those
/// configs share [`ServerConfig::session_storage`] or [`ServerConfig::ticketer`].
///
/// However, caution is needed: other fields influence the security of a session
/// and resumption between them can be surprising.  If sharing
/// [`ServerConfig::session_storage`] or [`ServerConfig::ticketer`] between two
/// `ServerConfig`s, you should also evaluate the following fields and ensure
/// they are equivalent:
///
/// * `ServerConfig::verifier` -- client authentication requirements,
/// * [`ServerConfig::cert_resolver`] -- server identities.
///
/// To illustrate, imagine two `ServerConfig`s `A` and `B`.  `A` requires
/// client authentication, `B` does not.  If `A` and `B` shared a resumption store,
/// it would be possible for a session originated by `B` (that is, an unauthenticated client)
/// to be inserted into the store, and then resumed by `A`.  This would give a false
/// impression to the user of `A` that the client was authenticated.  This is possible
/// whether the resumption is performed statefully (via [`ServerConfig::session_storage`])
/// or statelessly (via [`ServerConfig::ticketer`]).
///
/// _Unlike_ `ClientConfig`, rustls does not enforce any policy here.
///
/// [`RootCertStore`]: crate::RootCertStore
/// [`ServerSessionMemoryCache`]: crate::server::handy::ServerSessionMemoryCache
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Source of randomness and other crypto.
    pub(crate) provider: Arc<CryptoProvider>,

    /// Ignore the client's ciphersuite order. Instead,
    /// choose the top ciphersuite in the server list
    /// which is supported by the client.
    pub ignore_client_order: bool,

    /// The maximum size of plaintext input to be emitted in a single TLS record.
    /// A value of None is equivalent to the [TLS maximum] of 16 kB.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from [ServerConnection::new].
    ///
    /// Setting this value to a little less than the TCP MSS may improve latency
    /// for stream-y workloads.
    ///
    /// [TLS maximum]: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    /// [ServerConnection::new]: crate::server::ServerConnection::new
    pub max_fragment_size: Option<usize>,

    /// How to store client sessions.
    ///
    /// See [ServerConfig#sharing-resumption-storage-between-serverconfigs]
    /// for a warning related to this field.
    pub session_storage: Arc<dyn StoresServerSessions>,

    /// How to produce tickets.
    ///
    /// See [ServerConfig#sharing-resumption-storage-between-serverconfigs]
    /// for a warning related to this field.
    pub ticketer: Option<Arc<dyn TicketProducer>>,

    /// How to choose a server cert and key. This is usually set by
    /// [ConfigBuilder::with_single_cert] or [ConfigBuilder::with_server_credential_resolver].
    /// For async applications, see also [`Acceptor`][super::Acceptor].
    pub cert_resolver: Arc<dyn ServerCredentialResolver>,

    /// Protocol names we support, most preferred first.
    /// If empty we don't do ALPN at all.
    pub alpn_protocols: Vec<ApplicationProtocol<'static>>,

    /// How to verify client certificates.
    pub(super) verifier: Arc<dyn ClientVerifier>,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Allows traffic secrets to be extracted after the handshake,
    /// e.g. for kTLS setup.
    pub enable_secret_extraction: bool,

    /// Amount of early data to accept for sessions created by
    /// this config.  Specify 0 to disable early data.  The
    /// default is 0.
    ///
    /// Read the early data via
    /// [`ServerConnection::early_data()`][super::ServerConnection::early_data()].
    ///
    /// The units for this are _both_ plaintext bytes, _and_ ciphertext
    /// bytes, depending on whether the server accepts a client's early_data
    /// or not.  It is therefore recommended to include some slop in
    /// this value to account for the unknown amount of ciphertext
    /// expansion in the latter case.
    pub max_early_data_size: u32,

    /// Whether the server should send "0.5RTT" data.  This means the server
    /// sends data after its first flight of handshake messages, without
    /// waiting for the client to complete the handshake.
    ///
    /// This can improve TTFB latency for either server-speaks-first protocols,
    /// or client-speaks-first protocols when paired with "0RTT" data.  This
    /// comes at the cost of a subtle weakening of the normal handshake
    /// integrity guarantees that TLS provides.  Note that the initial
    /// `ClientHello` is indirectly authenticated because it is included
    /// in the transcript used to derive the keys used to encrypt the data.
    ///
    /// This only applies to TLS1.3 connections.  TLS1.2 connections cannot
    /// do this optimisation and this setting is ignored for them.  It is
    /// also ignored for TLS1.3 connections that even attempt client
    /// authentication.
    ///
    /// This defaults to false.  This means the first application data
    /// sent by the server comes after receiving and validating the client's
    /// handshake up to the `Finished` message.  This is the safest option.
    pub send_half_rtt_data: bool,

    /// How many TLS1.3 tickets to send immediately after a successful
    /// handshake.
    ///
    /// Because TLS1.3 tickets are single-use, this allows
    /// a client to perform multiple resumptions.
    ///
    /// The default is 2.
    ///
    /// If this is 0, no tickets are sent and clients will not be able to
    /// do any resumption.
    pub send_tls13_tickets: usize,

    /// If set to `true`, requires the client to support the extended
    /// master secret extraction method defined in [RFC 7627].
    ///
    /// The default is `true` if the configured [`CryptoProvider`] is FIPS-compliant,
    /// false otherwise.
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

    /// How to compress the server's certificate chain.
    ///
    /// If a client supports this extension, and advertises support
    /// for one of the compression algorithms included here, the
    /// server certificate will be compressed according to [RFC8779].
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

    /// How to decompress the clients's certificate chain.
    ///
    /// If this is non-empty, the [RFC8779] certificate compression
    /// extension is offered when requesting client authentication,
    /// and any compressed certificates are transparently decompressed
    /// during the handshake.
    ///
    /// This only applies to TLS1.3 connections.  It is ignored for
    /// TLS1.2 connections.
    ///
    /// [RFC8779]: https://datatracker.ietf.org/doc/rfc8879/
    pub cert_decompressors: Vec<&'static dyn compress::CertDecompressor>,

    /// Policy for how an invalid Server Name Indication (SNI) value from a client is handled.
    pub invalid_sni_policy: InvalidSniPolicy,
}

impl ServerConfig {
    /// Create a builder for a server configuration with a specific [`CryptoProvider`].
    ///
    /// This will use the provider's configured ciphersuites.  This implies which TLS
    /// protocol versions are enabled.
    ///
    /// This function always succeeds.  Any internal consistency problems with `provider`
    /// are reported at the end of the builder process.
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    #[cfg(feature = "std")]
    pub fn builder(provider: Arc<CryptoProvider>) -> ConfigBuilder<Self, WantsVerifier> {
        Self::builder_with_details(provider, Arc::new(DefaultTimeProvider))
    }

    /// Create a builder for a server configuration with no default implementation details.
    ///
    /// This API must be used by `no_std` users.
    ///
    /// You must provide a specific [`TimeProvider`].
    ///
    /// You must provide a specific [`CryptoProvider`].
    ///
    /// This will use the provider's configured ciphersuites.  This implies which TLS
    /// protocol versions are enabled.
    ///
    /// This function always succeeds.  Any internal consistency problems with `provider`
    /// are reported at the end of the builder process.
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

    /// Return the FIPS validation status for connections made with this configuration.
    ///
    /// This is different from [`CryptoProvider::fips()`]: [`CryptoProvider::fips()`]
    /// is concerned only with cryptography, whereas this _also_ covers TLS-level
    /// configuration that NIST recommends.
    pub fn fips(&self) -> FipsStatus {
        match self.require_ems {
            true => self.provider.fips(),
            false => FipsStatus::Unvalidated,
        }
    }

    /// Return the crypto provider used to construct this client configuration.
    pub fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }

    pub(crate) fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.provider.supports_version(v)
    }

    pub(super) fn current_time(&self) -> Result<UnixTime, Error> {
        self.time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)
    }
}

/// A trait for the ability to store server session data.
///
/// The keys and values are opaque.
///
/// Inserted keys are randomly chosen by the library and have
/// no internal structure (in other words, you may rely on all
/// bits being uniformly random).  Queried keys are untrusted data.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding sessions.
///
/// Implementations can be lossy (in other words, forgetting
/// key/value pairs) without any negative security consequences.
///
/// However, note that `take` **must** reliably delete a returned
/// value.  If it does not, there may be security consequences.
///
/// `put` and `take` are mutating operations; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresServerSessions: Debug + Send + Sync {
    /// Store session secrets encoded in `value` against `key`,
    /// overwrites any existing value against `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Find a value with the given `key`.  Return it, or None
    /// if it doesn't exist.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Find a value with the given `key`.  Return it and delete it;
    /// or None if it doesn't exist.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Whether the store can cache another session. This is used to indicate to clients
    /// whether their session can be resumed; the implementation is not required to remember
    /// a session even if it returns `true` here.
    fn can_cache(&self) -> bool;
}

/// How to choose a certificate chain and signing key for use
/// in server authentication.
///
/// This is suitable when selecting a certificate does not require
/// I/O or when the application is using blocking I/O anyhow.
///
/// For applications that use async I/O and need to do I/O to choose
/// a certificate (for instance, fetching a certificate from a data store),
/// the [`Acceptor`][super::Acceptor] interface is more suitable.
pub trait ServerCredentialResolver: Debug + Send + Sync {
    /// Choose a certificate chain and matching key given simplified ClientHello information.
    ///
    /// The `SelectedCredential` returned from this method contains an identity and a
    /// one-time-use [`Signer`] wrapping the private key. This is usually obtained via a
    /// [`Credentials`], on which an implementation can call [`Credentials::signer()`].
    /// An implementation can either store long-lived [`Credentials`] values, or instantiate
    /// them as needed using one of its constructors.
    ///
    /// Yielding an `Error` will abort the handshake. Some relevant error variants:
    ///
    /// * [`PeerIncompatible::NoSignatureSchemesInCommon`]
    /// * [`PeerIncompatible::NoServerNameProvided`]
    /// * [`Error::NoSuitableCertificate`]
    ///
    /// [`Credentials`]: crate::crypto::Credentials
    /// [`Credentials::signer()`]: crate::crypto::Credentials::signer
    /// [`Signer`]: crate::crypto::Signer
    /// [`PeerIncompatible::NoSignatureSchemesInCommon`]: crate::error::PeerIncompatible::NoSignatureSchemesInCommon
    /// [`PeerIncompatible::NoServerNameProvided`]: crate::error::PeerIncompatible::NoServerNameProvided
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error>;

    /// Returns which [`CertificateType`]s this resolver supports.
    ///
    /// Returning an empty slice will result in an error. The default implementation signals
    /// support for X.509 certificates. Implementations should return the same value every time.
    ///
    /// See [RFC 7250](https://tools.ietf.org/html/rfc7250) for more information.
    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }
}

/// A struct representing the received Client Hello
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub(super) server_name: Option<Cow<'a, DnsName<'a>>>,
    pub(super) signature_schemes: &'a [SignatureScheme],
    pub(super) alpn: Option<&'a Vec<ApplicationProtocol<'a>>>,
    pub(super) server_cert_types: Option<&'a [CertificateType]>,
    pub(super) client_cert_types: Option<&'a [CertificateType]>,
    pub(super) cipher_suites: &'a [CipherSuite],
    /// The [certificate_authorities] extension, if it was sent by the client.
    ///
    /// [certificate_authorities]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    pub(super) certificate_authorities: Option<&'a [DistinguishedName]>,
    pub(super) named_groups: Option<&'a [NamedGroup]>,
}

impl<'a> ClientHello<'a> {
    pub(super) fn new(
        input: &'a ClientHelloInput<'a>,
        sni: Option<&'a DnsName<'static>>,
        version: ProtocolVersion,
    ) -> Self {
        Self {
            server_name: sni.map(Cow::Borrowed),
            signature_schemes: &input.sig_schemes,
            alpn: input.client_hello.protocols.as_ref(),
            server_cert_types: input
                .client_hello
                .server_certificate_types
                .as_deref(),
            client_cert_types: input
                .client_hello
                .client_certificate_types
                .as_deref(),
            cipher_suites: &input.client_hello.cipher_suites,
            // We adhere to the TLS 1.2 RFC by not exposing this to the cert resolver if TLS version is 1.2
            certificate_authorities: match version {
                ProtocolVersion::TLSv1_2 => None,
                _ => input
                    .client_hello
                    .certificate_authority_names
                    .as_deref(),
            },
            named_groups: input
                .client_hello
                .named_groups
                .as_deref(),
        }
    }

    /// Get the server name indicator.
    ///
    /// Returns `None` if the client did not supply a SNI.
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        self.server_name.as_deref()
    }

    /// Get the compatible signature schemes.
    ///
    /// Returns standard-specified default if the client omitted this extension.
    pub fn signature_schemes(&self) -> &[SignatureScheme] {
        self.signature_schemes
    }

    /// Get the ALPN protocol identifiers submitted by the client.
    ///
    /// Returns `None` if the client did not include an ALPN extension.
    ///
    /// Application Layer Protocol Negotiation (ALPN) is a TLS extension that lets a client
    /// submit a set of identifiers that each a represent an application-layer protocol.
    /// The server will then pick its preferred protocol from the set submitted by the client.
    /// Each identifier is represented as a byte array, although common values are often ASCII-encoded.
    /// See the official RFC-7301 specifications at <https://datatracker.ietf.org/doc/html/rfc7301>
    /// for more information on ALPN.
    ///
    /// For example, a HTTP client might specify "http/1.1" and/or "h2". Other well-known values
    /// are listed in the at IANA registry at
    /// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
    ///
    /// The server can specify supported ALPN protocols by setting [`ServerConfig::alpn_protocols`].
    /// During the handshake, the server will select the first protocol configured that the client supports.
    pub fn alpn(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        self.alpn.map(|protocols| {
            protocols
                .iter()
                .map(|proto| proto.as_ref())
        })
    }

    /// Get cipher suites.
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        self.cipher_suites
    }

    /// Get the server certificate types offered in the ClientHello.
    ///
    /// Returns `None` if the client did not include a certificate type extension.
    pub fn server_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.server_cert_types
    }

    /// Get the client certificate types offered in the ClientHello.
    ///
    /// Returns `None` if the client did not include a certificate type extension.
    pub fn client_cert_types(&self) -> Option<&'a [CertificateType]> {
        self.client_cert_types
    }

    /// Get the [certificate_authorities] extension sent by the client.
    ///
    /// Returns `None` if the client did not send this extension.
    ///
    /// [certificate_authorities]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
    pub fn certificate_authorities(&self) -> Option<&'a [DistinguishedName]> {
        self.certificate_authorities
    }

    /// Get the [`named_groups`] extension sent by the client.
    ///
    /// This means different things in different versions of TLS:
    ///
    /// Originally it was introduced as the "[`elliptic_curves`]" extension for TLS1.2.
    /// It described the elliptic curves supported by a client for all purposes: key
    /// exchange, signature verification (for server authentication), and signing (for
    /// client auth).  Later [RFC7919] extended this to include FFDHE "named groups",
    /// but FFDHE groups in this context only relate to key exchange.
    ///
    /// In TLS1.3 it was renamed to "[`named_groups`]" and now describes all types
    /// of key exchange mechanisms, and does not relate at all to elliptic curves
    /// used for signatures.
    ///
    /// [`elliptic_curves`]: https://datatracker.ietf.org/doc/html/rfc4492#section-5.1.1
    /// [RFC7919]: https://datatracker.ietf.org/doc/html/rfc7919#section-2
    /// [`named_groups`]:https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
    pub fn named_groups(&self) -> Option<&'a [NamedGroup]> {
        self.named_groups
    }
}

/// A policy describing how an invalid Server Name Indication (SNI) value from a client is handled by the server.
///
/// The only valid form of SNI according to relevant RFCs ([RFC6066], [RFC1035]) is
/// non-IP-address host name, however some misconfigured clients may send a bare IP address, or
/// another invalid value. Some servers may wish to ignore these invalid values instead of producing
/// an error.
///
/// By default, Rustls will ignore invalid values that are an IP address (the most common misconfiguration)
/// and error for all other invalid values.
///
/// When an SNI value is ignored, Rustls treats the client as if it sent no SNI at all.
///
/// [RFC1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1
/// [RFC6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum InvalidSniPolicy {
    /// Reject all ClientHello messages that contain an invalid SNI value.
    RejectAll,
    /// Ignore an invalid SNI value in ClientHello messages if the value is an IP address.
    ///
    /// "Ignoring SNI" means accepting the ClientHello message, but acting as if the client sent no SNI.
    #[default]
    IgnoreIpAddresses,
    /// Ignore all invalid SNI in ClientHello messages.
    ///
    /// "Ignoring SNI" means accepting the ClientHello message, but acting as if the client sent no SNI.
    IgnoreAll,
}

impl InvalidSniPolicy {
    /// Returns the valid SNI value, or ignores the invalid SNI value if allowed by this policy; otherwise returns
    /// an error.
    pub(super) fn accept(
        &self,
        payload: Option<&ServerNamePayload<'_>>,
    ) -> Result<Option<DnsName<'static>>, Error> {
        let Some(payload) = payload else {
            return Ok(None);
        };
        if let Some(server_name) = payload.to_dns_name_normalized() {
            return Ok(Some(server_name));
        }
        match (self, payload) {
            (Self::IgnoreAll, _) => Ok(None),
            (Self::IgnoreIpAddresses, ServerNamePayload::IpAddress) => Ok(None),
            _ => Err(Error::PeerMisbehaved(
                PeerMisbehaved::ServerNameMustContainOneHostName,
            )),
        }
    }
}

impl ConfigBuilder<ServerConfig, WantsVerifier> {
    /// Choose how to verify client certificates.
    pub fn with_client_cert_verifier(
        self,
        client_cert_verifier: Arc<dyn ClientVerifier>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ConfigBuilder {
            state: WantsServerCert {
                verifier: client_cert_verifier,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Disable client authentication.
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        self.with_client_cert_verifier(Arc::new(NoClientAuth))
    }
}

/// A config builder state where the caller must supply how to provide a server certificate to
/// the connecting peer.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone, Debug)]
pub struct WantsServerCert {
    verifier: Arc<dyn ClientVerifier>,
}

impl ConfigBuilder<ServerConfig, WantsServerCert> {
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
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support
    /// all three encodings, but other `CryptoProvider`s may not.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert(
        self,
        identity: Arc<Identity<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let credentials = Credentials::from_der(identity, key_der, self.crypto_provider())?;
        self.with_server_credential_resolver(Arc::new(SingleCredential::from(credentials)))
    }

    /// Sets a single certificate chain, matching private key and optional OCSP
    /// response.  This certificate and key is used for all
    /// subsequent connections, irrespective of things like SNI hostname.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support
    /// all three encodings, but other `CryptoProvider`s may not.
    /// `ocsp` is a DER-encoded OCSP response.  Ignored if zero length.
    ///
    /// This function fails if `key_der` is invalid, or if the
    /// `SubjectPublicKeyInfo` from the private key does not match the public
    /// key for the end-entity certificate from the `cert_chain`.
    pub fn with_single_cert_with_ocsp(
        self,
        identity: Arc<Identity<'static>>,
        key_der: PrivateKeyDer<'static>,
        ocsp: Arc<[u8]>,
    ) -> Result<ServerConfig, Error> {
        let mut credentials = Credentials::from_der(identity, key_der, self.crypto_provider())?;
        if !ocsp.is_empty() {
            credentials.ocsp = Some(ocsp);
        }
        self.with_server_credential_resolver(Arc::new(SingleCredential::from(credentials)))
    }

    /// Sets a custom [`ServerCredentialResolver`].
    pub fn with_server_credential_resolver(
        self,
        cert_resolver: Arc<dyn ServerCredentialResolver>,
    ) -> Result<ServerConfig, Error> {
        self.provider.consistency_check()?;
        let require_ems = !matches!(self.provider.fips(), FipsStatus::Unvalidated);
        Ok(ServerConfig {
            provider: self.provider,
            ignore_client_order: false,
            max_fragment_size: None,
            #[cfg(feature = "std")]
            session_storage: handy::ServerSessionMemoryCache::new(256),
            #[cfg(not(feature = "std"))]
            session_storage: Arc::new(handy::NoServerSessionStorage {}),
            ticketer: None,
            cert_resolver,
            alpn_protocols: Vec::new(),
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            max_early_data_size: 0,
            send_half_rtt_data: false,
            send_tls13_tickets: 2,
            require_ems,
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            invalid_sni_policy: InvalidSniPolicy::default(),
        })
    }
}
