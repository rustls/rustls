use crate::sign::SigningKey;
use crate::suites;
use crate::{Error, NamedGroup};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::PrivateKeyDer;
use zeroize::Zeroize;

#[cfg(all(doc, feature = "tls12"))]
use crate::Tls12CipherSuite;
#[cfg(doc)]
use crate::{
    client, crypto, server, sign, ClientConfig, ConfigBuilder, ServerConfig, SupportedCipherSuite,
    Tls13CipherSuite,
};

pub use crate::webpki::{
    verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
};

/// *ring* based CryptoProvider.
#[cfg(feature = "ring")]
pub mod ring;

/// aws-lc-rs-based CryptoProvider.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs;

/// TLS message encryption/decryption interfaces.
pub mod cipher;

/// Hashing interfaces.
pub mod hash;

/// HMAC interfaces.
pub mod hmac;

/// Cryptography specific to TLS1.2.
pub mod tls12;

/// Cryptography specific to TLS1.3.
pub mod tls13;

/// Hybrid public key encryption (RFC 9180).
#[doc(hidden)]
pub mod hpke;

// Message signing interfaces. Re-exported under rustls::sign. Kept crate-internal here to
// avoid having two import paths to the same types.
pub(crate) mod signer;

pub use crate::rand::GetRandomFailed;

pub use crate::suites::CipherSuiteCommon;

pub use crate::msgs::handshake::KeyExchangeAlgorithm;

/// Controls core cryptography used by rustls.
///
/// This crate comes with two built-in options, provided as
/// `CryptoProvider` structures:
///
/// - [`crypto::ring::default_provider`]: (behind the `ring` crate feature, which
///   is enabled by default).  This provider uses the [*ring*](https://github.com/briansmith/ring)
///   crate.
/// - [`crypto::aws_lc_rs::default_provider`]: (behind the `aws_lc_rs` feature,
///   which is optional).  This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs)
///   crate.  The `fips` crate feature makes this option use FIPS140-3-approved cryptography.
///
/// This structure provides defaults. Everything in it can be overridden at
/// runtime by replacing field values as needed.
///
/// # Using a specific `CryptoProvider`
///
/// Supply the provider when constructing your [`ClientConfig`] or [`ServerConfig`]:
///
/// - [`ClientConfig::builder_with_provider()`]
/// - [`ServerConfig::builder_with_provider()`]
///
/// When creating and configuring a webpki-backed client or server certificate verifier, a choice of
/// provider is also needed to start the configuration process:
///
/// - [`client::WebPkiServerVerifier::builder_with_provider()`]
/// - [`server::WebPkiClientVerifier::builder_with_provider()`]
///
/// # Making a custom `CryptoProvider`
///
/// Your goal will be to populate a [`crypto::CryptoProvider`] struct instance.
///
/// ## Which elements are required?
///
/// There is no requirement that the individual elements (`SupportedCipherSuite`, `SupportedKxGroup`,
/// `SigningKey`, etc.) come from the same crate.  It is allowed and expected that uninteresting
/// elements would be delegated back to one of the default providers (statically) or a parent
/// provider (dynamically).
///
/// For example, if we want to make a provider that just overrides key loading in the config builder
/// API ([`ConfigBuilder::with_single_cert`] etc.), it might look like this:
///
/// ```
/// # #[cfg(feature = "ring")] {
/// # use std::sync::Arc;
/// # mod fictious_hsm_api { pub fn load_private_key(key_der: pki_types::PrivateKeyDer<'static>) -> ! { unreachable!(); } }
/// use rustls::crypto::ring;
///
/// pub fn provider() -> rustls::crypto::CryptoProvider {
///   rustls::crypto::CryptoProvider{
///     key_provider: &HsmKeyLoader,
///     ..ring::default_provider()
///   }
/// }
///
/// #[derive(Debug)]
/// struct HsmKeyLoader;
///
/// impl rustls::crypto::KeyProvider for HsmKeyLoader {
///     fn load_private_key(&self, key_der: pki_types::PrivateKeyDer<'static>) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
///          fictious_hsm_api::load_private_key(key_der)
///     }
/// }
/// # }
/// ```
///
/// ## References to the individual elements
///
/// The elements are documented separately:
///
/// - **Random** - see [`crypto::SecureRandom::fill()`].
/// - **Cipher suites** - see [`SupportedCipherSuite`], [`Tls12CipherSuite`], and
///   [`Tls13CipherSuite`].
/// - **Key exchange groups** - see [`crypto::SupportedKxGroup`].
/// - **Signature verification algorithms** - see [`crypto::WebPkiSupportedAlgorithms`].
/// - **Authentication key loading** - see [`crypto::KeyProvider::load_private_key()`] and
///   [`sign::SigningKey`].
///
/// # Example code
///
/// See [provider-example/] for a full client and server example that uses
/// cryptography from the [rust-crypto] and [dalek-cryptography] projects.
///
/// ```shell
/// $ cargo run --example client | head -3
/// Current ciphersuite: TLS13_CHACHA20_POLY1305_SHA256
/// HTTP/1.1 200 OK
/// Content-Type: text/html; charset=utf-8
/// Content-Length: 19899
/// ```
///
/// [provider-example/]: https://github.com/rustls/rustls/tree/main/provider-example/
/// [rust-crypto]: https://github.com/rustcrypto
/// [dalek-cryptography]: https://github.com/dalek-cryptography
///
/// # FIPS-approved cryptography
/// The `fips` crate feature enables use of the `aws-lc-rs` crate in FIPS mode.
///
/// You can verify the configuration at runtime by checking
/// [`ServerConfig::fips()`]/[`ClientConfig::fips()`] return `true`.
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// List of supported ciphersuites, in preference order -- the first element
    /// is the highest priority.
    ///
    /// The `SupportedCipherSuite` type carries both configuration and implementation.
    pub cipher_suites: Vec<suites::SupportedCipherSuite>,

    /// List of supported key exchange groups, in preference order -- the
    /// first element is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    ///
    /// The `SupportedKxGroup` type carries both configuration and implementation.
    pub kx_groups: Vec<&'static dyn SupportedKxGroup>,

    /// List of signature verification algorithms for use with webpki.
    ///
    /// These are used for both certificate chain verification and handshake signature verification.
    ///
    /// This is called by [`ConfigBuilder::with_root_certificates()`],
    /// [`server::WebPkiClientVerifier::builder_with_provider()`] and
    /// [`client::WebPkiServerVerifier::builder_with_provider()`].
    pub signature_verification_algorithms: WebPkiSupportedAlgorithms,

    /// Source of cryptographically secure random numbers.
    pub secure_random: &'static dyn SecureRandom,

    /// Provider for loading private [SigningKey]s from [PrivateKeyDer].
    pub key_provider: &'static dyn KeyProvider,
}

impl CryptoProvider {
    /// Returns `true` if this `CryptoProvider` is operating in FIPS mode.
    ///
    /// This covers only the cryptographic parts of FIPS approval.  There are
    /// also TLS protocol-level recommendations made by NIST.  You should
    /// prefer to call [`ClientConfig::fips()`] or [`ServerConfig::fips()`]
    /// which take these into account.
    pub fn fips(&self) -> bool {
        let Self {
            cipher_suites,
            kx_groups,
            signature_verification_algorithms,
            secure_random,
            key_provider,
        } = self;
        cipher_suites.iter().all(|cs| cs.fips())
            && kx_groups.iter().all(|kx| kx.fips())
            && signature_verification_algorithms.fips()
            && secure_random.fips()
            && key_provider.fips()
    }
}

/// A source of cryptographically secure randomness.
pub trait SecureRandom: Send + Sync + Debug {
    /// Fill the given buffer with random bytes.
    ///
    /// The bytes must be sourced from a cryptographically secure random number
    /// generator seeded with good quality, secret entropy.
    ///
    /// This is used for all randomness required by rustls, but not necessarily
    /// randomness required by the underlying cryptography library.  For example:
    /// [`SupportedKxGroup::start()`] requires random material to generate
    /// an ephemeral key exchange key, but this is not included in the interface with
    /// rustls: it is assumed that the cryptography library provides for this itself.
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// A mechanism for loading private [SigningKey]s from [PrivateKeyDer].
///
/// This trait is intended to be used with private key material that is sourced from DER,
/// such as a private-key that may be present on-disk. It is not intended to be used with
/// keys held in hardware security modules (HSMs) or physical tokens. For these use-cases
/// see the Rustls manual section on [customizing private key usage].
///
/// [customizing private key usage]: <https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#customising-private-key-usage>
pub trait KeyProvider: Send + Sync + Debug {
    /// Decode and validate a private signing key from `key_der`.
    ///
    /// This is used by [`ConfigBuilder::with_client_auth_cert()`], [`ConfigBuilder::with_single_cert()`],
    /// and [`ConfigBuilder::with_single_cert_with_ocsp()`].  The key types and formats supported by this
    /// function directly defines the key types and formats supported in those APIs.
    ///
    /// Return an error if the key type encoding is not supported, or if the key fails validation.
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    ///
    /// If this returns `true`, that must be the case for all possible key types
    /// supported by [`KeyProvider::load_private_key()`].
    fn fips(&self) -> bool {
        false
    }
}

/// A supported key exchange group.
///
/// This type carries both configuration and implementation. Specifically,
/// it has a TLS-level name expressed using the [`NamedGroup`] enum, and
/// a function which produces a [`ActiveKeyExchange`].
///
/// Compare with [`NamedGroup`], which carries solely a protocol identifier.
pub trait SupportedKxGroup: Send + Sync + Debug {
    /// Start a key exchange.
    ///
    /// This will prepare an ephemeral secret key in the supported group, and a corresponding
    /// public key. The key exchange can be completed by calling [ActiveKeyExchange#complete]
    /// or discarded.
    ///
    /// # Errors
    ///
    /// This can fail if the random source fails during ephemeral key generation.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error>;

    /// Named group the SupportedKxGroup operates in.
    ///
    /// If the `NamedGroup` enum does not have a name for the algorithm you are implementing,
    /// you can use [`NamedGroup::Unknown`].
    fn name(&self) -> NamedGroup;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// An in-progress key exchange originating from a [`SupportedKxGroup`].
pub trait ActiveKeyExchange: Send + Sync {
    /// Completes the key exchange, given the peer's public key.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// mis-encoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Return the public key being used.
    ///
    /// The encoding required is defined in
    /// [RFC8446 section 4.2.8.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2).
    fn pub_key(&self) -> &[u8];

    /// Return the group being used.
    fn group(&self) -> NamedGroup;
}

/// The result from [`ActiveKeyExchange::complete`].
pub struct SharedSecret {
    buf: Vec<u8>,
}

impl SharedSecret {
    /// Returns the shared secret as a slice of bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self { buf: source.to_vec() }
    }
}

#[cfg(any(feature = "ring", feature = "fips"))]
pub(crate) fn default_provider() -> CryptoProvider {
    #[cfg(all(feature = "ring", not(feature = "fips")))]
    {
        crate::crypto::ring::default_provider()
    }
    #[cfg(feature = "fips")]
    {
        crate::crypto::aws_lc_rs::default_provider()
    }
}

/// This function returns a [`CryptoProvider`] that uses
/// FIPS140-3-approved cryptography.
///
/// You can use this like:
///
/// ```rust
/// # #[cfg(feature = "fips")] {
/// # let root_store = rustls::RootCertStore::empty();
/// let config = rustls::ClientConfig::builder_with_provider(
///         rustls::crypto::default_fips_provider().into()
///     )
///     .with_safe_default_protocol_versions()
///     .unwrap()
///     .with_root_certificates(root_store)
///     .with_no_client_auth();
/// # }
/// ```
///
/// This expresses in your code that you require FIPS-approved
/// cryptography, and will not compile if you make a mistake
/// with cargo features.
#[cfg(feature = "fips")]
pub fn default_fips_provider() -> CryptoProvider {
    crate::crypto::aws_lc_rs::default_provider()
}
