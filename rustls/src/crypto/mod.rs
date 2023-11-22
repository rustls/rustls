use crate::crypto::signer::SigningKey;
use crate::suites;
use crate::webpki::WebPkiSupportedAlgorithms;
use crate::{Error, NamedGroup};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::PrivateKeyDer;
use zeroize::Zeroize;

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

/// Message signing interfaces.
pub mod signer;

/// Cryptography specific to TLS1.2.
pub mod tls12;

/// Cryptography specific to TLS1.3.
pub mod tls13;

/// Hybrid public key encryption (RFC 9180).
#[doc(hidden)]
pub mod hpke;

pub use crate::rand::GetRandomFailed;

pub use crate::msgs::handshake::KeyExchangeAlgorithm;

/// Controls core cryptography used by rustls.
///
/// This crate comes with two built-in options, provided as
/// `&dyn CryptoProvider` values:
///
/// - [`crate::crypto::ring::RING`]: (behind the `ring` crate feature, which
///   is enabled by default).  This provider uses the [*ring*](https://github.com/briansmith/ring)
///   crate.
/// - [`crate::crypto::aws_lc_rs::AWS_LC_RS`]: (behind the `aws_lc_rs` feature,
///   which is optional).  This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs)
///   crate.
///
/// # Using a specific `CryptoProvider`
///
/// Supply the provider when constructing your [`crate::ClientConfig`] or [`crate::ServerConfig`]:
///
/// - [`crate::ClientConfig::builder_with_provider()`]
/// - [`crate::ServerConfig::builder_with_provider()`]
///
/// When creating and configuring a webpki-backed client or server certificate verifier, a choice of
/// provider is also needed to start the configuration process:
///
/// - [`crate::client::WebPkiServerVerifier::builder_with_provider()`]
/// - [`crate::server::WebPkiClientVerifier::builder_with_provider()`]
///
/// # Making a custom `CryptoProvider`
///
/// Naturally start with a type that implements [`crate::crypto::CryptoProvider`].
///
/// ## Which elements are required?
///
/// There is no requirement that the individual elements (`SupportedCipherSuite`, `SupportedKxGroup`,
/// `SigningKey`, etc.) come from the same crate.  It is allowed and expected that uninteresting
/// elements would be delegated back to one of the default providers (statically) or a parent
/// provider (dynamically).
///
/// For example, if we want to make a provider that just overrides key loading in the config builder
/// API ([`crate::ConfigBuilder::with_single_cert`] etc.), it might look like this:
///
/// ```
/// # #[cfg(feature = "ring")] {
/// # use std::sync::Arc;
/// # mod fictious_hsm_api { pub fn load_private_key(key_der: pki_types::PrivateKeyDer<'static>) -> ! { unreachable!(); } }
/// use rustls::crypto::ring::RING;
///
/// #[derive(Debug)]
/// struct HsmKeyLoader;
///
/// impl rustls::crypto::CryptoProvider for HsmKeyLoader {
///     fn fill_random(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
///         RING.fill_random(buf)
///     }
///
///     fn default_cipher_suites(&self) -> &'static [rustls::SupportedCipherSuite] {
///         RING.default_cipher_suites()
///     }
///
///     fn default_kx_groups(&self) -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
///         RING.default_kx_groups()
///     }
///
///     fn signature_verification_algorithms(&self) -> rustls::WebPkiSupportedAlgorithms {
///         RING.signature_verification_algorithms()
///     }
///
///     fn load_private_key(&self, key_der: pki_types::PrivateKeyDer<'static>) -> Result<Arc<dyn rustls::crypto::signer::SigningKey>, rustls::Error> {
///         fictious_hsm_api::load_private_key(key_der)
///     }
/// }
/// # }
/// ```
///
/// ## References to the individual elements
///
/// The elements are documented separately:
///
/// - **Random** - see [`crate::crypto::CryptoProvider::fill_random()`].
/// - **Cipher suites** - see [`crate::SupportedCipherSuite`], [`crate::Tls12CipherSuite`], and
///   [`crate::Tls13CipherSuite`].
/// - **Key exchange groups** - see [`crate::crypto::SupportedKxGroup`].
/// - **Signature verification algorithms** - see [`crate::WebPkiSupportedAlgorithms`].
/// - **Authentication key loading** - see [`crate::crypto::CryptoProvider::load_private_key()`] and
///   [`SigningKey`].
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
pub trait CryptoProvider: Send + Sync + Debug + 'static {
    /// Fill the given buffer with random bytes.
    ///
    /// The bytes must be sourced from a cryptographically secure random number
    /// generator seeded with good quality, secret entropy.
    ///
    /// This is used for all randomness required by rustls, but not necessarily
    /// randomness required by the underlying cryptography library.  For example:
    /// [`crate::crypto::SupportedKxGroup::start()`] requires random material to generate
    /// an ephemeral key exchange key, but this is not included in the interface with
    /// rustls: it is assumed that the cryptography library provides for this itself.
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Provide a safe set of cipher suites that can be used as the defaults.
    ///
    /// This is used by [`crate::ConfigBuilder::with_safe_defaults()`] and
    /// [`crate::ConfigBuilder::with_safe_default_cipher_suites()`].
    ///
    /// Other (non-default) cipher suites can be provided separately and configured
    /// by passing them to [`crate::ConfigBuilder::with_cipher_suites()`]
    fn default_cipher_suites(&self) -> &'static [suites::SupportedCipherSuite];

    /// Return a safe set of supported key exchange groups to be used as the defaults.
    ///
    /// This is used by [`crate::ConfigBuilder::with_safe_defaults()`] and
    /// [`crate::ConfigBuilder::with_safe_default_kx_groups()`].
    ///
    /// Other (non-default) key exchange groups can be provided separately and configured
    /// by passing them to [`crate::ConfigBuilder::with_kx_groups()`].
    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup];

    /// Decode and validate a private signing key from `key_der`.
    ///
    /// This is used by [`crate::ConfigBuilder::with_client_auth_cert()`], [`crate::ConfigBuilder::with_single_cert()`],
    /// and [`crate::ConfigBuilder::with_single_cert_with_ocsp()`].  The key types and formats supported by this
    /// function directly defines the key types and formats supported in those APIs.
    ///
    /// Return an error if the key type encoding is not supported, or if the key fails validation.
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error>;

    /// Return the signature verification algorithms for use with webpki.
    ///
    /// These are used for both certificate chain verification and handshake signature verification.
    ///
    /// This is called by [`crate::ConfigBuilder::with_root_certificates()`],
    /// [`crate::server::WebPkiClientVerifier::builder_with_provider()`] and
    /// [`crate::client::WebPkiServerVerifier::builder_with_provider()`].
    fn signature_verification_algorithms(&self) -> WebPkiSupportedAlgorithms;
}

/// A supported key exchange group.
///
/// This has a TLS-level name expressed using the [`NamedGroup`] enum, and
/// a function which produces a [`ActiveKeyExchange`].
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
}

/// An in-progress key exchange originating from a `SupportedKxGroup`.
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

/// The result from `ActiveKeyExchange::complete` as a value.
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Returns the shared secret as a slice of bytes.
    pub(crate) fn secret_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self(source.to_vec())
    }
}
