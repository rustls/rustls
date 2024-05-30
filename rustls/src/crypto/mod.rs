use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;
#[cfg(feature = "std")]
use once_cell::sync::OnceCell;
use pki_types::PrivateKeyDer;
use zeroize::Zeroize;

use crate::sign::SigningKey;
pub use crate::webpki::{
    verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
};
#[cfg(all(doc, feature = "tls12"))]
use crate::Tls12CipherSuite;
#[cfg(doc)]
use crate::{
    client, crypto, server, sign, ClientConfig, ConfigBuilder, ServerConfig, SupportedCipherSuite,
    Tls13CipherSuite,
};
use crate::{suites, Error, NamedGroup, ProtocolVersion, SupportedProtocolVersion};

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

#[cfg(feature = "tls12")]
/// Cryptography specific to TLS1.2.
pub mod tls12;

/// Cryptography specific to TLS1.3.
pub mod tls13;

/// Hybrid public key encryption (RFC 9180).
pub mod hpke;

// Message signing interfaces. Re-exported under rustls::sign. Kept crate-internal here to
// avoid having two import paths to the same types.
pub(crate) mod signer;

pub use crate::msgs::handshake::KeyExchangeAlgorithm;
pub use crate::rand::GetRandomFailed;
pub use crate::suites::CipherSuiteCommon;

/// Controls core cryptography used by rustls.
///
/// This crate comes with two built-in options, provided as
/// `CryptoProvider` structures:
///
/// - [`crypto::aws_lc_rs::default_provider`]: (behind the `aws_lc_rs` feature,
///   which is enabled by default).  This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs)
///   crate.  The `fips` crate feature makes this option use FIPS140-3-approved cryptography.
/// - [`crypto::ring::default_provider`]: (behind the `ring` crate feature, which
///   is optional).  This provider uses the [*ring*](https://github.com/briansmith/ring)
///   crate.
///
/// This structure provides defaults. Everything in it can be overridden at
/// runtime by replacing field values as needed.
///
/// # Using the per-process default `CryptoProvider`
///
/// There is the concept of an implicit default provider, configured at run-time once in
/// a given process.
///
/// It is used for functions like [`ClientConfig::builder()`] and [`ServerConfig::builder()`].
///
/// The intention is that an application can specify the [`CryptoProvider`] they wish to use
/// once, and have that apply to the variety of places where their application does TLS
/// (which may be wrapped inside other libraries).
/// They should do this by calling [`CryptoProvider::install_default()`] early on.
///
/// To achieve this goal:
///
/// - _libraries_ should use [`ClientConfig::builder()`]/[`ServerConfig::builder()`]
///   or otherwise rely on the [`CryptoProvider::get_default()`] provider.
/// - _applications_ should call [`CryptoProvider::install_default()`] early
///   in their `fn main()`.
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
/// # #[cfg(feature = "aws_lc_rs")] {
/// # use std::sync::Arc;
/// # mod fictious_hsm_api { pub fn load_private_key(key_der: pki_types::PrivateKeyDer<'static>) -> ! { unreachable!(); } }
/// use rustls::crypto::aws_lc_rs;
///
/// pub fn provider() -> rustls::crypto::CryptoProvider {
///   rustls::crypto::CryptoProvider{
///     key_provider: &HsmKeyLoader,
///     ..aws_lc_rs::default_provider()
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
    ///
    /// A valid `CryptoProvider` must ensure that all cipher suites are accompanied by at least
    /// one matching key exchange group in [`CryptoProvider::kx_groups`].
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
    /// Sets this `CryptoProvider` as the default for this process.
    ///
    /// This can be called successfully at most once in any process execution.
    ///
    /// Call this early in your process to configure which provider is used for
    /// the provider.  The configuration should happen before any use of
    /// [`ClientConfig::builder()`] or [`ServerConfig::builder()`].
    #[cfg(feature = "std")]
    pub fn install_default(self) -> Result<(), Arc<Self>> {
        PROCESS_DEFAULT_PROVIDER.set(Arc::new(self))
    }

    /// Sets this `CryptoProvider` as the default for this process.
    ///
    /// This can be called successfully at most once in any process execution.
    ///
    /// Call this early in your process to configure which provider is used for
    /// the provider.  The configuration should happen before any use of
    /// [`ClientConfig::builder()`] or [`ServerConfig::builder()`].
    #[cfg(not(feature = "std"))]
    pub fn install_default(self) -> Result<(), Box<Arc<Self>>> {
        PROCESS_DEFAULT_PROVIDER.set(Box::new(Arc::new(self)))
    }

    /// Returns the default `CryptoProvider` for this process.
    ///
    /// This will be `None` if no default has been set yet.
    pub fn get_default() -> Option<&'static Arc<Self>> {
        PROCESS_DEFAULT_PROVIDER.get()
    }

    /// An internal function that:
    ///
    /// - gets the pre-installed default, or
    /// - installs one `from_crate_features()`, or else
    /// - panics about the need to call [`CryptoProvider::install_default()`]
    pub(crate) fn get_default_or_install_from_crate_features() -> &'static Arc<Self> {
        if let Some(provider) = Self::get_default() {
            return provider;
        }

        let provider = Self::from_crate_features()
            .expect("no process-level CryptoProvider available -- call CryptoProvider::install_default() before this point");
        // Ignore the error resulting from us losing a race, and accept the outcome.
        let _ = provider.install_default();
        Self::get_default().unwrap()
    }

    /// Returns a provider named unambiguously by rustls crate features.
    ///
    /// This function returns `None` if the crate features are ambiguous (ie, specify two
    /// providers), or specify no providers.  In both cases the application should
    /// explicitly specify the provider to use with [`CryptoProvider::install_default`].
    fn from_crate_features() -> Option<Self> {
        #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
        {
            return Some(ring::default_provider());
        }

        #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
        {
            return Some(aws_lc_rs::default_provider());
        }

        #[allow(unreachable_code)]
        None
    }

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

#[cfg(feature = "std")]
static PROCESS_DEFAULT_PROVIDER: OnceCell<Arc<CryptoProvider>> = OnceCell::new();
#[cfg(not(feature = "std"))]
static PROCESS_DEFAULT_PROVIDER: OnceBox<Arc<CryptoProvider>> = OnceBox::new();

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

    /// Start and complete a key exchange, in one operation.
    ///
    /// The default implementation for this calls `start()` and then calls
    /// `complete()` on the result.  This is suitable for Diffie-Hellman-like
    /// key exchange algorithms, where there is not a data dependency between
    /// our key share (named "pub_key" in this API) and the peer's (`peer_pub_key`).
    ///
    /// If there is such a data dependency (like key encapsulation mechanisms), this
    /// function should be implemented.
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let kx = self.start()?;

        Ok(CompletedKeyExchange {
            group: kx.group(),
            pub_key: kx.pub_key().to_vec(),
            secret: kx.complete(peer_pub_key)?,
        })
    }

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
    /// If the key exchange algorithm is FFDHE, the result must be left-padded with zeros,
    /// as required by [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-7.4.1)
    /// (see [`complete_for_tls_version()`](Self::complete_for_tls_version) for more details).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Completes the key exchange for the given TLS version, given the peer's public key.
    ///
    /// Note that finite-field Diffie–Hellman key exchange has different requirements for the derived
    /// shared secret in TLS 1.2 and TLS 1.3 (ECDHE key exchange is the same in TLS 1.2 and TLS 1.3):
    ///
    /// In TLS 1.2, the calculated secret is required to be stripped of leading zeros
    /// [(RFC 5246)](https://www.rfc-editor.org/rfc/rfc5246#section-8.1.2).
    ///
    /// In TLS 1.3, the calculated secret is required to be padded with leading zeros to be the same
    /// byte-length as the group modulus [(RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446#section-7.4.1).
    ///
    /// The default implementation of this method delegates to [`complete()`](Self::complete) assuming it is
    /// implemented for TLS 1.3 (i.e., for FFDHE KX, removes padding as needed). Implementers of this trait
    /// are encouraged to just implement [`complete()`](Self::complete) assuming TLS 1.3, and let the default
    /// implementation of this method handle TLS 1.2-specific requirements.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// mis-encoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        tls_version: &SupportedProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        if tls_version.version != ProtocolVersion::TLSv1_2 {
            return self.complete(peer_pub_key);
        }

        let group = self.group();
        let mut complete_res = self.complete(peer_pub_key)?;
        if group.key_exchange_algorithm() == KeyExchangeAlgorithm::DHE {
            complete_res.strip_leading_zeros();
        }
        Ok(complete_res)
    }

    /// Return the public key being used.
    ///
    /// For ECDHE, the encoding required is defined in
    /// [RFC8446 section 4.2.8.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2).
    ///
    /// For FFDHE, the encoding required is defined in
    /// [RFC8446 section 4.2.8.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.1).
    fn pub_key(&self) -> &[u8];

    /// Return the group being used.
    fn group(&self) -> NamedGroup;
}

/// The result from [`SupportedKxGroup::start_and_complete()`].
pub struct CompletedKeyExchange {
    /// Which group was used.
    pub group: NamedGroup,

    /// Our key share (sometimes a public key).
    pub pub_key: Vec<u8>,

    /// The computed shared secret.
    pub secret: SharedSecret,
}

/// The result from [`ActiveKeyExchange::complete`].
pub struct SharedSecret {
    buf: Vec<u8>,
    offset: usize,
}

impl SharedSecret {
    /// Returns the shared secret as a slice of bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    /// Removes leading zeros from `secret_bytes()` by adjusting the `offset`.
    ///
    /// This function does not re-allocate.
    fn strip_leading_zeros(&mut self) {
        let start = self
            .secret_bytes()
            .iter()
            .enumerate()
            .find(|(_i, x)| **x != 0)
            .map(|(i, _x)| i)
            .unwrap_or(self.secret_bytes().len());
        self.offset += start;
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self {
            buf: source.to_vec(),
            offset: 0,
        }
    }
}

/// This function returns a [`CryptoProvider`] that uses
/// FIPS140-3-approved cryptography.
///
/// Using this function expresses in your code that you require
/// FIPS-approved cryptography, and will not compile if you make
/// a mistake with cargo features.
///
/// See our [FIPS documentation](crate::manual::_06_fips) for
/// more detail.
///
/// Install this as the process-default provider, like:
///
/// ```rust
/// # #[cfg(feature = "fips")] {
/// rustls::crypto::default_fips_provider().install_default()
///     .expect("default provider already set elsewhere");
/// # }
/// ```
///
/// You can also use this explicitly, like:
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
#[cfg(any(feature = "fips", docsrs))]
#[cfg_attr(docsrs, doc(cfg(feature = "fips")))]
pub fn default_fips_provider() -> CryptoProvider {
    aws_lc_rs::default_provider()
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::SharedSecret;

    #[test]
    fn test_shared_secret_strip_leading_zeros() {
        let test_cases = [
            (vec![0, 1], vec![1]),
            (vec![1], vec![1]),
            (vec![1, 0, 2], vec![1, 0, 2]),
            (vec![0, 0, 1, 2], vec![1, 2]),
            (vec![0, 0, 0], vec![]),
            (vec![], vec![]),
        ];
        for (buf, expected) in test_cases {
            let mut secret = SharedSecret::from(&buf[..]);
            assert_eq!(secret.secret_bytes(), buf);
            secret.strip_leading_zeros();
            assert_eq!(secret.secret_bytes(), expected);
        }
    }
}
