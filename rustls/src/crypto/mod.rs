use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt::Debug;
use core::ops::Deref;
use core::time::Duration;

use pki_types::PrivateKeyDer;
use zeroize::Zeroize;

use crate::enums::ProtocolVersion;
use crate::error::{ApiMisuse, Error};
use crate::msgs::ffdhe_groups::FfdheGroup;
use crate::msgs::handshake::ALL_KEY_EXCHANGE_ALGORITHMS;
use crate::sync::Arc;
pub use crate::webpki::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
#[cfg(doc)]
use crate::{ClientConfig, ConfigBuilder, ServerConfig, client, crypto, server};
use crate::{SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite};

/// aws-lc-rs-based CryptoProvider.
#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

/// TLS message encryption/decryption interfaces.
pub mod cipher;

mod enums;
pub use enums::{CipherSuite, HashAlgorithm, NamedGroup, SignatureAlgorithm, SignatureScheme};

/// Hashing interfaces.
pub mod hash;

/// HMAC interfaces.
pub mod hmac;

/// Cryptography specific to TLS1.2.
pub mod tls12;

/// Cryptography specific to TLS1.3.
pub mod tls13;

/// Hybrid public key encryption (RFC 9180).
pub mod hpke;

// Message signing interfaces.
mod signer;
pub use signer::{
    CertificateIdentity, Credentials, Identity, InconsistentKeys, SelectedCredential, Signer,
    SigningKey, SingleCredential, public_key_to_spki,
};

pub use crate::msgs::handshake::KeyExchangeAlgorithm;
pub use crate::rand::GetRandomFailed;
pub use crate::suites::CipherSuiteCommon;

/// Controls core cryptography used by rustls.
///
/// This crate comes with one built-in option, provided as
/// `CryptoProvider` structures:
///
/// - [`crypto::aws_lc_rs::DEFAULT_PROVIDER`]: (behind the `aws-lc-rs` crate feature).
///   This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs)
///   crate.  The `fips` crate feature makes this option use FIPS140-3-approved cryptography.
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
///   in their `fn main()`. If _applications_ uses a custom provider based on the one built-in,
///   they can activate the `custom-provider` feature to ensure its usage.
///
/// # Using a specific `CryptoProvider`
///
/// Supply the provider when constructing your [`ClientConfig`] or [`ServerConfig`]:
///
/// - [`ClientConfig::builder()`]
/// - [`ServerConfig::builder()`]
///
/// When creating and configuring a webpki-backed client or server certificate verifier, a choice of
/// provider is also needed to start the configuration process:
///
/// - [`client::WebPkiServerVerifier::builder()`]
/// - [`server::WebPkiClientVerifier::builder()`]
///
/// If you install a custom provider and want to avoid any accidental use of a built-in provider, the feature
/// `custom-provider` can be activated to ensure your custom provider is used everywhere
/// and not a built-in one. This will disable any implicit use of a built-in provider.
///
/// # Making a custom `CryptoProvider`
///
/// Your goal will be to populate an instance of this `CryptoProvider` struct.
///
/// ## Which elements are required?
///
/// There is no requirement that the individual elements ([`SupportedCipherSuite`], [`SupportedKxGroup`],
/// [`SigningKey`], etc.) come from the same crate.  It is allowed and expected that uninteresting
/// elements would be delegated back to one of the default providers (statically) or a parent
/// provider (dynamically).
///
/// For example, if we want to make a provider that just overrides key loading in the config builder
/// API (with [`ConfigBuilder::with_single_cert`], etc.), it might look like this:
///
/// ```
/// # #[cfg(feature = "aws-lc-rs")] {
/// # use std::sync::Arc;
/// # mod fictitious_hsm_api { pub fn load_private_key(key_der: pki_types::PrivateKeyDer<'static>) -> ! { unreachable!(); } }
/// use rustls::crypto::aws_lc_rs;
///
/// pub fn provider() -> rustls::crypto::CryptoProvider {
///   rustls::crypto::CryptoProvider{
///     key_provider: &HsmKeyLoader,
///     ..aws_lc_rs::DEFAULT_PROVIDER
///   }
/// }
///
/// #[derive(Debug)]
/// struct HsmKeyLoader;
///
/// impl rustls::crypto::KeyProvider for HsmKeyLoader {
///     fn load_private_key(&self, key_der: pki_types::PrivateKeyDer<'static>) -> Result<Box<dyn rustls::crypto::SigningKey>, rustls::Error> {
///          fictitious_hsm_api::load_private_key(key_der)
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
///   [`SigningKey`].
///
/// # Example code
///
/// See custom [`provider-example/`] for a full client and server example that uses
/// cryptography from the [`RustCrypto`] and [`dalek-cryptography`] projects.
///
/// ```shell
/// $ cargo run --example client | head -3
/// Current ciphersuite: TLS13_CHACHA20_POLY1305_SHA256
/// HTTP/1.1 200 OK
/// Content-Type: text/html; charset=utf-8
/// Content-Length: 19899
/// ```
///
/// [`provider-example/`]: https://github.com/rustls/rustls/tree/main/provider-example/
/// [`RustCrypto`]: https://github.com/RustCrypto
/// [`dalek-cryptography`]: https://github.com/dalek-cryptography
///
/// # FIPS-approved cryptography
/// The `fips` crate feature enables use of the `aws-lc-rs` crate in FIPS mode.
///
/// You can verify the configuration at runtime by checking
/// [`ServerConfig::fips()`]/[`ClientConfig::fips()`] return `true`.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// List of supported TLS1.2 cipher suites, in preference order -- the first element
    /// is the highest priority.
    ///
    /// Note that the protocol version is negotiated before the cipher suite.
    ///
    /// The `Tls12CipherSuite` type carries both configuration and implementation.
    ///
    /// A valid `CryptoProvider` must ensure that all cipher suites are accompanied by at least
    /// one matching key exchange group in [`CryptoProvider::kx_groups`].
    pub tls12_cipher_suites: Cow<'static, [&'static Tls12CipherSuite]>,

    /// List of supported TLS1.3 cipher suites, in preference order -- the first element
    /// is the highest priority.
    ///
    /// Note that the protocol version is negotiated before the cipher suite.
    ///
    /// The `Tls13CipherSuite` type carries both configuration and implementation.
    pub tls13_cipher_suites: Cow<'static, [&'static Tls13CipherSuite]>,

    /// List of supported key exchange groups, in preference order -- the
    /// first element is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    ///
    /// The `SupportedKxGroup` type carries both configuration and implementation.
    pub kx_groups: Cow<'static, [&'static dyn SupportedKxGroup]>,

    /// List of signature verification algorithms for use with webpki.
    ///
    /// These are used for both certificate chain verification and handshake signature verification.
    ///
    /// This is called by [`ConfigBuilder::with_root_certificates()`],
    /// [`server::WebPkiClientVerifier::builder()`] and
    /// [`client::WebPkiServerVerifier::builder()`].
    pub signature_verification_algorithms: WebPkiSupportedAlgorithms,

    /// Source of cryptographically secure random numbers.
    pub secure_random: &'static dyn SecureRandom,

    /// Provider for loading private [`SigningKey`]s from [`PrivateKeyDer`].
    pub key_provider: &'static dyn KeyProvider,

    /// Provider for creating [`TicketProducer`]s for stateless session resumption.
    pub ticketer_factory: &'static dyn TicketerFactory,
}

impl CryptoProvider {
    /// Sets this `CryptoProvider` as the default for this process.
    ///
    /// This can be called successfully at most once in any process execution.
    ///
    /// Call this early in your process to configure which provider is used for
    /// the provider.  The configuration should happen before any use of
    /// [`ClientConfig::builder()`] or [`ServerConfig::builder()`].
    pub fn install_default(self) -> Result<(), Arc<Self>> {
        static_default::install_default(self)
    }
}

impl CryptoProvider {
    /// Returns the default `CryptoProvider` for this process.
    ///
    /// This will be `None` if no default has been set yet.
    pub fn get_default() -> Option<&'static Arc<Self>> {
        static_default::get_default()
    }

    /// Returns `true` if this `CryptoProvider` is operating in FIPS mode.
    ///
    /// This covers only the cryptographic parts of FIPS approval.  There are
    /// also TLS protocol-level recommendations made by NIST.  You should
    /// prefer to call [`ClientConfig::fips()`] or [`ServerConfig::fips()`]
    /// which take these into account.
    pub fn fips(&self) -> bool {
        let Self {
            tls12_cipher_suites,
            tls13_cipher_suites,
            kx_groups,
            signature_verification_algorithms,
            secure_random,
            key_provider,
            ticketer_factory,
        } = self;
        tls12_cipher_suites
            .iter()
            .all(|cs| cs.fips())
            && tls13_cipher_suites
                .iter()
                .all(|cs| cs.fips())
            && kx_groups.iter().all(|kx| kx.fips())
            && signature_verification_algorithms.fips()
            && secure_random.fips()
            && key_provider.fips()
            && ticketer_factory.fips()
    }

    pub(crate) fn consistency_check(&self) -> Result<(), Error> {
        if self.tls12_cipher_suites.is_empty() && self.tls13_cipher_suites.is_empty() {
            return Err(ApiMisuse::NoCipherSuitesConfigured.into());
        }

        if self.kx_groups.is_empty() {
            return Err(ApiMisuse::NoKeyExchangeGroupsConfigured.into());
        }

        // verifying cipher suites have matching kx groups
        let mut supported_kx_algos = Vec::with_capacity(ALL_KEY_EXCHANGE_ALGORITHMS.len());
        for group in self.kx_groups.iter() {
            let kx = group.name().key_exchange_algorithm();
            if !supported_kx_algos.contains(&kx) {
                supported_kx_algos.push(kx);
            }
            // Small optimization. We don't need to go over other key exchange groups
            // if we already cover all supported key exchange algorithms
            if supported_kx_algos.len() == ALL_KEY_EXCHANGE_ALGORITHMS.len() {
                break;
            }
        }

        for cs in self.tls12_cipher_suites.iter() {
            if supported_kx_algos.contains(&cs.kx) {
                continue;
            }
            let suite_name = cs.common.suite;
            return Err(Error::General(alloc::format!(
                "TLS1.2 cipher suite {suite_name:?} requires {0:?} key exchange, but no {0:?}-compatible \
                key exchange groups were present in `CryptoProvider`'s `kx_groups` field",
                cs.kx,
            )));
        }

        Ok(())
    }

    pub(crate) fn iter_cipher_suites(&self) -> impl Iterator<Item = SupportedCipherSuite> + '_ {
        self.tls13_cipher_suites
            .iter()
            .copied()
            .map(SupportedCipherSuite::Tls13)
            .chain(
                self.tls12_cipher_suites
                    .iter()
                    .copied()
                    .map(SupportedCipherSuite::Tls12),
            )
    }

    /// We support a given TLS version if at least one ciphersuite for the version
    /// is available.
    pub(crate) fn supports_version(&self, v: ProtocolVersion) -> bool {
        match v {
            ProtocolVersion::TLSv1_2 => !self.tls12_cipher_suites.is_empty(),
            ProtocolVersion::TLSv1_3 => !self.tls13_cipher_suites.is_empty(),
            _ => false,
        }
    }

    pub(crate) fn find_kx_group(
        &self,
        name: NamedGroup,
        version: ProtocolVersion,
    ) -> Option<&'static dyn SupportedKxGroup> {
        if !name.usable_for_version(version) {
            return None;
        }
        self.kx_groups
            .iter()
            .find(|skxg| skxg.name() == name)
            .copied()
    }
}

impl Borrow<[&'static Tls12CipherSuite]> for CryptoProvider {
    fn borrow(&self) -> &[&'static Tls12CipherSuite] {
        &self.tls12_cipher_suites
    }
}

impl Borrow<[&'static Tls13CipherSuite]> for CryptoProvider {
    fn borrow(&self) -> &[&'static Tls13CipherSuite] {
        &self.tls13_cipher_suites
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

/// A mechanism for loading private [`SigningKey`]s from [`PrivateKeyDer`].
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
    ) -> Result<Box<dyn SigningKey>, Error>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    ///
    /// If this returns `true`, that must be the case for all possible key types
    /// supported by [`KeyProvider::load_private_key()`].
    fn fips(&self) -> bool {
        false
    }
}

/// A factory that builds [`TicketProducer`]s.
///
/// These can be used in [`ServerConfig::ticketer`] to enable stateless resumption.
///
/// [`ServerConfig::ticketer`]: crate::server::ServerConfig::ticketer
pub trait TicketerFactory: Debug + Send + Sync {
    /// Build a new `TicketProducer`.
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool;
}

/// A trait for the ability to encrypt and decrypt tickets.
pub trait TicketProducer: Debug + Send + Sync {
    /// Encrypt and authenticate `plain`, returning the resulting
    /// ticket.  Return None if `plain` cannot be encrypted for
    /// some reason: an empty ticket will be sent and the connection
    /// will continue.
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>>;

    /// Decrypt `cipher`, validating its authenticity protection
    /// and recovering the plaintext.  `cipher` is fully attacker
    /// controlled, so this decryption must be side-channel free,
    /// panic-proof, and otherwise bullet-proof.  If the decryption
    /// fails, return None.
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>>;

    /// Returns the lifetime of tickets produced now.
    /// The lifetime is provided as a hint to clients that the
    /// ticket will not be useful after the given time.
    ///
    /// This lifetime must be implemented by key rolling and
    /// erasure, *not* by storing a lifetime in the ticket.
    ///
    /// The objective is to limit damage to forward secrecy caused
    /// by tickets, not just limiting their lifetime.
    fn lifetime(&self) -> Duration;
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
    /// public key. The key exchange can be completed by calling [`ActiveKeyExchange::complete()`]
    /// or discarded.
    ///
    /// Most implementations will want to return the `StartedKeyExchange::Single(_)` variant.
    /// Hybrid key exchange algorithms, which are constructed from two underlying algorithms,
    /// may wish to return `StartedKeyExchange::Hybrid(_)` variant which additionally allows
    /// one part of the key exchange to be completed separately.  See the documentation
    /// on [`HybridKeyExchange`] for more detail.
    ///
    /// # Errors
    ///
    /// This can fail if the random source fails during ephemeral key generation.
    fn start(&self) -> Result<StartedKeyExchange, Error>;

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
        let kx = self.start()?.into_single();

        Ok(CompletedKeyExchange {
            group: kx.group(),
            pub_key: kx.pub_key().to_vec(),
            secret: kx.complete(peer_pub_key)?,
        })
    }

    /// FFDHE group the `SupportedKxGroup` operates in, if any.
    ///
    /// The default implementation returns `None`, so non-FFDHE groups (the
    /// most common) do not need to do anything.
    ///
    /// FFDHE groups must implement this. `rustls::ffdhe_groups` contains
    /// suitable values to return, for example
    /// [`rustls::ffdhe_groups::FFDHE2048`][crate::ffdhe_groups::FFDHE2048].
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
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

/// Return value from [`SupportedKxGroup::start()`].
#[non_exhaustive]
pub enum StartedKeyExchange {
    /// A single [`ActiveKeyExchange`].
    Single(Box<dyn ActiveKeyExchange>),
    /// A [`HybridKeyExchange`] that can potentially be split.
    Hybrid(Box<dyn HybridKeyExchange>),
}

impl StartedKeyExchange {
    /// Collapses this object into its underlying [`ActiveKeyExchange`].
    ///
    /// This removes the ability to do the hybrid key exchange optimization,
    /// but still allows the key exchange as a whole to be completed.
    pub fn into_single(self) -> Box<dyn ActiveKeyExchange> {
        match self {
            Self::Single(s) => s,
            Self::Hybrid(h) => h.into_key_exchange(),
        }
    }

    /// Accesses the [`HybridKeyExchange`], and checks it was also usable separately.
    ///
    /// Returns:
    ///
    /// - the [`HybridKeyExchange`]
    /// - the stand-alone `SupportedKxGroup` for the hybrid's component group.
    ///
    /// This returns `None` for:
    ///
    /// - non-hybrid groups,
    /// - if the hybrid component group is not present in `supported`
    /// - if the hybrid component group is not usable with `version`
    pub(crate) fn as_hybrid_checked(
        &self,
        supported: &[&'static dyn SupportedKxGroup],
        version: ProtocolVersion,
    ) -> Option<(&dyn HybridKeyExchange, &'static dyn SupportedKxGroup)> {
        let Self::Hybrid(hybrid) = self else {
            return None;
        };

        let component_group = hybrid.component().0;
        if !component_group.usable_for_version(version) {
            return None;
        }

        supported
            .iter()
            .find(|g| g.name() == component_group)
            .copied()
            .map(|g| (hybrid.as_ref(), g))
    }
}

impl Deref for StartedKeyExchange {
    type Target = dyn ActiveKeyExchange;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(s) => s.as_ref(),
            Self::Hybrid(h) => h.as_key_exchange(),
        }
    }
}

/// An in-progress key exchange originating from a [`SupportedKxGroup`].
pub trait ActiveKeyExchange: Send + Sync {
    /// Completes the key exchange, given the peer's public key.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// misencoded, or an invalid public key (such as, but not limited to, being
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
    /// misencoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        tls_version: ProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        if tls_version == ProtocolVersion::TLSv1_3 {
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

    /// FFDHE group the `ActiveKeyExchange` is operating in.
    ///
    /// The default implementation returns `None`, so non-FFDHE groups (the
    /// most common) do not need to do anything.
    ///
    /// FFDHE groups must implement this. `rustls::ffdhe_groups` contains
    /// suitable values to return, for example
    /// [`rustls::ffdhe_groups::FFDHE2048`][crate::ffdhe_groups::FFDHE2048].
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup;
}

/// An in-progress hybrid key exchange originating from a [`SupportedKxGroup`].
///
/// "Hybrid" means a key exchange algorithm which is constructed from two
/// (or more) independent component algorithms. Usually one is post-quantum-secure,
/// and the other is "classical".  See
/// <https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/11/>
///
/// There is no requirement for a hybrid scheme (or any other!) to implement
/// `HybridKeyExchange` if it is not desirable for it to be "split" like this.
/// It only enables an optimization; described below.
///
/// # Background
/// Rustls always sends a presumptive key share in its `ClientHello`, using
/// (absent any other information) the first item in [`CryptoProvider::kx_groups`].
/// If the server accepts the client's selection, it can complete the handshake
/// using that key share.  If not, the server sends a `HelloRetryRequest` instructing
/// the client to send a different key share instead.
///
/// This request costs an extra round trip, and wastes the key exchange computation
/// (in [`SupportedKxGroup::start()`]) the client already did.  We would
/// like to avoid those wastes if possible.
///
/// It is early days for post-quantum-secure hybrid key exchange deployment.
/// This means (commonly) continuing to offer both the hybrid and classical
/// key exchanges, so the handshake can be completed without a `HelloRetryRequest`
/// for servers that support the offered hybrid or classical schemes.
///
/// Implementing `HybridKeyExchange` enables two optimizations:
///
/// 1. Sending both the hybrid and classical key shares in the `ClientHello`.
///
/// 2. Performing the classical key exchange setup only once.  This is important
///    because the classical key exchange setup is relatively expensive.
///    This optimization is permitted and described in
///    <https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-11.html#section-3.2>
///
/// Both of these only happen if the classical algorithm appears separately in
/// the client's [`CryptoProvider::kx_groups`], and if the hybrid algorithm appears
/// first in that list.
///
/// # How it works
/// This function is only called by rustls for clients.  It is called when
/// constructing the initial `ClientHello`.  rustls follows these steps:
///
/// 1. If the return value is `None`, nothing further happens.
/// 2. If the given [`NamedGroup`] does not appear in
///    [`CryptoProvider::kx_groups`], nothing further happens.
/// 3. The given key share is added to the `ClientHello`, after the hybrid entry.
///
/// Then, one of three things may happen when the server replies to the `ClientHello`:
///
/// 1. The server sends a `HelloRetryRequest`.  Everything is thrown away and
///    we start again.
/// 2. The server agrees to our hybrid key exchange: rustls calls
///    [`ActiveKeyExchange::complete()`] consuming `self`.
/// 3. The server agrees to our classical key exchange: rustls calls
///    [`HybridKeyExchange::complete_component()`] which
///    discards the hybrid key data, and completes just the classical key exchange.
pub trait HybridKeyExchange: ActiveKeyExchange {
    /// Returns the [`NamedGroup`] and public key "share" for the component.
    fn component(&self) -> (NamedGroup, &[u8]);

    /// Completes the classical component of the key exchange, given the peer's public key.
    ///
    /// This method must return an error if `peer_pub_key` is invalid: either
    /// misencoded, or an invalid public key (such as, but not limited to, being
    /// in a small order subgroup).
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// See the documentation on [`HybridKeyExchange`] for explanation.
    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Obtain the value as a `dyn ActiveKeyExchange`
    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static);

    /// Remove the ability to do hybrid key exchange on this object.
    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange>;
}

/// The result from [`SupportedKxGroup::start_and_complete()`].
#[expect(clippy::exhaustive_structs)]
pub struct CompletedKeyExchange {
    /// Which group was used.
    pub group: NamedGroup,

    /// Our key share (sometimes a public key).
    pub pub_key: Vec<u8>,

    /// The computed shared secret.
    pub secret: SharedSecret,
}

/// The result from [`ActiveKeyExchange::complete()`] or [`HybridKeyExchange::complete_component()`].
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
            .unwrap_or_else(|| self.secret_bytes().len());
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

impl From<Vec<u8>> for SharedSecret {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, offset: 0 }
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
/// let config = rustls::ClientConfig::builder(
///         rustls::crypto::default_fips_provider().into()
///     )
///     .with_root_certificates(root_store)
///     .with_no_client_auth()
///     .unwrap();
/// # }
/// ```
#[cfg(all(feature = "aws-lc-rs", any(feature = "fips", rustls_docsrs)))]
#[cfg_attr(rustls_docsrs, doc(cfg(feature = "fips")))]
pub fn default_fips_provider() -> CryptoProvider {
    aws_lc_rs::DEFAULT_PROVIDER
}

mod static_default {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    #[cfg(feature = "std")]
    use std::sync::OnceLock;

    #[cfg(not(feature = "std"))]
    use once_cell::race::OnceBox;

    use super::CryptoProvider;
    use crate::sync::Arc;

    #[cfg(feature = "std")]
    pub(crate) fn install_default(
        default_provider: CryptoProvider,
    ) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.set(Arc::new(default_provider))
    }

    #[cfg(not(feature = "std"))]
    pub(crate) fn install_default(
        default_provider: CryptoProvider,
    ) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER
            .set(Box::new(Arc::new(default_provider)))
            .map_err(|e| *e)
    }

    pub(crate) fn get_default() -> Option<&'static Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.get()
    }

    #[cfg(feature = "std")]
    static PROCESS_DEFAULT_PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    #[cfg(not(feature = "std"))]
    static PROCESS_DEFAULT_PROVIDER: OnceBox<Arc<CryptoProvider>> = OnceBox::new();
}

#[cfg(test)]
pub(crate) fn tls13_suite(
    suite: CipherSuite,
    provider: &CryptoProvider,
) -> &'static Tls13CipherSuite {
    provider
        .tls13_cipher_suites
        .iter()
        .find(|cs| cs.common.suite == suite)
        .unwrap()
}

#[cfg(test)]
pub(crate) fn tls12_suite(
    suite: CipherSuite,
    provider: &CryptoProvider,
) -> &'static Tls12CipherSuite {
    provider
        .tls12_cipher_suites
        .iter()
        .find(|cs| cs.common.suite == suite)
        .unwrap()
}

#[cfg(test)]
pub(crate) fn tls13_only(provider: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        tls12_cipher_suites: Cow::default(),
        ..provider
    }
}

#[cfg(test)]
pub(crate) fn tls12_only(provider: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        tls13_cipher_suites: Cow::default(),
        ..provider
    }
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
