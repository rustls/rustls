use crate::suites;
use crate::{Error, NamedGroup};

use core::fmt::Debug;

/// *ring* based CryptoProvider.
#[cfg(feature = "ring")]
pub mod ring;

/// TLS message encryption/decryption interfaces.
pub mod cipher;

/// Hashing interfaces.
pub mod hash;

/// HMAC interfaces.
pub mod hmac;

/// Message signing interfaces.
pub mod signer;

pub use crate::rand::GetRandomFailed;

pub use crate::msgs::handshake::KeyExchangeAlgorithm;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Provide a safe set of cipher suites that can be used as the defaults.
    fn default_cipher_suites() -> &'static [suites::SupportedCipherSuite];

    /// Return a safe set of supported key exchange groups to be used as the defaults.
    fn default_kx_groups() -> &'static [&'static dyn SupportedKxGroup];
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
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, GetRandomFailed>;

    /// Named group the SupportedKxGroup operates in.
    fn name(&self) -> NamedGroup;
}

/// An in-progress key exchange originating from a `SupportedKxGroup`.
pub trait ActiveKeyExchange: Send + Sync {
    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is returned as a [`SharedSecret`] which can be constructed
    /// from a `&[u8]`.
    ///
    /// This consumes and so terminates the [`ActiveKeyExchange`].
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error>;

    /// Return the public key being used.
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

impl From<&[u8]> for SharedSecret {
    fn from(source: &[u8]) -> Self {
        Self(source.to_vec())
    }
}
