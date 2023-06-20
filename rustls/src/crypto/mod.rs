use crate::rand::GetRandomFailed;
use crate::suites;
use crate::{Error, NamedGroup};

use core::fmt::Debug;

/// *ring* based CryptoProvider.
pub mod ring;

/// TLS message encryption/decryption intefaces.
pub mod cipher;

/// Hashing interfaces.
pub mod hash;

/// HMAC interfaces.
pub mod hmac;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// KeyExchange operations that are supported by the provider.
    type KeyExchange: KeyExchange;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Configure a safe set of cipher suites that can be used as the defaults.
    fn default_cipher_suites() -> &'static [suites::SupportedCipherSuite];
}

/// An in-progress key exchange over a [SupportedGroup].
pub trait KeyExchange: Sized + Send + Sync + 'static {
    /// The supported group the key exchange is operating over.
    type SupportedGroup: SupportedGroup;

    /// Start a key exchange using the [NamedGroup] if it is a suitable choice
    /// based on the groups supported.
    ///
    /// This will prepare an ephemeral secret key in the supported group, and a corresponding
    /// public key. The key exchange must be completed by calling [KeyExchange#complete].
    ///
    /// `name` gives the name of the chosen key exchange group that should be used.  `supported`
    /// is the configured collection of supported key exchange groups. Implementation-specific
    /// data can be looked up in this array (based on `name`) to allow unconfigured algorithms
    /// to be discarded by the linker.
    ///
    /// # Errors
    ///
    /// Returns an error if the [NamedGroup] is not supported, or if a key exchange
    /// can't be started.
    fn start(
        name: NamedGroup,
        supported: &[&'static Self::SupportedGroup],
    ) -> Result<Self, KeyExchangeError>;

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    fn complete<T>(self, peer: &[u8], f: impl FnOnce(&[u8]) -> Result<T, ()>) -> Result<T, Error>;

    /// Return the group being used.
    fn group(&self) -> NamedGroup;

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8];

    /// Return all supported key exchange groups.
    fn all_kx_groups() -> &'static [&'static Self::SupportedGroup];
}

/// Enumerates possible key exchange errors.
#[derive(Debug)]
pub enum KeyExchangeError {
    /// Returned when the specified group is unsupported.
    UnsupportedGroup,

    /// Random material generation failure during key generation/exchange.
    GetRandomFailed,
}

/// A trait describing a supported key exchange group that can be identified by name.
pub trait SupportedGroup: Debug + Send + Sync + 'static {
    /// Named group the SupportedGroup operates in.
    fn name(&self) -> NamedGroup;
}
