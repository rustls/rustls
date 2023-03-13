use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;
use crate::{Error, NamedGroup};

use std::fmt::Debug;

/// *ring* based CryptoProvider.
pub mod ring;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// KeyExchange operations that are supported by the provider.
    type KeyExchange: KeyExchange;

    /// Build a ticket generator.
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed>;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;
}

/// An in-progress key exchange over a [SupportedGroup].
pub trait KeyExchange: Sized + Send + Sync + 'static {
    /// The supported group the key exchange is operating over.
    type SupportedGroup: SupportedGroup;

    /// Start a key exchange using the [NamedGroup] if it is a suitable choice
    /// based on the groups supported.
    ///
    /// # Errors
    ///
    /// Returns an error if the [NamedGroup] is not supported, or if a key exchange
    /// can't be started (see [KeyExchange#start]).
    fn choose(
        name: NamedGroup,
        supported: &[&'static Self::SupportedGroup],
    ) -> Result<Self, KeyExchangeError>;

    /// Start a key exchange using the [SupportedGroup]. This will prepare an ephemeral
    /// secret key in the supported group, and a corresponding public key. The key exchange
    /// must be completed by calling [KeyExchange#complete].
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    fn start(skxg: &'static Self::SupportedGroup) -> Result<Self, GetRandomFailed>;

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
pub enum KeyExchangeError {
    /// Returned when the specified group is unsupported.
    UnsupportedGroup,

    /// Returned when key exchange fails.
    KeyExchangeFailed(GetRandomFailed),
}

/// A trait describing a supported key exchange group that can be identified by name.
pub trait SupportedGroup: Debug + Send + Sync + 'static {
    /// Named group the SupportedGroup operates in.
    fn name(&self) -> NamedGroup;
}
