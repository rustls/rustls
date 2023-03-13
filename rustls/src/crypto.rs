use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;
use crate::NamedGroup;
use std::fmt::Debug;

/// *ring* based CryptoProvider.
pub mod ring;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Build a ticket generator.
    fn ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed>;

    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Verify that the two input slices are equal, in constant time.
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool;
}

pub(crate) enum KeyExchangeError {
    UnsupportedGroup,
    KeyExchangeFailed(GetRandomFailed),
}

/// A trait describing a supported key exchange group that can be identified by name.
pub trait SupportedGroup: Debug + Send + Sync + 'static {
    /// Named group the SupportedGroup operates in.
    fn name(&self) -> NamedGroup;
}
