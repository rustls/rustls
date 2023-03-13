use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;

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
