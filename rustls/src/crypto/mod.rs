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
}
