use crate::rand::GetRandomFailed;

use ring::rand::{SecureRandom, SystemRandom};

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;
}

/// Default crypto provider.
pub struct Ring;

impl CryptoProvider for Ring {
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }
}
