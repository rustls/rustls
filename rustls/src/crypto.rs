use crate::rand::GetRandomFailed;

use ring::constant_time;
use ring::rand::{SecureRandom, SystemRandom};

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Fill the given buffer with random bytes.
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Verify that the two input slices are equal, in constant time.
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool;
}

/// Default crypto provider.
pub struct Ring;

impl CryptoProvider for Ring {
    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool {
        constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}
