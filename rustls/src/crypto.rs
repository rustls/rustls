use ring::constant_time;

/// Pluggable crypto galore.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Verify that the two input slices are equal, in constant time.
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool;
}

/// Default crypto provider.
pub struct Ring;

impl CryptoProvider for Ring {
    fn verify_equal_ct(a: &[u8], b: &[u8]) -> bool {
        constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}
