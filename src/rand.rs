
/// The single place where we generate random material
/// for our own use.  These functions never fail,
/// they panic on error.

use ring::rand::{SystemRandom, SecureRandom};
use msgs::codec;

/// Fill the whole slice with random material.
pub fn fill_random(bytes: &mut [u8]) {
    SystemRandom::new()
        .fill(bytes)
        .unwrap();
}

/// Return a uniformly random u32.
pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    fill_random(&mut buf);
    codec::decode_u32(&buf)
        .unwrap()
}
