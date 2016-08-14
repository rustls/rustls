
/// The single place where we generate random material
/// for our own use.  These functions never fail,
/// they panic on error.

extern crate ring;

/// Fill the whole slice with random material.
pub fn fill_random(bytes: &mut [u8]) {
  ring::rand::SystemRandom::new()
    .fill(bytes)
    .unwrap();
}

