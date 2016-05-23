
/* The single place where we generate random material
 * for our own use.  These functions never fail,
 * they panic on error. */

extern crate ring;
use ring::rand::SecureRandom;

/* Fill the whole slice with random material. */
pub fn fill_random(bytes: &mut [u8]) {
  ring::rand::SystemRandom::new()
    .fill(bytes)
    .unwrap();
}

/* Make the vec v contain sz random bytes. */
pub fn fill_random_vec(v: &mut Vec<u8>, sz: usize) {
  v.resize(sz, 0u8);
  fill_random(v);
}
