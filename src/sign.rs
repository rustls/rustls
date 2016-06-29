use msgs::enums::{HashAlgorithm, SignatureAlgorithm};

extern crate ring;
extern crate untrusted;

/// A thing that can sign a message.
pub trait Signer {
  /// Signs `message`, hashing it with `hash_alg` first.
  fn sign(&self, hash_alg: &HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, ()>;

  /// What kind of key we have.
  fn algorithm(&self) -> SignatureAlgorithm;
}

/// A Signer for RSA-PKCS1
pub struct RSASigner {
  key: ring::signature::RSAKeyPair
}

impl RSASigner {
  pub fn new(der: &[u8]) -> Result<RSASigner, ()> {
    let key = ring::signature::RSAKeyPair::from_der(untrusted::Input::new(der).unwrap());
    key.map(|k| RSASigner { key: k })
  }
}

impl Signer for RSASigner {
  fn sign(&self, hash_alg: &HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, ()> {
    let mut sig = vec![0; self.key.public_modulus_len()];
    let pad = match hash_alg {
      &HashAlgorithm::SHA256 => &ring::signature::RSA_PKCS1_SHA256,
      &HashAlgorithm::SHA384 => &ring::signature::RSA_PKCS1_SHA384,
      &HashAlgorithm::SHA512 => &ring::signature::RSA_PKCS1_SHA512,
      _ => unreachable!()
    };
    let rng = ring::rand::SystemRandom::new();
    self.key.sign(pad, &rng, message, &mut sig)
      .map(|_| sig)
  }

  fn algorithm(&self) -> SignatureAlgorithm {
    SignatureAlgorithm::RSA
  }
}
