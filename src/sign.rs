use msgs::enums::{HashAlgorithm, SignatureAlgorithm};
use untrusted;
use ring;
use ring::signature;
use std::sync::Arc;
use key;

/// A thing that can sign a message.
pub trait Signer {
    /// Signs `message`, hashing it with `hash_alg` first.
    fn sign(&self, hash_alg: &HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, ()>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A Signer for RSA-PKCS1
pub struct RSASigner {
    key: Arc<signature::RSAKeyPair>,
}

impl RSASigner {
    pub fn new(der: &key::PrivateKey) -> Result<RSASigner, ()> {
        let key = signature::RSAKeyPair::from_der(untrusted::Input::from(&der.0));
        key.map(|s| RSASigner { key: Arc::new(s) })
            .map_err(|_| ())
    }
}

impl Signer for RSASigner {
    fn sign(&self, hash_alg: &HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut sig = vec![0; self.key.public_modulus_len()];
        let pad = match hash_alg {
            &HashAlgorithm::SHA256 => &signature::RSA_PKCS1_SHA256,
            &HashAlgorithm::SHA384 => &signature::RSA_PKCS1_SHA384,
            &HashAlgorithm::SHA512 => &signature::RSA_PKCS1_SHA512,
            _ => unreachable!(),
        };

        let rng = ring::rand::SystemRandom::new();
        let mut signer = try!(signature::RSASigningState::new(self.key.clone()).map_err(|_| ()));

        signer.sign(pad, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| ())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
