use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use signature::{RandomizedSigner, SignatureEncoding};

#[derive(Clone, Debug)]
pub struct EcdsaSigningKeyP256 {
    key: Arc<p256::ecdsa::SigningKey>,
    scheme: SignatureScheme,
}

impl TryFrom<PrivateKeyDer<'_>> for EcdsaSigningKeyP256 {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                p256::ecdsa::SigningKey::from_pkcs8_der(der.secret_pkcs8_der()).map(|kp| Self {
                    key: Arc::new(kp),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for EcdsaSigningKeyP256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKeyP256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: p256::ecdsa::DerSignature| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
