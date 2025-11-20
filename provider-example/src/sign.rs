use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::crypto::{SignatureScheme, Signer, SigningKey};
use rustls::pki_types::{PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use signature::{RandomizedSigner, SignatureEncoding};

#[derive(Clone, Debug)]
pub(crate) struct EcdsaSigningKeyP256 {
    key: Arc<p256::ecdsa::SigningKey>,
    scheme: SignatureScheme,
}

impl TryFrom<PrivatePkcs8KeyDer<'_>> for EcdsaSigningKeyP256 {
    type Error = pkcs8::Error;

    fn try_from(value: PrivatePkcs8KeyDer<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            key: Arc::new(p256::ecdsa::SigningKey::from_pkcs8_der(
                value.secret_pkcs8_der(),
            )?),
            scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
        })
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

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.key
                .verifying_key()
                .to_public_key_der()
                .ok()?
                .into_vec(),
        ))
    }
}

impl Signer for EcdsaSigningKeyP256 {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: p256::ecdsa::DerSignature| sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
