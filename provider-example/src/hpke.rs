use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use std::error::Error as StdError;

use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{
    HpkeAead as HpkeAeadId, HpkeKdf as HpkeKdfId, HpkeKem as HpkeKemId,
};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::{Error, OtherError};

/// All supported HPKE suites.
///
/// Note: hpke-rs w/ rust-crypto does not support P-384 and P-521 DH KEMs.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    DHKEM_P256_HKDF_SHA256_AES_128,
    DHKEM_P256_HKDF_SHA256_AES_256,
    DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    DHKEM_X25519_HKDF_SHA256_AES_128,
    DHKEM_X25519_HKDF_SHA256_AES_256,
    DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

pub static DHKEM_P256_HKDF_SHA256_AES_128: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_P256_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::AES_128_GCM,
    },
});

pub static DHKEM_P256_HKDF_SHA256_AES_256: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_P256_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::AES_256_GCM,
    },
});

pub static DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_P256_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::CHACHA20_POLY_1305,
    },
});

pub static DHKEM_X25519_HKDF_SHA256_AES_128: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_X25519_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::AES_128_GCM,
    },
});

pub static DHKEM_X25519_HKDF_SHA256_AES_256: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_X25519_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::AES_256_GCM,
    },
});

pub static DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305: &HpkeRs = &HpkeRs(HpkeSuite {
    kem: HpkeKemId::DHKEM_X25519_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdfId::HKDF_SHA256,
        aead_id: HpkeAeadId::CHACHA20_POLY_1305,
    },
});

/// A HPKE suite backed by the [hpke-rs] crate and its rust-crypto cryptography provider.
///
/// [hpke-rs]: https://github.com/franziskuskiefer/hpke-rs
#[derive(Debug)]
pub struct HpkeRs(HpkeSuite);

impl HpkeRs {
    fn start(&self) -> Result<hpke_rs::Hpke<HpkeRustCrypto>, Error> {
        Ok(hpke_rs::Hpke::new(
            hpke_rs::Mode::Base,
            KemAlgorithm::try_from(u16::from(self.0.kem)).map_err(other_err)?,
            KdfAlgorithm::try_from(u16::from(self.0.sym.kdf_id)).map_err(other_err)?,
            AeadAlgorithm::try_from(u16::from(self.0.sym.aead_id)).map_err(other_err)?,
        ))
    }
}

impl Hpke for HpkeRs {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, ciphertext) = self
            .start()?
            .seal(&pk_r, info, aad, plaintext, None, None, None)
            .map_err(other_err)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ciphertext))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, context) = self
            .start()?
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(other_err)?;
        Ok((
            EncapsulatedSecret(enc.to_vec()),
            Box::new(HpkeRsSender { context }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        self.start()?
            .open(
                enc.0.as_slice(),
                &sk_r,
                info,
                aad,
                ciphertext,
                None,
                None,
                None,
            )
            .map_err(other_err)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        Ok(Box::new(HpkeRsReceiver {
            context: self
                .start()?
                .setup_receiver(enc.0.as_slice(), &sk_r, info, None, None, None)
                .map_err(other_err)?,
        }))
    }

    fn suite(&self) -> HpkeSuite {
        self.0
    }
}

#[derive(Debug)]
struct HpkeRsSender {
    context: hpke_rs::Context<HpkeRustCrypto>,
}

impl HpkeSealer for HpkeRsSender {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .seal(aad, plaintext)
            .map_err(other_err)
    }
}

#[derive(Debug)]
struct HpkeRsReceiver {
    context: hpke_rs::Context<HpkeRustCrypto>,
}

impl HpkeOpener for HpkeRsReceiver {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .open(aad, ciphertext)
            .map_err(other_err)
    }
}

#[cfg(feature = "std")]
fn other_err(err: impl StdError + Send + Sync + 'static) -> Error {
    Error::Other(OtherError(Arc::new(err)))
}

#[cfg(not(feature = "std"))]
fn other_err(err: impl Send + Sync + 'static) -> Error {
    Error::General(alloc::format!("{}", err));
}
