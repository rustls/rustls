use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};
use std::error::Error as StdError;

use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkeProvider, HpkePublicKey, HpkeSealer,
    HpkeSuite,
};
use rustls::{Error, OtherError};

pub static HPKE_PROVIDER: &'static dyn HpkeProvider = &HpkeRsProvider {};

/// A Rustls HPKE provider backed by hpke-rs and the RustCrypto backend.
#[derive(Debug)]
struct HpkeRsProvider {}

impl HpkeProvider for HpkeRsProvider {
    fn start(&self, suite: &HpkeSuite) -> Result<Box<dyn Hpke + 'static>, Error> {
        Ok(Box::new(HpkeRs(hpke_rs::Hpke::new(
            hpke_rs::Mode::Base,
            KemAlgorithm::try_from(u16::from(suite.kem)).map_err(other_err)?,
            KdfAlgorithm::try_from(u16::from(suite.sym.kdf_id)).map_err(other_err)?,
            AeadAlgorithm::try_from(u16::from(suite.sym.aead_id)).map_err(other_err)?,
        ))))
    }

    fn supports_suite(&self, suite: &HpkeSuite) -> bool {
        let kem = KemAlgorithm::try_from(u16::from(suite.kem)).ok();
        let kdf = KdfAlgorithm::try_from(u16::from(suite.sym.kdf_id)).ok();
        let aead = AeadAlgorithm::try_from(u16::from(suite.sym.aead_id)).ok();
        match (kem, kdf, aead) {
            (Some(kem), Some(kdf), Some(aead)) => {
                HpkeRustCrypto::supports_kem(kem).is_ok()
                    && HpkeRustCrypto::supports_kdf(kdf).is_ok()
                    && HpkeRustCrypto::supports_aead(aead).is_ok()
            }
            _ => false,
        }
    }
}

struct HpkeRs(hpke_rs::Hpke<HpkeRustCrypto>);

impl Debug for HpkeRs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkeRsHpke").finish()
    }
}

impl Hpke for HpkeRs {
    fn seal(
        &mut self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, ciphertext) = self
            .0
            .seal(&pk_r, info, aad, plaintext, None, None, None)
            .map_err(other_err)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ciphertext))
    }

    fn setup_sealer(
        &mut self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, context) = self
            .0
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(other_err)?;
        Ok((
            EncapsulatedSecret(enc.to_vec()),
            Box::new(HpkeRsSender { context }),
        ))
    }

    fn open(
        &mut self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        self.0
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
        &mut self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        Ok(Box::new(HpkeRsReceiver {
            context: self
                .0
                .setup_receiver(enc.0.as_slice(), &sk_r, info, None, None, None)
                .map_err(other_err)?,
        }))
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
