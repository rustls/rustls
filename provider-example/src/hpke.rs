use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};
use std::error::Error as StdError;

use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkePrivateKey, HpkeProvider, HpkePublicKey, HpkeSuite,
};
use rustls::{Error, OtherError};

pub static HPKE_PROVIDER: &'static dyn HpkeProvider = &HpkeRsProvider {};

/// A Rustls HPKE provider backed by hpke-rs.
#[derive(Debug)]
struct HpkeRsProvider {}

impl HpkeProvider for HpkeRsProvider {
    fn start(&self, suite: &HpkeSuite) -> Result<Box<dyn Hpke>, Error> {
        Ok(Box::new(HpkeRs(hpke_rs::Hpke::new(
            hpke_rs::Mode::Base,
            KemAlgorithm::try_from(suite.kem.get_u16()).map_err(other_err)?,
            KdfAlgorithm::try_from(suite.sym.kdf_id.get_u16()).map_err(other_err)?,
            AeadAlgorithm::try_from(suite.sym.aead_id.get_u16()).map_err(other_err)?,
        ))))
    }

    fn supports_suite(&self, suite: &HpkeSuite) -> bool {
        let kem = KemAlgorithm::try_from(suite.kem.get_u16()).ok();
        let kdf = KdfAlgorithm::try_from(suite.sym.kdf_id.get_u16()).ok();
        let aead = AeadAlgorithm::try_from(suite.sym.aead_id.get_u16()).ok();
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
        pk_r: &HpkePublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.0.clone());
        let (enc, ciphertext) = self
            .0
            .seal(&pk_r, info, aad, plaintext, None, None, None)
            .map_err(other_err)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ciphertext))
    }

    fn open(
        &mut self,
        enc: &EncapsulatedSecret,
        sk_r: &HpkePrivateKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.secret_bytes().to_vec());
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
}

fn other_err(err: impl StdError + Send + Sync + 'static) -> Error {
    Error::Other(OtherError(Arc::new(err)))
}
