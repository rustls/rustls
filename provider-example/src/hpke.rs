use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::Error;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead as HpkeAeadId, HpkeKdf as HpkeKdfId, HpkeKem as HpkeKemId,
    HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite, HpkeSymmetricCipherSuite,
};

use super::other_err;

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

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let kem_algorithm = match self.0.kem {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => KemAlgorithm::DhKemP256,
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => KemAlgorithm::DhKem25519,
            _ => {
                // Safety: we don't expose HpkeRs static instances for unsupported algorithms.
                unimplemented!()
            }
        };

        let (public_key, secret_key) =
            HpkeRustCrypto::kem_key_gen(kem_algorithm, &mut HpkeRustCrypto::prng())
                .map_err(other_err)?;

        Ok((HpkePublicKey(public_key), HpkePrivateKey::from(secret_key)))
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

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use rustls::pki_types::FipsStatus;

    use super::*;

    #[test]
    fn smoke_test() {
        for suite in ALL_SUPPORTED_SUITES {
            _ = format!("{suite:?}"); // HpkeRs suites should be Debug.

            // We should be able to generate a random keypair.
            let (pk, sk) = suite.generate_key_pair().unwrap();

            // Info value corresponds to the first RFC 9180 base mode test vector.
            let info = &[
                0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69,
                0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e,
            ][..];

            // We should be able to set up a sealer.
            let (enc, mut sealer) = suite.setup_sealer(info, &pk).unwrap();

            _ = format!("{sealer:?}"); // Sealer should be Debug.

            // Setting up a sealer with an invalid public key should fail.
            let bad_setup_res = suite.setup_sealer(info, &HpkePublicKey(vec![]));
            assert!(matches!(bad_setup_res.unwrap_err(), Error::Other(_)));

            // We should be able to seal some plaintext.
            let aad = &[0xC0, 0xFF, 0xEE];
            let pt = &[0xF0, 0x0D];
            let ct = sealer.seal(aad, pt).unwrap();

            // We should be able to set up an opener.
            let mut opener = suite
                .setup_opener(&enc, info, &sk)
                .unwrap();
            _ = format!("{opener:?}"); // Opener should be Debug.

            // Setting up an opener with an invalid private key should fail.
            let bad_key_res = suite.setup_opener(&enc, info, &HpkePrivateKey::from(vec![]));
            assert!(matches!(bad_key_res.unwrap_err(), Error::Other(_)));

            // Opening the plaintext should work with the correct opener and aad.
            let pt_prime = opener.open(aad, &ct).unwrap();
            assert_eq!(pt_prime, pt);

            // Opening the plaintext with the correct opener and wrong aad should fail.
            let open_res = opener.open(&[0x0], &ct);
            assert!(matches!(open_res.unwrap_err(), Error::Other(_)));

            // Opening the plaintext with the wrong opener should fail.
            let mut sk_rm_prime = sk.secret_bytes().to_vec();
            sk_rm_prime[10] ^= 0xFF; // Corrupt a byte of the private key.
            let mut opener_two = suite
                .setup_opener(&enc, info, &HpkePrivateKey::from(sk_rm_prime))
                .unwrap();
            let open_res = opener_two.open(aad, &ct);
            assert!(matches!(open_res.unwrap_err(), Error::Other(_)));
        }
    }

    #[test]
    fn test_fips() {
        // None of the rust-crypto backed hpke-rs suites should be considered FIPS approved.
        assert!(
            ALL_SUPPORTED_SUITES
                .iter()
                .all(|suite| matches!(suite.fips(), FipsStatus::Unvalidated))
        );
    }
}
