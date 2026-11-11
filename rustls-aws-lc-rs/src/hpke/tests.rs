use alloc::string::String;
use alloc::{format, vec};
use std::println;

use serde::Deserialize;

use super::*;

#[test]
fn smoke_test() {
    for suite in ALL_SUPPORTED_SUITES {
        _ = format!("{suite:?}"); // HpkeAwsLcRs suites should be Debug.

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

#[cfg(not(feature = "fips"))] // Ensure all supported suites are available to test.
#[test]
fn test_fips() {
    let testcases: &[(&dyn Hpke, bool)] = &[
        // FIPS compatible.
        (DH_KEM_P256_HKDF_SHA256_AES_128, true),
        (DH_KEM_P256_HKDF_SHA256_AES_256, true),
        (DH_KEM_P384_HKDF_SHA384_AES_128, true),
        (DH_KEM_P384_HKDF_SHA384_AES_256, true),
        (DH_KEM_P521_HKDF_SHA512_AES_128, true),
        (DH_KEM_P521_HKDF_SHA512_AES_256, true),
        // AEAD is not FIPS compatible.
        (DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY1305, false),
        (DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY1305, false),
        (DH_KEM_P521_HKDF_SHA512_CHACHA20_POLY1305, false),
        // KEM is not FIPS compatible.
        (DH_KEM_X25519_HKDF_SHA256_AES_128, false),
        (DH_KEM_X25519_HKDF_SHA256_AES_256, false),
        (DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305, false),
    ];
    for (suite, allowed) in testcases {
        match allowed {
            true => assert_eq!(suite.fips(), crate::fips()),
            false => assert_eq!(
                suite.fips(),
                FipsStatus::Unvalidated,
                "expected non-FIPS compatible suite"
            ),
        }
    }
}

#[test]
fn failed_open_does_not_consume_sequence() {
    for suite in ALL_SUPPORTED_SUITES {
        let (pk, sk) = suite.generate_key_pair().unwrap();
        let (enc, mut sealer) = suite
            .setup_sealer(b"example", &pk)
            .unwrap();
        let ct0 = sealer
            .seal(b"aad", b"message 0")
            .unwrap();
        let ct1 = sealer
            .seal(b"aad", b"message 1")
            .unwrap();

        let mut opener = suite
            .setup_opener(&enc, b"example", &sk)
            .unwrap();
        assert!(opener.open(b"wrong aad", &ct0).is_err());
        assert_eq!(opener.open(b"aad", &ct0).unwrap(), b"message 0");
        assert_eq!(opener.open(b"aad", &ct1).unwrap(), b"message 1");
    }
}

#[test]
fn seq_num_does_not_wrap() {
    let max_seq_num = (1u128 << (NONCE_LEN * 8)) - 1;
    let mut ks = KeySchedule::<AES_128_KEY_LEN> {
        aead: &aead::AES_128_GCM,
        key: AeadKey([0u8; AES_128_KEY_LEN]),
        base_nonce: [0u8; NONCE_LEN],
        seq_num: max_seq_num,
    };
    assert!(ks.increment_seq_num().is_err());
    assert_eq!(ks.seq_num, max_seq_num);
}

#[test]
fn seal_at_the_sequence_limit_fails_without_advancing() {
    let max_seq_num = (1u128 << (NONCE_LEN * 8)) - 1;
    let mut sealer = Sealer::<AES_128_KEY_LEN, 32> {
        key_schedule: KeySchedule {
            aead: &aead::AES_128_GCM,
            key: AeadKey([0u8; AES_128_KEY_LEN]),
            base_nonce: [0u8; NONCE_LEN],
            seq_num: max_seq_num,
        },
    };
    assert!(sealer.seal(b"aad", b"message").is_err());
    assert_eq!(sealer.key_schedule.seq_num, max_seq_num);
}

// Ensure open propagates the sequence-limit error even after successful authentication.
#[test]
fn open_at_the_sequence_limit_fails_without_advancing() {
    let max_seq_num = (1u128 << (NONCE_LEN * 8)) - 1;
    let mut opener = Opener::<AES_128_KEY_LEN, 32> {
        key_schedule: KeySchedule {
            aead: &aead::AES_128_GCM,
            key: AeadKey([0u8; AES_128_KEY_LEN]),
            base_nonce: [0u8; NONCE_LEN],
            seq_num: max_seq_num,
        },
    };

    // Seal directly: the HPKE sealer refuses to produce a ciphertext at this
    // sequence. With an all-zero base nonce, the nonce equals the sequence number
    // encoded as 12 bytes. At the maximum sequence, every byte is 0xff.
    let key =
        LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &[0u8; AES_128_KEY_LEN]).unwrap());
    let mut ciphertext = b"message".to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0xff; NONCE_LEN]),
        Aad::from(b"aad"),
        &mut ciphertext,
    )
    .unwrap();

    assert!(
        opener
            .open(b"aad", &ciphertext)
            .is_err()
    );
    assert_eq!(opener.key_schedule.seq_num, max_seq_num);
}

/// Confirm open/seal operations work using the test vectors from [RFC 9180 Appendix A].
///
/// [RFC 9180 Appendix A]: https://www.rfc-editor.org/info/rfc9180#TestVectors
#[test]
fn check_test_vectors() {
    for (idx, vec) in test_vectors().into_iter().enumerate() {
        let Some(hpke) = vec.applicable() else {
            println!("skipping inapplicable vector {idx}");
            continue;
        };

        println!("testing vector {idx}");
        let pk_r = HpkePublicKey(hex::decode(vec.pk_rm).unwrap());
        let sk_r = HpkePrivateKey::from(hex::decode(vec.sk_rm).unwrap());
        let sk_em = hex::decode(vec.sk_em).unwrap();
        let info = hex::decode(vec.info).unwrap();
        let expected_enc = hex::decode(vec.enc).unwrap();

        let (enc, mut sealer) = hpke
            .setup_test_sealer(&info, &pk_r, &sk_em)
            .unwrap();
        assert_eq!(enc.0, expected_enc);

        let mut opener = hpke
            .setup_opener(&enc, &info, &sk_r)
            .unwrap();

        for test_encryption in vec.encryptions {
            let aad = hex::decode(test_encryption.aad).unwrap();
            let pt = hex::decode(test_encryption.pt).unwrap();
            let expected_ct = hex::decode(test_encryption.ct).unwrap();

            let ciphertext = sealer.seal(&aad, &pt).unwrap();
            assert_eq!(ciphertext, expected_ct);

            let plaintext = opener.open(&aad, &ciphertext).unwrap();
            assert_eq!(plaintext, pt);
        }
    }
}

#[derive(Deserialize, Debug)]
struct TestVector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename(deserialize = "pkRm"))]
    pk_rm: String,
    #[serde(rename(deserialize = "skRm"))]
    sk_rm: String,
    #[serde(rename(deserialize = "skEm"))]
    sk_em: String,
    enc: String,
    encryptions: Vec<TestEncryption>,
}

#[derive(Deserialize, Debug)]
struct TestEncryption {
    aad: String,
    pt: String,
    ct: String,
}

impl TestVector {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::from(self.kem_id),
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::from(self.kdf_id),
                aead_id: HpkeAead::from(self.aead_id),
            },
        }
    }

    fn applicable(&self) -> Option<&'static dyn TestHpke> {
        // Only base mode test vectors for supported suites are applicable.
        if self.mode != 0 {
            return None;
        }

        lookup_suite(self.suite())
    }
}

fn test_vectors() -> Vec<TestVector> {
    serde_json::from_slice(
        &std::fs::read("../rustls-provider-test/tests/rfc-9180-test-vectors.json")
            .expect("failed to open test vectors data file"),
    )
    .expect("failed to deserialize test vectors")
}

/// Find the supported suite matching `suite`, if any.
pub(super) fn lookup_suite(suite: HpkeSuite) -> Option<&'static dyn TestHpke> {
    TEST_SUITES
        .iter()
        .find(|s| s.suite() == suite)
        .copied()
}

pub(super) trait TestHpke: Hpke {
    fn setup_test_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
        sk_em: &[u8],
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error>;
}

impl<const KEY_SIZE: usize, const KDF_SIZE: usize> TestHpke for HpkeAwsLcRs<KEY_SIZE, KDF_SIZE> {
    fn setup_test_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
        sk_em: &[u8],
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (encap, sealer) = Sealer::test_only_new(self, info, pub_key, sk_em)?;
        Ok((encap, Box::new(sealer)))
    }
}

static TEST_SUITES: &[&dyn TestHpke] = &[
    DH_KEM_P256_HKDF_SHA256_AES_128,
    DH_KEM_P256_HKDF_SHA256_AES_256,
    #[cfg(not(feature = "fips"))]
    DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    DH_KEM_P384_HKDF_SHA384_AES_128,
    DH_KEM_P384_HKDF_SHA384_AES_256,
    #[cfg(not(feature = "fips"))]
    DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY1305,
    DH_KEM_P521_HKDF_SHA512_AES_128,
    DH_KEM_P521_HKDF_SHA512_AES_256,
    #[cfg(not(feature = "fips"))]
    DH_KEM_P521_HKDF_SHA512_CHACHA20_POLY1305,
    #[cfg(not(feature = "fips"))]
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    #[cfg(not(feature = "fips"))]
    DH_KEM_X25519_HKDF_SHA256_AES_256,
    #[cfg(not(feature = "fips"))]
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];
