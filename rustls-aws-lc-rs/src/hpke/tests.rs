use alloc::string::String;
use alloc::{format, vec};
use core::fmt::Debug;
use core::ops::Deref;
use std::println;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

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

    fn setup_test_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn TestOpener + 'static>, Error>;

    fn public_key(&self, secret_key: &HpkePrivateKey) -> Result<HpkePublicKey, Error>;
}

/// An [`HpkeOpener`] that exposes its current sequence number.
pub(super) trait TestOpener: HpkeOpener {
    fn seq_num(&self) -> u128;
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

    fn setup_test_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn TestOpener + 'static>, Error> {
        Ok(Box::new(Opener::new(self, enc, info, secret_key)?))
    }

    fn public_key(&self, secret_key: &HpkePrivateKey) -> Result<HpkePublicKey, Error> {
        self.dh_kem
            .test_only_public_key(secret_key)
    }
}

impl<const KEY_SIZE: usize, const KDF_SIZE: usize> TestOpener for Opener<KEY_SIZE, KDF_SIZE> {
    fn seq_num(&self) -> u128 {
        self.key_schedule.seq_num
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

/// Confirm base mode encapsulation accepts and rejects recipient public keys as expected.
#[test]
fn encap_test_vectors() {
    for (group, hpke) in applicable_groups::<EncapTest>("hpke_x25519_encap_test.json") {
        for test in group.tests {
            println!("testing encap vector {}: {}", test.tc_id, test.comment);
            let should_pass = should_pass(test.result, &test.flags);
            let pk_rm = HpkePublicKey(test.pk_rm.to_vec());
            let sk_rm = test
                .sk_rm
                .as_ref()
                .map(|sk_rm| HpkePrivateKey::from(sk_rm.to_vec()));
            if let Some(sk_rm) = &sk_rm {
                assert_eq!(hpke.public_key(sk_rm).unwrap().0, *test.pk_rm);

                // The vector's own `enc` and `ct` must open to `pt`.
                let enc = EncapsulatedSecret(test.enc.to_vec());
                let pt = hpke
                    .open(&enc, &test.info, &test.aad, &test.ct, sk_rm)
                    .unwrap();
                assert_eq!(pt, *test.pt);
            }

            // Setting up a sealer with an invalid key must fail. Sealing with a sealer
            // that was set up must not fail. Encapsulating with the vector's ephemeral
            // key must produce the expected `enc` and `ct` exactly.
            let deterministic = hpke.setup_test_sealer(&test.info, &pk_rm, &test.sk_em);
            if let Some((enc, mut sealer)) = check(test.tc_id, should_pass, deterministic) {
                assert_eq!(enc.0, *test.enc);
                assert_eq!(
                    sealer
                        .seal(&test.aad, &test.pt)
                        .unwrap(),
                    *test.ct
                );
            }

            // Encapsulating with a fresh ephemeral key must accept or reject the
            // recipient key in the same way and produce output of the same lengths. When
            // the recipient private key is known, the output must also open to the
            // plaintext.
            let randomized = hpke.setup_sealer(&test.info, &pk_rm);
            if let Some((enc, mut sealer)) = check(test.tc_id, should_pass, randomized) {
                let ct = sealer
                    .seal(&test.aad, &test.pt)
                    .unwrap();
                assert_eq!(enc.0.len(), test.enc.len());
                assert_eq!(ct.len(), test.ct.len());
                if let Some(sk_rm) = &sk_rm {
                    let pt = hpke
                        .open(&enc, &test.info, &test.aad, &ct, sk_rm)
                        .unwrap();
                    assert_eq!(pt, *test.pt);
                }
            }
        }
    }
}

/// Confirm single-shot base mode open accepts and rejects messages as expected.
#[test]
fn decrypt_test_vectors() {
    for (group, hpke) in applicable_groups::<DecryptTest>("hpke_x25519_decrypt_test.json") {
        for test in group.tests {
            println!("testing decrypt vector {}: {}", test.tc_id, test.comment);
            let should_pass = should_pass(test.result, &test.flags);
            let sk_rm = HpkePrivateKey::from(test.sk_rm.to_vec());
            assert_eq!(hpke.public_key(&sk_rm).unwrap().0, *test.pk_rm);

            // An invalid vector may be rejected when setting up the opener or when
            // opening, except that an `enc` of the wrong length must be rejected during
            // setup.
            let enc = EncapsulatedSecret(test.enc.to_vec());
            let opener = hpke.setup_opener(&enc, &test.info, &sk_rm);
            if test
                .flags
                .iter()
                .any(|flag| WRONG_LENGTH_ENC_FLAGS.contains(&flag.as_str()))
            {
                assert!(
                    opener.is_err(),
                    "vector {}: wrong length enc accepted",
                    test.tc_id
                );
            }
            let outcome = opener.and_then(|mut opener| opener.open(&test.aad, &test.ct));
            if let Some(pt) = check(test.tc_id, should_pass, outcome) {
                assert_eq!(pt, *test.pt);
            }

            // Vectors sealed by an honest sender include its ephemeral key. Encapsulating
            // with that key must produce `enc` and `ct` exactly.
            let Some(sk_em) = &test.sk_em else {
                continue;
            };
            let pk_rm = HpkePublicKey(test.pk_rm.to_vec());
            let (enc, mut sealer) = hpke
                .setup_test_sealer(&test.info, &pk_rm, sk_em)
                .unwrap();
            assert_eq!(enc.0, *test.enc);
            assert_eq!(
                sealer
                    .seal(&test.aad, &test.pt)
                    .unwrap(),
                *test.ct
            );
        }
    }
}

/// Confirm opening a sequence of messages with one context behaves as expected.
///
/// Each message must be accepted or rejected as the vector says, and a failed open must
/// leave the sequence number unchanged.
#[test]
fn sequence_test_vectors() {
    for (group, hpke) in applicable_groups::<SequenceTest>("hpke_x25519_sequence_test.json") {
        for test in group.tests {
            println!("testing sequence vector {}: {}", test.tc_id, test.comment);
            let sk_rm = HpkePrivateKey::from(test.sk_rm.to_vec());
            assert_eq!(hpke.public_key(&sk_rm).unwrap().0, *test.pk_rm);

            let enc = EncapsulatedSecret(test.enc.to_vec());
            let mut opener = hpke
                .setup_test_opener(&enc, &test.info, &sk_rm)
                .unwrap();
            for decryption in &test.decryptions {
                let seq_num = u128::from(decryption.sequence_number);
                assert_eq!(opener.seq_num(), seq_num);
                let outcome = opener.open(&decryption.aad, &decryption.ct);
                // A successful open advances the sequence number by one and a failed
                // open leaves it unchanged.
                assert_eq!(opener.seq_num(), seq_num + u128::from(outcome.is_ok()));
                let should_pass = should_pass(decryption.result, &test.flags);
                if let Some(pt) = check(test.tc_id, should_pass, outcome) {
                    assert_eq!(pt, *decryption.pt);
                }
            }

            // Sequences sealed by an honest sender include its ephemeral key. Sealing
            // each message in order with that key must produce `enc` and every `ct`
            // exactly.
            let Some(sk_em) = &test.sk_em else {
                continue;
            };
            let pk_rm = HpkePublicKey(test.pk_rm.to_vec());
            let (enc, mut sealer) = hpke
                .setup_test_sealer(&test.info, &pk_rm, sk_em)
                .unwrap();
            assert_eq!(enc.0, *test.enc);
            for decryption in &test.decryptions {
                assert_eq!(decryption.result, TestResult::Valid);
                let ct = sealer
                    .seal(&decryption.aad, &decryption.pt)
                    .unwrap();
                assert_eq!(ct, *decryption.ct);
            }
        }
    }
}

/// Whether a vector with the given result and flags must succeed, as opposed to fail.
///
/// The outcome of `acceptable` vectors is pinned by [`ACCEPTED_FLAGS`] so that a change
/// in behaviour is noticed.
fn should_pass(result: TestResult, flags: &[String]) -> bool {
    match result {
        TestResult::Valid => true,
        TestResult::Invalid => false,
        TestResult::Acceptable => flags
            .iter()
            .all(|flag| ACCEPTED_FLAGS.contains(&flag.as_str())),
    }
}

/// Check the outcome of an operation against the expected result.
///
/// The value of a successful outcome is returned for further verification.
fn check<T: Debug>(tc_id: u32, should_pass: bool, outcome: Result<T, Error>) -> Option<T> {
    match (should_pass, outcome) {
        (true, Ok(value)) => Some(value),
        (false, Err(_)) => None,
        (true, Err(err)) => panic!("vector {tc_id}: unexpected failure: {err:?}"),
        (false, Ok(value)) => panic!("vector {tc_id}: unexpected success: {value:?}"),
    }
}

/// Load the test groups from the named vector file.
///
/// Each group is paired with the supported suite it exercises. Groups for unsupported
/// suites are skipped.
fn applicable_groups<T: DeserializeOwned>(
    file: &str,
) -> Vec<(TestGroup<T>, &'static dyn TestHpke)> {
    let vectors = serde_json::from_slice::<TestVectors<T>>(
        &std::fs::read(format!("../rustls-provider-test/tests/wycheproof/{file}"))
            .expect("failed to open test vectors data file"),
    )
    .expect("failed to deserialize test vectors");
    assert_eq!(
        vectors.number_of_tests,
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>()
    );

    let groups = vectors
        .test_groups
        .into_iter()
        .filter_map(|group| match lookup_suite(group.suite()) {
            Some(hpke) => Some((group, hpke)),
            None => {
                println!(
                    "skipping {file} group for unsupported suite {:?}",
                    group.suite()
                );
                None
            }
        })
        .collect::<Vec<_>>();

    // Only FIPS builds, which omit the X25519 suites, are expected to skip every group.
    assert!(
        cfg!(feature = "fips") || !groups.is_empty(),
        "no applicable groups in {file}"
    );
    groups
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVectors<T> {
    number_of_tests: usize,
    test_groups: Vec<TestGroup<T>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup<T> {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    tests: Vec<T>,
}

impl<T> TestGroup<T> {
    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::from(self.kem_id),
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::from(self.kdf_id),
                aead_id: HpkeAead::from(self.aead_id),
            },
        }
    }
}

/// A `SetupBaseS` and `Seal` test from `hpke_*_encap_test.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapTest {
    tc_id: u32,
    comment: String,
    pk_rm: HexBytes,
    sk_em: HexBytes,
    sk_rm: Option<HexBytes>,
    info: HexBytes,
    aad: HexBytes,
    pt: HexBytes,
    enc: HexBytes,
    ct: HexBytes,
    result: TestResult,
    flags: Vec<String>,
}

/// A `SetupBaseR` and `Open` test from `hpke_*_decrypt_test.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptTest {
    tc_id: u32,
    comment: String,
    sk_rm: HexBytes,
    pk_rm: HexBytes,
    sk_em: Option<HexBytes>,
    info: HexBytes,
    aad: HexBytes,
    enc: HexBytes,
    ct: HexBytes,
    pt: HexBytes,
    result: TestResult,
    flags: Vec<String>,
}

/// A `SetupBaseR` and ordered multi-message `Open` test from `hpke_*_sequence_test.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SequenceTest {
    tc_id: u32,
    comment: String,
    sk_rm: HexBytes,
    pk_rm: HexBytes,
    sk_em: Option<HexBytes>,
    info: HexBytes,
    enc: HexBytes,
    decryptions: Vec<Decryption>,
    flags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Decryption {
    sequence_number: u64,
    aad: HexBytes,
    ct: HexBytes,
    pt: HexBytes,
    result: TestResult,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

/// A byte string, hex encoded in the test vector files.
struct HexBytes(Vec<u8>);

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex::decode(String::deserialize(deserializer)?)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Deref for HexBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Flags of `acceptable` vectors that the implementation accepts rather than rejects.
///
/// RFC 9180 leaves these to the implementation. aws-lc-rs follows RFC 7748 literally,
/// masking the high bit of a non-canonical X25519 key and computing with points on the
/// twist, and no length limit is applied to `info`.
const ACCEPTED_FLAGS: &[&str] = &[
    "LongInfo",
    "NonCanonicalEncLargeOrder",
    "NonCanonicalPkRmLargeOrder",
    "Twist",
];

/// Flags of vectors whose `enc` is not `Nenc` bytes long.
///
/// RFC 9180 requires such an `enc` to be rejected when the opener is set up. Checking only
/// that the open fails would also pass an implementation that accepts the malformed `enc`,
/// derives keys from it and then fails to authenticate the ciphertext.
const WRONG_LENGTH_ENC_FLAGS: &[&str] = &["WrongLengthEnc", "EncTrailingByteInContext"];
