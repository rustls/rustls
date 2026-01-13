use std::fs::File;

use rustls::crypto::hpke::{
    Hpke, HpkeAead, HpkeKdf, HpkeKem, HpkePrivateKey, HpkePublicKey, HpkeSuite,
    HpkeSymmetricCipherSuite,
};
use serde::Deserialize;

/// Confirm open/seal operations work using the test vectors from [RFC 9180 Appendix A].
///
/// [RFC 9180 Appendix A]: https://www.rfc-editor.org/rfc/rfc9180#TestVectors
#[test]
fn check_test_vectors() {
    for (idx, vec) in test_vectors().into_iter().enumerate() {
        let Some(hpke_pairs) = vec.applicable() else {
            println!("skipping inapplicable vector {idx}");
            continue;
        };

        println!("testing vector {idx}");
        let pk_r = HpkePublicKey(hex::decode(vec.pk_rm).unwrap());
        let sk_r = HpkePrivateKey::from(hex::decode(vec.sk_rm).unwrap());
        let info = hex::decode(vec.info).unwrap();

        for enc in vec.encryptions {
            let aad = hex::decode(enc.aad).unwrap();
            let pt = hex::decode(enc.pt).unwrap();

            for (sealer, opener) in &hpke_pairs {
                let (enc, ciphertext) = sealer
                    .seal(&info, &aad, &pt, &pk_r)
                    .unwrap();

                let plaintext = opener
                    .open(&enc, &info, &aad, &ciphertext, &sk_r)
                    .unwrap();
                assert_eq!(plaintext, pt);
            }
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
    encryptions: Vec<TestEncryption>,
}

#[derive(Deserialize, Debug)]
struct TestEncryption {
    aad: String,
    pt: String,
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

    fn applicable(&self) -> Option<Vec<(&'static dyn Hpke, &'static dyn Hpke)>> {
        // Only base mode test vectors for supported suites are applicable.
        if self.mode != 0 {
            return None;
        }

        match (
            Self::lookup_suite(self.suite(), rustls_aws_lc_rs::hpke::ALL_SUPPORTED_SUITES),
            Self::lookup_suite(self.suite(), provider_example::hpke::ALL_SUPPORTED_SUITES),
        ) {
            // Both providers support the suite. Test against themselves, and each other.
            (Some(aws_suite), Some(hpke_rs_suite)) => Some(vec![
                (aws_suite, aws_suite),
                (hpke_rs_suite, hpke_rs_suite),
                (aws_suite, hpke_rs_suite),
                (hpke_rs_suite, aws_suite),
            ]),

            // aws-lc-rs supported the suite, not hpke-rs, test against itself
            (Some(aws_suite), None) => Some(vec![(aws_suite, aws_suite)]),

            // hpke-rs supported the suite, not AWS-LC-RS, test against itself
            //
            // Note: presently there are no suites hpke-rs supports that aws-lc-rs doesn't. This
            //       is future-proofing.
            (None, Some(hpke_rs_suite)) => Some(vec![(hpke_rs_suite, hpke_rs_suite)]),

            // Neither provider supported the suite - nothing to do.
            (None, None) => None,
        }
    }

    fn lookup_suite(
        suite: HpkeSuite,
        supported: &[&'static dyn Hpke],
    ) -> Option<&'static dyn Hpke> {
        supported
            .iter()
            .find(|s| s.suite() == suite)
            .copied()
    }
}

fn test_vectors() -> Vec<TestVector> {
    serde_json::from_reader(
        &mut File::open("tests/rfc-9180-test-vectors.json")
            .expect("failed to open test vectors data file"),
    )
    .expect("failed to deserialize test vectors")
}
