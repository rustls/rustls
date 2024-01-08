use std::fs::File;

use rustls::crypto::hpke::{HpkePrivateKey, HpkePublicKey, HpkeSuite};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls_provider_example::HPKE_PROVIDER;
use serde::Deserialize;

/// Confirm opne/seal operations work using using the test vectors from [RFC 9180 Appendix A].
///
/// [RFC 9180 Appendix A]: https://www.rfc-editor.org/rfc/rfc9180#TestVectors
#[test]
fn check_test_vectors() {
    for (idx, vec) in test_vectors().into_iter().enumerate() {
        if !vec.applicable() {
            println!("skipping inapplicable vector {idx}");
            continue;
        }

        println!("testing vector {idx}");
        let mut hpke = HPKE_PROVIDER
            .start(&vec.suite())
            .unwrap();
        let pk_r = HpkePublicKey(hex::decode(vec.pk_rm).unwrap());
        let sk_r = HpkePrivateKey::from(hex::decode(vec.sk_rm).unwrap());
        let info = hex::decode(vec.info).unwrap();

        for enc in vec.encryptions {
            let aad = hex::decode(enc.aad).unwrap();
            let pt = hex::decode(enc.pt).unwrap();

            let (enc, ciphertext) = hpke
                .seal(&info, &aad, &pt, &pk_r)
                .unwrap();

            let plaintext = hpke
                .open(&enc, &info, &aad, &ciphertext, &sk_r)
                .unwrap();
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

    fn applicable(&self) -> bool {
        // Only base mode test vectors for supported suites are applicable.
        self.mode == 0 && HPKE_PROVIDER.supports_suite(&self.suite())
    }
}

fn test_vectors() -> Vec<TestVector> {
    serde_json::from_reader(
        &mut File::open("tests/rfc-9180-test-vectors.json")
            .expect("failed to open test vectors data file"),
    )
    .expect("failed to deserialize test vectors")
}
