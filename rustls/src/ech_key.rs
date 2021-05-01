use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::*;
use crate::msgs::handshake::*;

use hpke::kex::Serializable;
use hpke::{kem, Kem};
use rand::{rngs::StdRng, SeedableRng};
use webpki::DnsNameRef;

pub type HpkePrivateKey = Vec<u8>;
pub type HpkePublicKey = Vec<u8>;

#[derive(Clone, Debug)]
pub struct HpkeKeyPair {
    pub kem_id: KEM,
    pub private_key: HpkePrivateKey,
    pub public_key: HpkePublicKey,
}

impl HpkeKeyPair {
    #[allow(dead_code)]
    pub fn new(kem_id: KEM) -> HpkeKeyPair {
        let mut csprng = StdRng::from_entropy();
        let (private_key, public_key) = match kem_id {
            KEM::DHKEM_P256_HKDF_SHA256 => {
                let (private, public) = kem::DhP256HkdfSha256::gen_keypair(&mut csprng);
                (
                    private.to_bytes().as_slice().to_vec(),
                    public.to_bytes().as_slice().to_vec(),
                )
            }
            KEM::DHKEM_P384_HKDF_SHA384 => unimplemented!(),
            KEM::DHKEM_P521_HKDF_SHA512 => unimplemented!(),
            KEM::DHKEM_X25519_HKDF_SHA256 => {
                let (private, public) = kem::X25519HkdfSha256::gen_keypair(&mut csprng);
                (
                    private.to_bytes().as_slice().to_vec(),
                    public.to_bytes().as_slice().to_vec(),
                )
            }
            KEM::DHKEM_X448_HKDF_SHA512 => unimplemented!(),
            _ => unreachable!(),
        };
        HpkeKeyPair {
            kem_id,
            private_key,
            public_key,
        }
    }
}

/// A private key paired with an ECHConfig, which contains the corresponding public key.
#[derive(Clone, Debug)]
pub struct EchKey {
    pub private_key: HpkePrivateKey,
    pub config: ECHConfig,
}

impl EchKey {
    // TODO: Reconsider this API. This is just enough to get this feature working.
    #[allow(dead_code)]
    pub fn new(config_id: u8, key_pair: HpkeKeyPair, domain: DnsNameRef) -> EchKey {
        EchKey {
            private_key: key_pair.private_key,
            config: ECHConfig {
                version: ECHVersion::V10,
                contents: ECHConfigContents {
                    hpke_key_config: HpkeKeyConfig {
                        config_id,
                        hpke_kem_id: key_pair.kem_id,
                        hpke_public_key: PayloadU16(key_pair.public_key),
                        hpke_symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite::default()],
                    },
                    maximum_name_length: 255,
                    public_name: PayloadU16::new(domain.as_ref().to_vec()),
                    extensions: PayloadU16::empty(),
                },
            },
        }
    }
}

impl Codec for EchKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        PayloadU16(self.private_key.clone()).encode(bytes);
        self.config.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<EchKey> {
        let private_key = PayloadU16::read(r)?;
        let config_payload = PayloadU16::read(r)?;
        let config = ECHConfig::read(&mut Reader::init(&config_payload.into_inner()))?;
        Some(EchKey {
            private_key: private_key.into_inner(),
            config,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gen_p256() {
        let p256 = HpkeKeyPair::new(KEM::DHKEM_P256_HKDF_SHA256);
        assert_eq!(p256.private_key.len(), 32);
        assert_eq!(p256.public_key.len(), 65);
    }

    #[test]
    #[should_panic]
    fn test_gen_p384() {
        let _p384 = HpkeKeyPair::new(KEM::DHKEM_P384_HKDF_SHA384);
    }

    #[test]
    #[should_panic]
    fn test_gen_p521() {
        let _p521 = HpkeKeyPair::new(KEM::DHKEM_P521_HKDF_SHA512);
    }

    #[test]
    fn test_gen_x25519() {
        let x25519 = HpkeKeyPair::new(KEM::DHKEM_X25519_HKDF_SHA256);
        assert_eq!(x25519.private_key.len(), 32);
        assert_eq!(x25519.public_key.len(), 32);
    }

    #[test]
    #[should_panic]
    fn test_gen_x448() {
        let _x448 = HpkeKeyPair::new(KEM::DHKEM_X448_HKDF_SHA512);
    }

    #[test]
    fn test_create_default_ech_config() {
        let x25519 = HpkeKeyPair::new(KEM::DHKEM_X25519_HKDF_SHA256);
        let domain = webpki::DnsNameRef::try_from_ascii_str("example.com").unwrap();
        let key = EchKey::new(0, x25519.clone(), domain);
        assert_eq!(key.private_key, x25519.private_key);
        assert_eq!(key.config.version, ECHVersion::V10);
        assert_eq!(
            key.config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            KEM::DHKEM_X25519_HKDF_SHA256
        );
        let suites = key
            .config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites;
        assert_eq!(suites[0].hpke_aead_id, AEAD::AES_128_GCM);
        assert_eq!(suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
    }

    // Some test data from https://github.com/cloudflare/go/blob/cf/src/crypto/tls/ech_test.go
    const ECH_CONFIGS: &str = "AJD+CgBEAAAgACCLVO6NYnbfqTVUAx5GfKwpsOKDEukOz8AZ0SjArwqIGQAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAD+CgBEAQAgACBnVG7W7IZfo30dizn+kATcrBRdEMEcPQF2dryg/i5UTAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
    const ECH_KEYS: &str = "ACDhS0q2cTU1Qzi6hPM4BQ/HLnbEUZyWdY2GbmS0DVkumgBIAfUARAAAIAAgi1TujWJ236k1VAMeRnysKbDigxLpDs/AGdEowK8KiBkABAABAAEAAAATY2xvdWRmbGFyZS1lc25pLmNvbQAAACBmNj/zQe6OT/MR/MM39G6kwMJCJEXpdvTAkbdHErlgXwBIAfUARAEAIAAgZ1Ru1uyGX6N9HYs5/pAE3KwUXRDBHD0Bdna8oP4uVEwABAABAAEAAAATY2xvdWRmbGFyZS1lc25pLmNvbQAA";

    fn test_decode_for_kem(config: &ECHConfig, kem: KEM) {
        assert_eq!(config.version, ECHVersion::V10);
        let name = String::from_utf8(
            config
                .contents
                .public_name
                .clone()
                .into_inner(),
        )
        .unwrap();
        assert_eq!("cloudflare-esni.com", name.as_str());
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            kem
        );
        let cipher_suites = &config
            .contents
            .hpke_key_config
            .hpke_symmetric_cipher_suites;
        assert_eq!(cipher_suites.len(), 1);
        assert_eq!(cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
        assert_eq!(cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    }

    fn decode_ech_keys() -> Vec<EchKey> {
        let mut keys = vec![];
        let bytes = base64::decode(&ECH_KEYS).unwrap();
        let reader = &mut Reader::init(&bytes);
        while reader.any_left() {
            keys.push(EchKey::read(reader).unwrap());
        }
        keys
    }

    #[test]
    fn test_sign_and_decode() {
        let bytes = base64::decode(&ECH_CONFIGS).unwrap();
        let configs = ECHConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 2);
        for config in &configs {
            test_decode_for_kem(&config, KEM::DHKEM_X25519_HKDF_SHA256);
        }
        let keys = decode_ech_keys();
        assert_eq!(keys.len(), 2);
    }
}
