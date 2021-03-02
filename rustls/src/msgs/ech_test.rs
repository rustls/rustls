use base64;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{ECHConfigs, ECHConfig};
use crate::msgs::enums::{ECHVersion, KEM, KDF, AEAD};
use crate::msgs::ech::{HPKEKeyPair, ECHKey};

#[test]
fn test_echconfig_serialization() {
    // An ECHConfig record from Cloudflare for "crypto.cloudflare.com"
    let base64_echconfigs = "AEf+CQBDABNjbG91ZGZsYXJlLWVzbmkuY29tACCD91Ovu3frIsjhFKo0I1fPd/a09nzKMrjC9GZV3NvrfQAgAAQAAQABAAAAAA==";
    let bytes = base64::decode(&base64_echconfigs).unwrap();
    let configs = ECHConfigs::read(&mut Reader::init(&bytes)).unwrap();
    assert_eq!(configs.len(), 1);
    let config: &ECHConfig = &configs[0];
    assert_eq!(config.version, ECHVersion::V9);
    let name = String::from_utf8(config.contents.public_name.clone().into_inner()).unwrap();
    assert_eq!("cloudflare-esni.com", name.as_str());
    assert_eq!(config.contents.hpke_kem_id, KEM::DHKEM_X25519_HKDF_SHA256);
    assert_eq!(config.contents.ech_cipher_suites.len(), 1);
    assert_eq!(config.contents.ech_cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
    assert_eq!(config.contents.ech_cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    let mut output = Vec::new();
    configs.encode(&mut output);
    assert_eq!(base64_echconfigs, base64::encode(&output));
}

#[test]
fn test_gen_p256() {
    let p256 = HPKEKeyPair::new(KEM::DHKEM_P256_HKDF_SHA256);
    assert_eq!(p256.private_key.len(), 32);
    assert_eq!(p256.public_key.len(), 65);
}

#[test]
#[should_panic]
fn test_gen_p384() {
    let _p384 = HPKEKeyPair::new(KEM::DHKEM_P384_HKDF_SHA384);
}

#[test]
#[should_panic]
fn test_gen_p521() {
    let _p521 = HPKEKeyPair::new(KEM::DHKEM_P521_HKDF_SHA512);
}

#[test]
fn test_gen_x25519() {
    let x25519 = HPKEKeyPair::new(KEM::DHKEM_X25519_HKDF_SHA256);
    assert_eq!(x25519.private_key.len(), 32);
    assert_eq!(x25519.public_key.len(), 32);
}

#[test]
#[should_panic]
fn test_gen_x448() {
    let _x448 = HPKEKeyPair::new(KEM::DHKEM_X448_HKDF_SHA512);
}

#[test]
fn test_create_default_ech_config() {
    let x25519 = HPKEKeyPair::new(KEM::DHKEM_X25519_HKDF_SHA256);
    let domain = webpki::DNSNameRef::try_from_ascii_str("example.com").unwrap();
    let key = ECHKey::new(x25519.clone(), domain);
    assert_eq!(key.private_key, x25519.private_key);
    assert_eq!(key.config.version, ECHVersion::V9);
    assert_eq!(key.config.contents.hpke_kem_id, KEM::DHKEM_X25519_HKDF_SHA256);
    assert_eq!(key.config.contents.ech_cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    assert_eq!(key.config.contents.ech_cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
}

// Some test data from https://github.com/cloudflare/go/blob/cf/src/crypto/tls/ech_test.go
const ECH_CONFIGS: &str = "AMf+CQBPABNjbG91ZGZsYXJlLWVzbmkuY29tACBFy97nrxkmIILJkm/CsjHQUihIJCKHOx7kQkzfq/3wFwAgABAAAQABAAEAAwACAAEAAgADAAAAAP4JAHAAE2Nsb3VkZmxhcmUtZXNuaS5jb20AQQSlUJ59U4Ini8sB7pdc/H93rD/K7io/ZqwR8b9phx6CA0VFLXd/YWF+ZOwWxy1Gyt+LQpHh8+UTjr0/Fmc0snzAABAAEAABAAEAAQADAAIAAQACAAMAAAAA";
//const SIGNING_KEY: &str = "MHcCAQEEIIJsLXmfzw6FDlqyRRLhY6lVB6ws5ewjUQjnS4DXsQ60oAoGCCqGSM49AwEHoUQDQgAElq+qE01Z87KIPHWdEAk0cWssHkRnS4aQCDfstoxDIWQ4rMwHvrWGFy/vytRwyjhHuX9ntc5ArCpwbAmY+oW/4w==";
const ECH_KEYS: &str = "ACA/SG/gkFYqQ0vvrgz8CRtn8QBhUdmJIHrpLRa4MHbjpgBT/gkATwATY2xvdWRmbGFyZS1lc25pLmNvbQAgRcve568ZJiCCyZJvwrIx0FIoSCQihzse5EJM36v98BcAIAAQAAEAAQABAAMAAgABAAIAAwAAAAAAIOpdZ5c3Q1EIq5eztNrW+7GcUiPKPDhm6JqulMAt5NLmAHT+CQBwABNjbG91ZGZsYXJlLWVzbmkuY29tAEEEpVCefVOCJ4vLAe6XXPx/d6w/yu4qP2asEfG/aYceggNFRS13f2FhfmTsFsctRsrfi0KR4fPlE469PxZnNLJ8wAAQABAAAQABAAEAAwACAAEAAgADAAAAAA==";

fn test_decode_for_kem(config: &ECHConfig, kem: KEM) {
    assert_eq!(config.version, ECHVersion::V9);
    let name = String::from_utf8(config.contents.public_name.clone().into_inner()).unwrap();
    assert_eq!("cloudflare-esni.com", name.as_str());
    assert_eq!(config.contents.hpke_kem_id, kem);
    assert_eq!(config.contents.ech_cipher_suites.len(), 4);
    let cipher_suites = &config.contents.ech_cipher_suites;
    assert_eq!(cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
    assert_eq!(cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    assert_eq!(cipher_suites[1].hpke_kdf_id, KDF::HKDF_SHA256);
    assert_eq!(cipher_suites[1].hpke_aead_id, AEAD::CHACHA20_POLY_1305);
    assert_eq!(cipher_suites[2].hpke_kdf_id, KDF::HKDF_SHA384);
    assert_eq!(cipher_suites[2].hpke_aead_id, AEAD::AES_128_GCM);
    assert_eq!(cipher_suites[3].hpke_kdf_id, KDF::HKDF_SHA384);
    assert_eq!(cipher_suites[3].hpke_aead_id, AEAD::CHACHA20_POLY_1305);
}

fn decode_ech_keys() -> Vec<ECHKey> {
    let mut keys = vec![];
    let bytes = base64::decode(&ECH_KEYS).unwrap();
    let reader = &mut Reader::init(&bytes);
    while reader.any_left() {
        keys.push(ECHKey::read(reader).unwrap());
    }
    keys
}

#[test]
fn test_sign_and_decode() {
    let bytes = base64::decode(&ECH_CONFIGS).unwrap();
    let configs = ECHConfigs::read(&mut Reader::init(&bytes)).unwrap();
    assert_eq!(configs.len(), 2);
    let x25519_config = &configs[0];
    test_decode_for_kem(x25519_config, KEM::DHKEM_X25519_HKDF_SHA256);
    let p256_config = &configs[1];
    test_decode_for_kem(p256_config, KEM::DHKEM_P256_HKDF_SHA256);

    let keys = decode_ech_keys();
    assert_eq!(keys.len(), 2);
}
