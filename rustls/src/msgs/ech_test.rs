use base64;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{ECHConfigs, ECHConfig};
use crate::msgs::enums::{ECHVersion, KEM, KDF, AEAD};
use crate::msgs::ech::{HPKEKeyPair, ECHKey};
use std::convert::TryFrom;

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