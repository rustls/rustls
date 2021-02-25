use base64;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{ECHConfigs, ECHConfig};
use crate::msgs::enums::{ECHVersion, KEM, KDF, AEAD};

#[test]
fn test_echconfig_serialization() {
    // An ECHConfig record from Cloudflare for "crypto.cloudflare.com"
    let base64_echconfigs = "AEf+CQBDABNjbG91ZGZsYXJlLWVzbmkuY29tACCD91Ovu3frIsjhFKo0I1fPd/a09nzKMrjC9GZV3NvrfQAgAAQAAQABAAAAAA==";
    let bytes = base64::decode(&base64_echconfigs).unwrap();
    let configs = ECHConfigs::read(&mut Reader::init(&bytes)).unwrap();
    let config: &ECHConfig = &configs[0];
    assert_eq!(config.version, ECHVersion::V9);
    assert_eq!(config.length, 67);
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
