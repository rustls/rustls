use base64;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{ECHConfigList, ECHConfig};
use crate::msgs::enums::{ECHVersion, KEM, KDF, AEAD};

#[test]
fn test_echconfig_serialization() {
    // An ECHConfigList record from Cloudflare for "crypto.cloudflare.com", draft-10
    let base64_echconfigs = "AEj+CgBEuwAgACCYKvleXJQ16RUURAsG1qTRN70ob5ewCDH6NuzE97K8MAAEAAEAAQAAABNjbG91ZGZsYXJlLWVzbmkuY29tAAA=";
    let bytes = base64::decode(&base64_echconfigs).unwrap();
    let configs = ECHConfigList::read(&mut Reader::init(&bytes)).unwrap();
    assert_eq!(configs.len(), 1);
    let config: &ECHConfig = &configs[0];
    assert_eq!(config.version, ECHVersion::V10);
    let name = String::from_utf8(config.contents.public_name.clone().into_inner()).unwrap();
    assert_eq!("cloudflare-esni.com", name.as_str());
    assert_eq!(config.contents.hpke_key_config.hpke_kem_id, KEM::DHKEM_X25519_HKDF_SHA256);
    assert_eq!(config.contents.hpke_key_config.hpke_symmetric_cipher_suites.len(), 1);
    assert_eq!(config.contents.hpke_key_config.hpke_symmetric_cipher_suites[0].hpke_kdf_id, KDF::HKDF_SHA256);
    assert_eq!(config.contents.hpke_key_config.hpke_symmetric_cipher_suites[0].hpke_aead_id, AEAD::AES_128_GCM);
    let mut output = Vec::new();
    configs.encode(&mut output);
    assert_eq!(base64_echconfigs, base64::encode(&output));
}