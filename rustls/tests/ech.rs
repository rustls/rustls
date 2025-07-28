use pki_types::DnsName;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{EchVersion, HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
};

#[test]
fn test_decode_config_list() {
    fn assert_config(contents: &EchConfigContents, public_name: impl AsRef<[u8]>, max_len: u8) {
        assert_eq!(contents.maximum_name_length, max_len);
        assert_eq!(
            contents.public_name,
            DnsName::try_from(public_name.as_ref()).unwrap()
        );
        assert!(contents.extensions.is_empty());
    }

    fn assert_key_config(
        config: &HpkeKeyConfig,
        id: u8,
        kem_id: HpkeKem,
        cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    ) {
        assert_eq!(config.config_id, id);
        assert_eq!(config.kem_id, kem_id);
        assert_eq!(config.symmetric_cipher_suites, cipher_suites);
    }

    let config_list = get_ech_config(ECHCONFIG_LIST_LOCALHOST);
    assert_eq!(config_list.len(), 1);
    let EchConfigPayload::V18(contents) = &config_list[0] else {
        panic!("unexpected ECH config version: {:?}", config_list[0]);
    };
    assert_config(contents, "localhost", 128);
    assert_key_config(
        &contents.key_config,
        0,
        HpkeKem::DHKEM_X25519_HKDF_SHA256,
        vec![
            HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
            HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::CHACHA20_POLY_1305,
            },
        ],
    );

    let config_list = get_ech_config(ECHCONFIG_LIST_CF);
    assert_eq!(config_list.len(), 2);
    let EchConfigPayload::V18(contents_a) = &config_list[0] else {
        panic!("unexpected ECH config version: {:?}", config_list[0]);
    };
    assert_config(contents_a, "cloudflare-esni.com", 37);
    assert_key_config(
        &contents_a.key_config,
        195,
        HpkeKem::DHKEM_X25519_HKDF_SHA256,
        vec![HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        }],
    );
    let EchConfigPayload::V18(contents_b) = &config_list[1] else {
        panic!("unexpected ECH config version: {:?}", config_list[1]);
    };
    assert_config(contents_b, "cloudflare-esni.com", 42);
    assert_key_config(
        &contents_b.key_config,
        3,
        HpkeKem::DHKEM_P256_HKDF_SHA256,
        vec![HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        }],
    );

    let config_list = get_ech_config(ECHCONFIG_LIST_WITH_UNSUPPORTED);
    assert_eq!(config_list.len(), 4);
    // The first config should be unsupported.
    assert!(matches!(
        config_list[0],
        EchConfigPayload::Unknown {
            version: EchVersion::Unknown(0xBADD),
            ..
        }
    ));
    // The other configs should be recognized.
    for config in config_list.iter().skip(1) {
        assert!(matches!(config, EchConfigPayload::V18(_)));
    }
}

#[test]
fn test_echconfig_serialization() {
    fn assert_round_trip_eq(original: &[u8]) {
        let configs = get_ech_config(original);
        let mut output = Vec::new();
        configs.encode(&mut output);
        assert_eq!(original, output);
    }

    assert_round_trip_eq(ECHCONFIG_LIST_LOCALHOST);
    assert_round_trip_eq(ECHCONFIG_LIST_CF);
    assert_round_trip_eq(ECHCONFIG_LIST_WITH_UNSUPPORTED);
}

fn get_ech_config(encoded: &[u8]) -> Vec<EchConfigPayload> {
    Vec::<_>::read(&mut Reader::init(encoded)).unwrap()
}

// One EchConfig, with server-name "localhost".
static ECHCONFIG_LIST_LOCALHOST: &[u8] = include_bytes!("data/localhost-echconfigs.bin");

// Two EchConfigs, both with server-name "cloudflare-esni.com".
static ECHCONFIG_LIST_CF: &[u8] =  include_bytes!("data/cloudflare-esni-echconfigs.bin");

// Three EchConfigs, the first one with an unsupported version.
static ECHCONFIG_LIST_WITH_UNSUPPORTED: &[u8] = include_bytes!("data/unsupported-then-valid-echconfigs.bin");
