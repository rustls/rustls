//! This file contains tests that use the test-only FFDHE KX group (defined in submodule `ffdhe`)

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::borrow::Cow;
use std::sync::Arc;

use num_bigint::BigUint;
use rustls::crypto::kx::ffdhe::{FFDHE2048, FFDHE3072, FFDHE4096, FfdheGroup};
use rustls::crypto::kx::{
    ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::crypto::{CipherSuite, CipherSuiteCommon, CryptoProvider};
use rustls::enums::ProtocolVersion;
use rustls::{ClientConfig, Connection, ServerConfig, SupportedCipherSuite, Tls12CipherSuite};
use rustls_test::{
    ClientConfigExt, KeyType, ServerConfigExt, do_handshake, do_suite_and_kx_test,
    make_pair_for_arc_configs, make_pair_for_configs, provider_with_one_suite,
};

use super::provider;

#[test]
fn config_builder_for_client_rejects_cipher_suites_without_compatible_kx_groups() {
    let bad_crypto_provider = CryptoProvider {
        kx_groups: Cow::Owned(vec![&FFDHE2048_KX_GROUP as &dyn SupportedKxGroup]),
        tls12_cipher_suites: Cow::Owned(vec![
            provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        ]),
        ..provider::DEFAULT_PROVIDER
    };

    let build_err = ClientConfig::builder(bad_crypto_provider.into())
        .with_root_certificates(KeyType::EcdsaP256.client_root_store())
        .with_no_client_auth()
        .unwrap_err()
        .to_string();

    // Current expected error:
    // Ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 requires [ECDHE] key exchange, but no \
    // [ECDHE]-compatible key exchange groups were present in `CryptoProvider`'s `kx_groups` field
    assert!(build_err.contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    assert!(build_err.contains("ECDHE"));
    assert!(build_err.contains("key exchange"));
}

#[test]
fn ffdhe_ciphersuite() {
    use provider::cipher_suite;

    let test_cases = [
        (
            ProtocolVersion::TLSv1_2,
            SupportedCipherSuite::Tls12(&TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
        ),
        (
            ProtocolVersion::TLSv1_3,
            SupportedCipherSuite::Tls13(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
        ),
    ];

    for (expected_protocol, expected_cipher_suite) in test_cases {
        let provider = Arc::new(provider_with_one_suite(
            &ffdhe_provider(),
            expected_cipher_suite,
        ));
        let client_config = ClientConfig::builder(provider.clone()).finish(KeyType::Rsa2048);
        let server_config = ServerConfig::builder(provider).finish(KeyType::Rsa2048);
        do_suite_and_kx_test(
            client_config,
            server_config,
            expected_cipher_suite,
            NamedGroup::FFDHE2048,
            expected_protocol,
        );
    }
}

#[test]
fn server_avoids_dhe_cipher_suites_when_client_has_no_known_dhe_in_groups_ext() {
    let client_config = ClientConfig::builder(
        CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![
                &TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            tls13_cipher_suites: Cow::Owned(vec![]),
            kx_groups: Cow::Owned(vec![&FFDHE4096_KX_GROUP, provider::kx_group::SECP256R1]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    let server_config = ServerConfig::builder(
        CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![
                &TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            kx_groups: Cow::Owned(vec![&FFDHE2048_KX_GROUP, provider::kx_group::SECP256R1]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
    assert_eq!(
        server
            .negotiated_cipher_suite()
            .unwrap()
            .suite(),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    );
    assert_eq!(
        server
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::secp256r1,
    )
}

#[test]
fn server_avoids_cipher_suite_with_no_common_kx_groups() {
    let server_config = ServerConfig::builder(
        CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![
                provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                &TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            tls13_cipher_suites: Cow::Owned(vec![provider::cipher_suite::TLS13_AES_128_GCM_SHA256]),
            kx_groups: Cow::Owned(vec![provider::kx_group::SECP256R1, &FFDHE2048_KX_GROUP]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    )
    .finish(KeyType::Rsa2048)
    .into();

    let test_cases = [
        (
            // TLS 1.2, have common
            vec![
                // this matches:
                provider::kx_group::SECP256R1,
                &FFDHE2048_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_2,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Some(NamedGroup::secp256r1),
        ),
        (
            vec![
                // this matches:
                provider::kx_group::SECP256R1,
                &FFDHE3072_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_2,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Some(NamedGroup::secp256r1),
        ),
        (
            vec![
                provider::kx_group::SECP384R1,
                // this matches:
                &FFDHE2048_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_2,
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            Some(NamedGroup::FFDHE2048),
        ),
        (
            // TLS 1.3, have common
            vec![
                // this matches:
                provider::kx_group::SECP256R1,
                &FFDHE2048_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_3,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            Some(NamedGroup::secp256r1),
        ),
        (
            vec![
                // this matches:
                provider::kx_group::SECP256R1,
                &FFDHE3072_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_3,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            Some(NamedGroup::secp256r1),
        ),
        (
            vec![
                provider::kx_group::SECP384R1,
                // this matches:
                &FFDHE2048_KX_GROUP,
            ],
            ProtocolVersion::TLSv1_3,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            Some(NamedGroup::FFDHE2048),
        ),
    ];

    for (client_kx_groups, protocol_version, expected_cipher_suite, expected_group) in test_cases {
        let provider = CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![
                provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                &TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            tls13_cipher_suites: Cow::Owned(vec![provider::cipher_suite::TLS13_AES_128_GCM_SHA256]),
            kx_groups: Cow::Owned(client_kx_groups),
            ..provider::DEFAULT_PROVIDER
        };
        let provider = match protocol_version {
            ProtocolVersion::TLSv1_2 => CryptoProvider {
                tls13_cipher_suites: Default::default(),
                ..provider
            },
            ProtocolVersion::TLSv1_3 => CryptoProvider {
                tls12_cipher_suites: Default::default(),
                ..provider
            },
            _ => unreachable!(),
        };
        let client_config = ClientConfig::builder(provider.into())
            .finish(KeyType::Rsa2048)
            .into();

        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        do_handshake(&mut client, &mut server);
        assert_eq!(
            server
                .negotiated_cipher_suite()
                .unwrap()
                .suite(),
            expected_cipher_suite
        );
        assert_eq!(server.protocol_version(), Some(protocol_version));
        assert_eq!(
            server
                .negotiated_key_exchange_group()
                .map(|kx| kx.name()),
            expected_group,
        );
    }
}

#[test]
fn non_ffdhe_kx_does_not_have_ffdhe_group() {
    let non_ffdhe = provider::kx_group::SECP256R1;
    assert_eq!(non_ffdhe.ffdhe_group(), None);
    let active = non_ffdhe.start().unwrap();
    assert_eq!(active.ffdhe_group(), None);
}

/// A test-only `CryptoProvider`, only supporting FFDHE key exchange
fn ffdhe_provider() -> CryptoProvider {
    CryptoProvider {
        tls12_cipher_suites: Cow::Owned(vec![&TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]),
        tls13_cipher_suites: Cow::Owned(vec![
            provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]),
        kx_groups: Cow::Owned(FFDHE_KX_GROUPS.to_vec()),
        ..provider::DEFAULT_PROVIDER
    }
}

static FFDHE_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&FFDHE2048_KX_GROUP, &FFDHE3072_KX_GROUP];

const FFDHE2048_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE2048, FFDHE2048);
const FFDHE3072_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE3072, FFDHE3072);
const FFDHE4096_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE4096, FFDHE4096);

/// The (test-only) TLS1.2 ciphersuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        ..provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.common
    },
    kx: KeyExchangeAlgorithm::DHE,
    ..*provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};

#[derive(Debug)]
struct FfdheKxGroup(pub NamedGroup, pub FfdheGroup<'static>);

impl SupportedKxGroup for FfdheKxGroup {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        let mut x = vec![0; 64];
        ffdhe_provider()
            .secure_random
            .fill(&mut x)?;
        let x = BigUint::from_bytes_be(&x);

        let p = BigUint::from_bytes_be(self.1.p);
        let g = BigUint::from_bytes_be(self.1.g);

        let x_pub = g.modpow(&x, &p);
        let x_pub = to_bytes_be_with_len(x_pub, self.1.p.len());

        Ok(StartedKeyExchange::Single(Box::new(ActiveFfdheKx {
            x_pub,
            x,
            p,
            group: self.1,
            named_group: self.0,
        })))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.1)
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

struct ActiveFfdheKx {
    x_pub: Vec<u8>,
    x: BigUint,
    p: BigUint,
    group: FfdheGroup<'static>,
    named_group: NamedGroup,
}

impl ActiveKeyExchange for ActiveFfdheKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_pub = BigUint::from_bytes_be(peer_pub_key);
        let secret = peer_pub.modpow(&self.x, &self.p);
        let secret = to_bytes_be_with_len(secret, self.group.p.len());

        Ok(SharedSecret::from(&secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.group)
    }

    fn group(&self) -> NamedGroup {
        self.named_group
    }
}

fn to_bytes_be_with_len(n: BigUint, len_bytes: usize) -> Vec<u8> {
    let mut bytes = n.to_bytes_le();
    bytes.resize(len_bytes, 0);
    bytes.reverse();
    bytes
}
