//! Cryptography-related tests, and tests around key material handling.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use rustls::crypto::{Credentials, CryptoProvider};
use rustls::{
    ClientConfig, ClientConnection, ConnectionTrafficSecrets, Error, KeyLog, ServerConfig,
    ServerConnection, SupportedCipherSuite,
};
use rustls_test::{
    ClientConfigExt, KeyType, ServerConfigExt, aes_128_gcm_with_1024_confidentiality_limit,
    do_handshake, make_client_config, make_pair, make_pair_for_arc_configs, make_pair_for_configs,
    make_server_config, provider_with_one_suite, transfer,
};

use super::provider;
use super::provider::cipher_suite;

#[test]
fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let provider = provider::DEFAULT_TLS12_PROVIDER;
    let kt = KeyType::Rsa2048;
    let mut client_config = make_client_config(kt, &provider);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();
    assert_eq!(client_full_log, server_full_log);
    assert_eq!(1, client_full_log.len());
    assert_eq!("CLIENT_RANDOM", client_full_log[0].label);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();
    assert_eq!(client_resume_log, server_resume_log);
    assert_eq!(1, client_resume_log.len());
    assert_eq!("CLIENT_RANDOM", client_resume_log[0].label);
    assert_eq!(client_full_log[0].secret, client_resume_log[0].secret);
}

#[test]
fn key_log_for_tls13() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let kt = KeyType::Rsa2048;
    let mut client_config = make_client_config(kt, &provider);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[0]);
    assert_eq!(client_full_log[1], server_full_log[1]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[0].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[1].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[4].label);

    assert_eq!(6, server_resume_log.len());
    assert_eq!("CLIENT_EARLY_TRAFFIC_SECRET", server_resume_log[0].label);
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[1].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[2].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", server_resume_log[3].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", server_resume_log[4].label);
    assert_eq!("EXPORTER_SECRET", server_resume_log[5].label);

    assert_eq!(client_resume_log[0], server_resume_log[1]);
    assert_eq!(client_resume_log[1], server_resume_log[2]);
    assert_eq!(client_resume_log[2], server_resume_log[3]);
    assert_eq!(client_resume_log[3], server_resume_log[4]);
    assert_eq!(client_resume_log[4], server_resume_log[5]);
}
#[derive(Debug)]
struct KeyLogToVec {
    label: &'static str,
    items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogToVec {
    fn new(who: &'static str) -> Self {
        Self {
            label: who,
            items: Mutex::new(vec![]),
        }
    }

    fn take(&self) -> Vec<KeyLogItem> {
        core::mem::take(&mut self.items.lock().unwrap())
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}

/// Test that secrets can be extracted and used for encryption/decryption.
#[test]
fn test_secret_extraction_enabled() {
    // Normally, secret extraction would be used to configure kTLS (TLS offload
    // to the kernel). We want this test to run on any platform, though, so
    // instead we just compare secrets for equality.

    // TLS 1.2 and 1.3 have different mechanisms for key exchange and handshake,
    // and secrets are stored/extracted differently, so we want to test them both.
    // We support 3 different AEAD algorithms (AES-128-GCM mode, AES-256-GCM, and
    // Chacha20Poly1305), so that's 2*3 = 6 combinations to test.
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    for suite in [
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_AES_256_GCM_SHA384),
        #[cfg(not(feature = "fips"))]
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        #[cfg(not(feature = "fips"))]
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    ] {
        println!("Testing suite {:?}", suite.suite().as_str());

        // Only offer the cipher suite (and protocol version) that we're testing
        let mut server_config =
            ServerConfig::builder(provider_with_one_suite(&provider, suite).into())
                .with_no_client_auth()
                .with_single_cert(kt.identity(), kt.key())
                .unwrap();
        // Opt into secret extraction from both sides
        server_config.enable_secret_extraction = true;
        let server_config = Arc::new(server_config);

        let mut client_config = make_client_config(kt, &provider);
        client_config.enable_secret_extraction = true;

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        do_handshake(&mut client, &mut server);

        // The handshake is finished, we're now able to extract traffic secrets
        let client_secrets = client
            .dangerous_extract_secrets()
            .unwrap();
        let server_secrets = server
            .dangerous_extract_secrets()
            .unwrap();

        // Comparing secrets for equality is something you should never have to
        // do in production code, so ConnectionTrafficSecrets doesn't implement
        // PartialEq/Eq on purpose. Instead, we have to get creative.
        fn explode_secrets(s: &ConnectionTrafficSecrets) -> (&[u8], &[u8]) {
            match s {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
                ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
                ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                    (key.as_ref(), iv.as_ref())
                }
                _ => panic!("unexpected secret type"),
            }
        }

        fn assert_secrets_equal(
            (l_seq, l_sec): (u64, ConnectionTrafficSecrets),
            (r_seq, r_sec): (u64, ConnectionTrafficSecrets),
        ) {
            assert_eq!(l_seq, r_seq);
            assert_eq!(explode_secrets(&l_sec), explode_secrets(&r_sec));
        }

        assert_secrets_equal(client_secrets.tx, server_secrets.rx);
        assert_secrets_equal(client_secrets.rx, server_secrets.tx);
    }
}

#[test]
fn test_secret_extract_produces_correct_variant() {
    fn check(suite: SupportedCipherSuite, f: impl Fn(ConnectionTrafficSecrets) -> bool) {
        let kt = KeyType::Rsa2048;

        let provider: Arc<CryptoProvider> =
            provider_with_one_suite(&provider::DEFAULT_PROVIDER, suite).into();

        let mut server_config = ServerConfig::builder(provider.clone()).finish(kt);

        server_config.enable_secret_extraction = true;
        let server_config = Arc::new(server_config);

        let mut client_config = ClientConfig::builder(provider).finish(kt);
        client_config.enable_secret_extraction = true;

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        do_handshake(&mut client, &mut server);

        let client_secrets = client
            .dangerous_extract_secrets()
            .unwrap();
        let server_secrets = server
            .dangerous_extract_secrets()
            .unwrap();

        assert!(f(client_secrets.tx.1));
        assert!(f(client_secrets.rx.1));
        assert!(f(server_secrets.tx.1));
        assert!(f(server_secrets.rx.1));
    }

    check(
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_AES_128_GCM_SHA256),
        |sec| matches!(sec, ConnectionTrafficSecrets::Aes128Gcm { .. }),
    );
    check(
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_AES_256_GCM_SHA384),
        |sec| matches!(sec, ConnectionTrafficSecrets::Aes256Gcm { .. }),
    );
    check(
        SupportedCipherSuite::Tls13(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
        |sec| matches!(sec, ConnectionTrafficSecrets::Chacha20Poly1305 { .. }),
    );

    check(
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        |sec| matches!(sec, ConnectionTrafficSecrets::Aes128Gcm { .. }),
    );
    check(
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        |sec| matches!(sec, ConnectionTrafficSecrets::Aes256Gcm { .. }),
    );
    check(
        SupportedCipherSuite::Tls12(cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        |sec| matches!(sec, ConnectionTrafficSecrets::Chacha20Poly1305 { .. }),
    );
}

/// Test that secrets cannot be extracted unless explicitly enabled, and until
/// the handshake is done.
#[test]
fn test_secret_extraction_disabled_or_too_early() {
    let kt = KeyType::Rsa2048;
    let provider = Arc::new(CryptoProvider {
        tls13_cipher_suites: Cow::Owned(vec![cipher_suite::TLS13_AES_128_GCM_SHA256]),
        ..provider::DEFAULT_PROVIDER
    });

    for (server_enable, client_enable) in [(true, false), (false, true)] {
        let mut server_config = ServerConfig::builder(provider.clone())
            .with_no_client_auth()
            .with_single_cert(kt.identity(), kt.key())
            .unwrap();
        server_config.enable_secret_extraction = server_enable;
        let server_config = Arc::new(server_config);

        let mut client_config = make_client_config(kt, &provider);
        client_config.enable_secret_extraction = client_enable;

        let client_config = Arc::new(client_config);

        let (client, server) = make_pair_for_arc_configs(&client_config, &server_config);

        assert!(
            client
                .dangerous_extract_secrets()
                .is_err(),
            "extraction should fail until handshake completes"
        );
        assert!(
            server
                .dangerous_extract_secrets()
                .is_err(),
            "extraction should fail until handshake completes"
        );

        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);

        do_handshake(&mut client, &mut server);

        assert_eq!(
            server_enable,
            server
                .dangerous_extract_secrets()
                .is_ok()
        );
        assert_eq!(
            client_enable,
            client
                .dangerous_extract_secrets()
                .is_ok()
        );
    }
}

#[test]
fn test_refresh_traffic_keys_during_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Ed25519, &provider::DEFAULT_PROVIDER);
    assert_eq!(
        client
            .refresh_traffic_keys()
            .unwrap_err(),
        Error::HandshakeNotComplete
    );
    assert_eq!(
        server
            .refresh_traffic_keys()
            .unwrap_err(),
        Error::HandshakeNotComplete
    );
}

#[test]
fn test_refresh_traffic_keys() {
    let (mut client, mut server) = make_pair(KeyType::Ed25519, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    fn check_both_directions(client: &mut ClientConnection, server: &mut ServerConnection) {
        client
            .writer()
            .write_all(b"to-server-1")
            .unwrap();
        server
            .writer()
            .write_all(b"to-client-1")
            .unwrap();
        transfer(client, server);
        server.process_new_packets().unwrap();

        transfer(server, client);
        client.process_new_packets().unwrap();

        let mut buf = [0u8; 16];
        let len = server.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"to-server-1");

        let len = client.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"to-client-1");
    }

    check_both_directions(&mut client, &mut server);
    client.refresh_traffic_keys().unwrap();
    check_both_directions(&mut client, &mut server);
    server.refresh_traffic_keys().unwrap();
    check_both_directions(&mut client, &mut server);
}

#[test]
fn test_automatic_refresh_traffic_keys() {
    const fn encrypted_size(body: usize) -> usize {
        let padding = 1;
        let header = 5;
        let tag = 16;
        header + body + padding + tag
    }

    const KEY_UPDATE_SIZE: usize = encrypted_size(5);
    let provider = aes_128_gcm_with_1024_confidentiality_limit(provider::DEFAULT_PROVIDER);

    let client_config = ClientConfig::builder(provider.clone()).finish(KeyType::Ed25519);
    let server_config = ServerConfig::builder(provider).finish(KeyType::Ed25519);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    for i in 0..(CONFIDENTIALITY_LIMIT + 16) {
        let message = format!("{i:08}");
        client
            .writer()
            .write_all(message.as_bytes())
            .unwrap();
        let transferred = transfer(&mut client, &mut server);
        println!(
            "{}: {} -> {:?}",
            i,
            transferred,
            server.process_new_packets().unwrap()
        );

        // at CONFIDENTIALITY_LIMIT messages, we also have a key_update message sent
        assert_eq!(
            transferred,
            match i {
                CONFIDENTIALITY_LIMIT => KEY_UPDATE_SIZE + encrypted_size(message.len()),
                _ => encrypted_size(message.len()),
            }
        );

        let mut buf = [0u8; 32];
        let recvd = server.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..recvd], message.as_bytes());
    }

    // finally, server writes and pumps its key_update response
    let message = b"finished";
    server
        .writer()
        .write_all(message)
        .unwrap();
    let transferred = transfer(&mut server, &mut client);

    println!(
        "F: {} -> {:?}",
        transferred,
        client.process_new_packets().unwrap()
    );
    assert_eq!(transferred, KEY_UPDATE_SIZE + encrypted_size(message.len()));
}

#[test]
fn tls12_connection_fails_after_key_reaches_confidentiality_limit() {
    let provider = Arc::new(CryptoProvider {
        tls13_cipher_suites: Default::default(),
        ..Arc::unwrap_or_clone(aes_128_gcm_with_1024_confidentiality_limit(dbg!(
            provider::DEFAULT_PROVIDER
        )))
    });

    let client_config = ClientConfig::builder(provider.clone()).finish(KeyType::Ed25519);
    let server_config = ServerConfig::builder(provider).finish(KeyType::Ed25519);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    for i in 0..CONFIDENTIALITY_LIMIT {
        let message = format!("{i:08}");
        client
            .writer()
            .write_all(message.as_bytes())
            .unwrap();
        let transferred = transfer(&mut client, &mut server);
        println!(
            "{}: {} -> {:?}",
            i,
            transferred,
            server.process_new_packets().unwrap()
        );

        let mut buf = [0u8; 32];
        let recvd = server.reader().read(&mut buf).unwrap();

        match i {
            1023 => assert_eq!(recvd, 0),
            _ => assert_eq!(&buf[..recvd], message.as_bytes()),
        }
    }
}

#[test]
fn test_keys_match_for_all_signing_key_types() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let key = provider
            .key_provider
            .load_private_key(kt.client_key())
            .unwrap();
        let _ = Credentials::new(kt.client_identity(), key).expect("keys match");
        println!("{kt:?} ok");
    }
}

const CONFIDENTIALITY_LIMIT: u64 = 1024;
