//! Assorted public API tests.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fmt, mem};

use pki_types::{CertificateDer, DnsName, IpAddr, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use provider::cipher_suite;
use provider::sign::RsaSigningKey;
use rustls::client::{ResolvesClientCert, Resumption, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::message::{Message, MessagePayload, PlainMessage};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::{
    AlertDescription, ApiMisuse, CertificateError, CertificateIdentity, CipherSuite, ClientConfig,
    ClientConnection, ConnectionTrafficSecrets, ContentType, DistinguishedName, Error,
    ExtendedKeyPurpose, HandshakeKind, HandshakeType, InconsistentKeys, InvalidMessage, KeyLog,
    KeyingMaterialExporter, NamedGroup, PeerIdentity, PeerIncompatible, PeerMisbehaved,
    ProtocolVersion, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
    SupportedCipherSuite, sign,
};
#[cfg(feature = "aws-lc-rs")]
use rustls::{
    client::{EchConfig, EchGreaseConfig, EchMode},
    crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    pki_types::EchConfigListBytes,
};
use webpki::anchor_from_trusted_cert;

use super::common::*;
use super::*;

fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let provider = provider::default_provider();
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version_provider in all_versions(&provider) {
        let mut client_config = make_client_config(KeyType::Rsa2048, &version_provider);
        client_config
            .alpn_protocols
            .clone_from(&client_protos);

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(client.alpn_protocol(), None);
        assert_eq!(server.alpn_protocol(), None);
        let error = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(client.alpn_protocol(), agreed);
        assert_eq!(server.alpn_protocol(), agreed);
        assert_eq!(error.err(), expected_error);
    }
}

fn alpn_test(server_protos: Vec<Vec<u8>>, client_protos: Vec<Vec<u8>>, agreed: Option<&[u8]>) {
    alpn_test_error(server_protos, client_protos, agreed, None)
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec![b"server-proto".to_vec()], vec![], None);

    // client support
    alpn_test(vec![], vec![b"client-proto".to_vec()], None);

    // no overlap
    alpn_test_error(
        vec![b"server-proto".to_vec()],
        vec![b"client-proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );

    // server chooses preference
    alpn_test(
        vec![b"server-proto".to_vec(), b"client-proto".to_vec()],
        vec![b"client-proto".to_vec(), b"server-proto".to_vec()],
        Some(b"server-proto"),
    );

    // case sensitive
    alpn_test_error(
        vec![b"PROTO".to_vec()],
        vec![b"proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );
}

#[test]
fn connection_level_alpn_protocols() {
    let provider = provider::default_provider();
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    // Config specifies `h2`
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let client_config = Arc::new(client_config);

    // Client relies on config-specified `h2`, server agrees
    let mut client =
        ClientConnection::new(client_config.clone(), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    do_handshake_until_error(&mut client, &mut server).unwrap();
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));

    // Specify `http/1.1` for the connection, server agrees
    let mut client = ClientConnection::new_with_alpn(
        client_config,
        server_name("localhost"),
        vec![b"http/1.1".to_vec()],
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake_until_error(&mut client, &mut server).unwrap();
    assert_eq!(client.alpn_protocol(), Some(&b"http/1.1"[..]));
}

fn version_test(
    client_versions: &[ProtocolVersion],
    server_versions: &[ProtocolVersion],
    result: Option<ProtocolVersion>,
) {
    let provider = provider::default_provider();
    let client_provider = apply_versions(provider.clone(), client_versions);
    let server_provider = apply_versions(provider, server_versions);

    let client_config = make_client_config(KeyType::Rsa2048, &client_provider);
    let server_config = make_server_config(KeyType::Rsa2048, &server_provider);

    println!("version {client_versions:?} {server_versions:?} -> {result:?}");

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    } else {
        do_handshake(&mut client, &mut server);
        assert_eq!(client.protocol_version(), result);
        assert_eq!(server.protocol_version(), result);
    }
}

fn apply_versions(provider: CryptoProvider, versions: &[ProtocolVersion]) -> CryptoProvider {
    match versions {
        []
        | [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
        | [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] => provider,
        [ProtocolVersion::TLSv1_3] => provider.with_only_tls13(),
        [ProtocolVersion::TLSv1_2] => provider.with_only_tls12(),
        _ => panic!("unhandled versions {versions:?}"),
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(&[], &[], Some(ProtocolVersion::TLSv1_3));

    // client default, server 1.2 -> 1.2
    version_test(
        &[],
        &[ProtocolVersion::TLSv1_2],
        Some(ProtocolVersion::TLSv1_2),
    );

    // client 1.2, server default -> 1.2
    version_test(
        &[ProtocolVersion::TLSv1_2],
        &[],
        Some(ProtocolVersion::TLSv1_2),
    );

    // client 1.2, server 1.3 -> fail
    version_test(
        &[ProtocolVersion::TLSv1_2],
        &[ProtocolVersion::TLSv1_3],
        None,
    );

    // client 1.3, server 1.2 -> fail
    version_test(
        &[ProtocolVersion::TLSv1_3],
        &[ProtocolVersion::TLSv1_2],
        None,
    );

    // client 1.3, server 1.2+1.3 -> 1.3
    version_test(
        &[ProtocolVersion::TLSv1_3],
        &[ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        Some(ProtocolVersion::TLSv1_3),
    );

    // client 1.2+1.3, server 1.2 -> 1.2
    version_test(
        &[ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
        &[ProtocolVersion::TLSv1_2],
        Some(ProtocolVersion::TLSv1_2),
    );
}

#[test]
fn config_builder_for_client_rejects_empty_kx_groups() {
    assert_eq!(
        ClientConfig::builder_with_provider(
            CryptoProvider {
                kx_groups: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_root_certificates(KeyType::EcdsaP256.client_root_store())
        .with_no_client_auth()
        .err(),
        Some(ApiMisuse::NoKeyExchangeGroupsConfigured.into())
    );
}

#[test]
fn config_builder_for_client_rejects_empty_cipher_suites() {
    assert_eq!(
        ClientConfig::builder_with_provider(
            CryptoProvider {
                tls12_cipher_suites: Vec::default(),
                tls13_cipher_suites: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_root_certificates(KeyType::EcdsaP256.client_root_store())
        .with_no_client_auth()
        .err(),
        Some(ApiMisuse::NoCipherSuitesConfigured.into())
    );
}

#[test]
fn config_builder_for_server_rejects_empty_kx_groups() {
    assert_eq!(
        ServerConfig::builder_with_provider(
            CryptoProvider {
                kx_groups: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_no_client_auth()
        .with_single_cert(KeyType::EcdsaP256.chain(), KeyType::EcdsaP256.key())
        .err(),
        Some(ApiMisuse::NoKeyExchangeGroupsConfigured.into())
    );
}

#[test]
fn config_builder_for_server_rejects_empty_cipher_suites() {
    assert_eq!(
        ServerConfig::builder_with_provider(
            CryptoProvider {
                tls12_cipher_suites: Vec::default(),
                tls13_cipher_suites: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_no_client_auth()
        .with_single_cert(KeyType::EcdsaP256.chain(), KeyType::EcdsaP256.key())
        .err(),
        Some(ApiMisuse::NoCipherSuitesConfigured.into())
    );
}

#[test]
fn config_builder_for_client_with_time() {
    ClientConfig::builder_with_details(
        provider::default_provider().into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    );
}

#[test]
fn config_builder_for_server_with_time() {
    ServerConfig::builder_with_details(
        provider::default_provider().into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    );
}

#[test]
fn client_can_get_server_cert() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt, &provider));
            do_handshake(&mut client, &mut server);

            let certs = match client.peer_identity() {
                Some(PeerIdentity::X509(certs)) => certs,
                _ => panic!("expected X509 certs"),
            };

            assert_eq!(certs.end_entity, kt.chain()[0]);
            assert_eq!(certs.intermediates, &kt.chain().as_slice()[1..]);
        }
    }
}

#[test]
fn client_can_get_server_cert_after_resumption() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = make_server_config(*kt, &provider);
        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

            let original_certs = client.peer_identity();

            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));

            let resumed_certs = client.peer_identity();

            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[test]
fn client_only_attempts_resumption_with_compatible_security() {
    let provider = provider::default_provider();
    let kt = KeyType::Rsa2048;
    CountingLogger::install();
    CountingLogger::reset();

    let server_config = make_server_config(kt, &provider);
    for version_provider in all_versions(&provider) {
        let base_client_config = make_client_config(kt, &version_provider);
        let (mut client, mut server) =
            make_pair_for_configs(base_client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

        // base case
        let (mut client, mut server) =
            make_pair_for_configs(base_client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));

        // allowed case, using `clone`
        let client_config = ClientConfig::clone(&base_client_config);
        let (mut client, mut server) =
            make_pair_for_configs(client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));

        // disallowed case: unmatching `client_auth_cert_resolver`
        let mut client_config = ClientConfig::clone(&base_client_config);
        client_config.client_auth_cert_resolver =
            make_client_config_with_auth(kt, &version_provider).client_auth_cert_resolver;

        CountingLogger::reset();
        let (mut client, mut server) =
            make_pair_for_configs(client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        #[cfg(feature = "log")]
        assert!(COUNTS.with(|c| {
            c.borrow().trace.iter().any(|item| {
                item == "resumption not allowed between different ResolvesClientCert values"
            })
        }));

        // disallowed case: unmatching `verifier`
        let mut client_config = make_client_config_with_auth(kt, &version_provider);
        client_config.resumption = base_client_config.resumption.clone();
        client_config.client_auth_cert_resolver = base_client_config
            .client_auth_cert_resolver
            .clone();

        CountingLogger::reset();
        let (mut client, mut server) =
            make_pair_for_configs(client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        #[cfg(feature = "log")]
        assert!(COUNTS.with(|c| {
            c.borrow()
                .trace
                .iter()
                .any(|item| item == "resumption not allowed between different ServerCertVerifiers")
        }));
    }
}

#[test]
fn server_can_get_client_cert() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = match server.peer_identity() {
                Some(PeerIdentity::X509(certs)) => certs,
                _ => panic!("expected X509 certs"),
            };

            let client_chain = kt.client_chain();
            assert_eq!(certs.end_entity, client_chain[0]);
            assert_eq!(certs.intermediates, &client_chain[1..]);
        }
    }
}

#[test]
fn server_can_get_client_cert_after_resumption() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let client_config = Arc::new(client_config);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let original_certs = server.peer_identity();

            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let resumed_certs = server.peer_identity();
            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[test]
fn resumption_combinations() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = make_server_config(*kt, &provider);
        for (version, version_provider) in [
            (ProtocolVersion::TLSv1_2, provider.clone().with_only_tls12()),
            (ProtocolVersion::TLSv1_3, provider.clone().with_only_tls13()),
        ] {
            let client_config = make_client_config(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            let expected_kx = expected_kx_for_version(version);

            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
            assert_eq!(
                client
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                expected_kx
            );
            assert_eq!(
                server
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                expected_kx
            );

            let (mut client, mut server) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
            if version == ProtocolVersion::TLSv1_2 {
                assert!(
                    client
                        .negotiated_key_exchange_group()
                        .is_none()
                );
                assert!(
                    server
                        .negotiated_key_exchange_group()
                        .is_none()
                );
            } else {
                assert_eq!(
                    client
                        .negotiated_key_exchange_group()
                        .unwrap()
                        .name(),
                    expected_kx
                );
                assert_eq!(
                    server
                        .negotiated_key_exchange_group()
                        .unwrap()
                        .name(),
                    expected_kx
                );
            }
        }
    }
}

#[test]
fn test_config_builders_debug() {
    if !provider_is_ring() {
        return;
    }

    let b = ServerConfig::builder_with_provider(
        CryptoProvider {
            tls13_cipher_suites: vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
            kx_groups: vec![provider::kx_group::X25519],
            ..provider::default_provider()
        }
        .into(),
    );
    let _ = format!("{b:?}");
    let b = ServerConfig::builder_with_provider(
        provider::default_provider()
            .with_only_tls13()
            .into(),
    );
    let _ = format!("{b:?}");
    let b = b.with_no_client_auth();
    let _ = format!("{b:?}");

    let b = ClientConfig::builder_with_provider(
        CryptoProvider {
            tls13_cipher_suites: vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
            kx_groups: vec![provider::kx_group::X25519],
            ..provider::default_provider()
        }
        .into(),
    );
    let _ = format!("{b:?}");
    let b = ClientConfig::builder_with_provider(
        provider::default_provider()
            .with_only_tls13()
            .into(),
    );
    let _ = format!("{b:?}");
}

/// Test that the server handles combination of `offer_client_auth()` returning true
/// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
/// client's and server's ability to "recover" from the server asking for a client
/// certificate and not being given one.
#[test]
fn server_allow_any_anonymous_or_authenticated_client() {
    let provider = Arc::new(provider::default_provider());
    let kt = KeyType::Rsa2048;
    for client_cert_chain in [None, Some(kt.client_chain())] {
        let client_auth = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .allow_unauthenticated()
            .build()
            .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_client_cert_verifier(client_auth)
            .with_single_cert(kt.chain(), kt.key())
            .unwrap();
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = if client_cert_chain.is_some() {
                make_client_config_with_auth(kt, &version_provider)
            } else {
                make_client_config(kt, &version_provider)
            };
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = match server.peer_identity() {
                Some(PeerIdentity::X509(certs)) => Some(certs),
                None => None,
                _ => panic!("expected X509 certs"),
            };

            let (certs, client_chain) = match (certs, &client_cert_chain) {
                (Some(certs), Some(client_chain)) => (certs, client_chain),
                (None, None) => continue,
                _ => panic!("expected both sides to agree on presence of client certs"),
            };

            assert_eq!(certs.end_entity, client_chain[0]);
            assert_eq!(certs.intermediates, &client_chain[1..]);
        }
    }
}

#[test]
fn test_tls13_valid_early_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    // Inject a plaintext alert from the client. The server should accept this since:
    //  * It hasn't decrypted any messages from the peer yet.
    //  * The message content type is Alert.
    //  * The payload size is indicative of a plaintext alert message.
    //  * The negotiated protocol version is TLS 1.3.
    server
        .read_tls(&mut io::Cursor::new(&encoding::alert(
            AlertDescription::UnknownCa,
            &[],
        )))
        .unwrap();

    // The server should process the plaintext alert without error.
    assert_eq!(
        server.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::UnknownCa)),
    );
}

#[test]
fn test_tls13_too_short_early_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message
    // because the payload length is too large to be considered an early plaintext alert.
    server
        .read_tls(&mut io::Cursor::new(&encoding::alert(
            AlertDescription::UnknownCa,
            &[0xff],
        )))
        .unwrap();

    // The server should produce a decrypt error trying to decrypt the plaintext alert.
    assert_eq!(server.process_new_packets(), Err(Error::DecryptError),);
}

#[test]
fn test_tls13_late_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());

    // Complete a bi-directional TLS1.3 handshake. After this point no plaintext messages
    // should occur.
    do_handshake(&mut client, &mut server);

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message.
    server
        .read_tls(&mut io::Cursor::new(&encoding::alert(
            AlertDescription::UnknownCa,
            &[],
        )))
        .unwrap();

    // The server should produce a decrypt error, trying to decrypt a plaintext alert.
    assert_eq!(server.process_new_packets(), Err(Error::DecryptError));
}

#[test]
fn server_cert_resolve_with_sni() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("the.value.from.sni").unwrap()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("the.value.from.sni"))
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_alpn() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_config = make_client_config(*kt, &provider);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("sni-value")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_named_groups() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);

        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_named_groups: Some(
                provider
                    .kx_groups
                    .iter()
                    .map(|kx| kx.name())
                    .collect(),
            ),
            ..Default::default()
        });

        let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn client_trims_terminating_dot() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("some-host.com").unwrap()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("some-host.com.")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

fn check_sigalgs_reduced_by_ciphersuite(
    kt: KeyType,
    suite: CipherSuite,
    expected_sigalgs: Vec<SignatureScheme>,
) {
    let client_config = ClientConfig::builder_with_provider(
        provider_with_one_suite(&provider::default_provider(), find_suite(suite)).into(),
    )
    .finish(kt);

    let mut server_config = make_server_config(kt, &provider::default_provider());

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        expected_cipher_suites: Some(vec![suite, CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
        ..Default::default()
    });

    let mut client =
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server);
    assert!(err.is_err());
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_rsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Rsa2048,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        vec![
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
    );
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_ecdsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::EcdsaP256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        if provider_is_aws_lc_rs() {
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED25519,
            ]
        } else {
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        },
    );
}

#[derive(Debug)]
struct ServerCheckNoSni {}

impl ResolvesServerCert for ServerCheckNoSni {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        assert!(client_hello.server_name().is_none());

        None
    }
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckNoSni {});
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let mut client_config = make_client_config(*kt, &version_provider);
            client_config.enable_sni = false;

            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("value-not-sent"))
                    .unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert!(err.is_err());
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                server_name("not-the-right-hostname.com"),
            )
            .unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("not-the-right-hostname.com")
                )))
            );
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_ip_address() {
    fn check_server_name(
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        name: &'static str,
    ) -> Result<(), ErrorFromPeer> {
        let mut client = ClientConnection::new(client_config, server_name(name)).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake_until_error(&mut client, &mut server)
    }

    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let client_config = Arc::new(make_client_config(*kt, &version_provider));

            // positive ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.1"),
                Ok(()),
            );

            // negative ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("198.51.100.2")
                )))
            );

            // positive ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::1"),
                Ok(()),
            );

            // negative ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("2001:db8::2")
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_revoked() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier that will check the EE certificate's revocation status.
        let crls = vec![kt.end_entity_crl()];
        let builder = webpki_server_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(crls)
            .only_check_end_entity_revocation();

        for version_provider in all_versions(&provider) {
            let client_config =
                make_client_config_with_verifier(builder.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail since the server's EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_unknown_revocation() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier builder that will check the EE certificate's revocation status, but not
        // allow unknown revocation status (the default). We'll provide CRLs that are not relevant
        // to the EE cert to ensure its status is unknown.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let forbid_unknown_verifier =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(unrelated_crls.clone())
                .only_check_end_entity_revocation();

        // Also set up a verifier builder that will allow unknown revocation status.
        let allow_unknown_verifier =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(unrelated_crls)
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                forbid_unknown_verifier.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect if we use the forbid_unknown_verifier that the handshake will fail since the
            // server's EE certificate's revocation status is unknown given the CRLs we've provided.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            );

            // We expect if we use the allow_unknown_verifier that the handshake will not fail.
            let client_config =
                make_client_config_with_verifier(allow_unknown_verifier.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_check_server_certificate_intermediate_revoked() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier builder that will check the full chain revocation status against a CRL
        // that marks the intermediate certificate as revoked. We allow unknown revocation status
        // so the EE cert's unknown status doesn't cause an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();

        // Also set up a verifier builder that will use the same CRL, but only check the EE certificate
        // revocation status.
        let ee_verifier_builder = webpki_server_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                full_chain_verifier_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail when using the full chain verifier since the intermediate's
            // EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );

            let client_config =
                make_client_config_with_verifier(ee_verifier_builder.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            // We expect the handshake to succeed when we use the verifier that only checks the EE certificate
            // revocation status. The revoked intermediate status should not be checked.
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok())
        }
    }
}

#[test]
fn client_check_server_certificate_ee_crl_expired() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier that will check the EE certificate's revocation status, with CRL expiration enforced.
        let crls = vec![kt.end_entity_crl_expired()];
        let enforce_expiration_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration();

        // Also setup a server verifier without CRL expiration enforced.
        let crls = vec![kt.end_entity_crl_expired()];
        let ignore_expiration_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                enforce_expiration_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail since the CRL is expired.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert!(matches!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::ExpiredRevocationListContext { .. }
                )))
            ));

            let client_config = make_client_config_with_verifier(
                ignore_expiration_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to succeed when CRL expiration is ignored.
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok())
        }
    }
}

/// Simple smoke-test of the webpki verify_server_cert_signed_by_trust_anchor helper API.
/// This public API is intended to be used by consumers implementing their own verifier and
/// so isn't used by the other existing verifier tests.
#[test]
fn client_check_server_certificate_helper_api() {
    for kt in KeyType::all_for_provider(&provider::default_provider()) {
        let chain = kt.chain();
        let correct_roots = kt.client_root_store();
        let incorrect_roots = match kt {
            KeyType::Rsa2048 => KeyType::EcdsaP256,
            _ => KeyType::Rsa2048,
        }
        .client_root_store();
        // Using the correct trust anchors, we should verify without error.
        assert!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &correct_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .is_ok()
        );
        // Using the wrong trust anchors, we should get the expected error.
        assert_eq!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &incorrect_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
    }
}

#[test]
fn client_check_server_valid_purpose() {
    let chain = KeyType::EcdsaP256.client_chain();
    let trust_anchor = chain.last().unwrap();
    let roots = RootCertStore {
        roots: vec![
            anchor_from_trusted_cert(trust_anchor)
                .unwrap()
                .to_owned(),
        ],
    };

    let error = verify_server_cert_signed_by_trust_anchor(
        &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
        &roots,
        &[chain.get(1).unwrap().clone()],
        UnixTime::now(),
        webpki::ALL_VERIFICATION_ALGS,
    )
    .unwrap_err();
    assert_eq!(
        error,
        Error::InvalidCertificate(CertificateError::InvalidPurposeContext {
            required: ExtendedKeyPurpose::ServerAuth,
            presented: vec![ExtendedKeyPurpose::ClientAuth],
        })
    );

    assert_eq!(
        format!("{error}"),
        "invalid peer certificate: certificate does not allow extended key usage for \
         server authentication, allows client authentication"
    );
}

#[derive(Debug)]
struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
    expect_root_hint_subjects: Vec<Vec<u8>>,
    expect_sigschemes: Vec<SignatureScheme>,
}

impl ClientCheckCertResolve {
    fn new(
        expect_queries: usize,
        expect_root_hint_subjects: Vec<Vec<u8>>,
        expect_sigschemes: Vec<SignatureScheme>,
    ) -> Self {
        Self {
            query_count: AtomicUsize::new(0),
            expect_queries,
            expect_root_hint_subjects,
            expect_sigschemes,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);

        if sigschemes.is_empty() {
            panic!("no signature schemes shared by server");
        }

        assert_eq!(sigschemes, self.expect_sigschemes);
        assert_eq!(root_hint_subjects, self.expect_root_hint_subjects);

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn test_client_cert_resolve(
    key_type: KeyType,
    server_config: Arc<ServerConfig>,
    expected_root_hint_subjects: Vec<Vec<u8>>,
) {
    let provider = provider::default_provider();
    for (version, version_provider) in [
        (
            ProtocolVersion::TLSv1_3,
            &provider.clone().with_only_tls13(),
        ),
        (
            ProtocolVersion::TLSv1_2,
            &provider.clone().with_only_tls12(),
        ),
    ] {
        println!("{version:?} {key_type:?}:");

        let mut client_config = make_client_config(key_type, version_provider);
        client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(
            1,
            expected_root_hint_subjects.clone(),
            default_signature_schemes(version),
        ));

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            do_handshake_until_error(&mut client, &mut server),
            Err(ErrorFromPeer::Server(Error::PeerMisbehaved(
                PeerMisbehaved::NoCertificatesPresented
            )))
        );
    }
}

fn default_signature_schemes(version: ProtocolVersion) -> Vec<SignatureScheme> {
    let mut v = vec![];

    v.extend_from_slice(&[
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
    ]);

    if provider_is_aws_lc_rs() {
        v.insert(2, SignatureScheme::ECDSA_NISTP521_SHA512);
    }

    if version == ProtocolVersion::TLSv1_2 {
        v.extend_from_slice(&[
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]);
    }

    v
}

#[test]
fn client_cert_resolve_default() {
    // Test that in the default configuration that a client cert resolver gets the expected
    // CA subject hints, and supported signature algorithms.
    let provider = provider::default_provider();
    for key_type in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *key_type, &provider,
        ));

        // In a default configuration we expect that the verifier's trust anchors are used
        // for the hint subjects.
        let expected_root_hint_subjects = vec![
            key_type
                .ca_distinguished_name()
                .to_vec(),
        ];

        test_client_cert_resolve(*key_type, server_config, expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_no_hints() {
    // Test that a server can provide no hints and the client cert resolver gets the expected
    // arguments.
    let provider = provider::default_provider();
    for key_type in KeyType::all_for_provider(&provider) {
        // Build a verifier with no hint subjects.
        let verifier = webpki_client_verifier_builder(key_type.client_root_store(), &provider)
            .clear_root_hint_subjects();
        let server_config = make_server_config_with_client_verifier(*key_type, verifier, &provider);
        let expected_root_hint_subjects = Vec::default(); // no hints expected.
        test_client_cert_resolve(*key_type, server_config.into(), expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_added_hint() {
    // Test that a server can add an extra subject above/beyond those found in its trust store
    // and the client cert resolver gets the expected arguments.
    let provider = provider::default_provider();
    let extra_name = b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponyland IDK CA".to_vec();
    for key_type in KeyType::all_for_provider(&provider) {
        let expected_hint_subjects = vec![
            key_type
                .ca_distinguished_name()
                .to_vec(),
            extra_name.clone(),
        ];
        // Create a verifier that adds the extra_name as a hint subject in addition to the ones
        // from the root cert store.
        let verifier = webpki_client_verifier_builder(key_type.client_root_store(), &provider)
            .add_root_hint_subjects([DistinguishedName::from(extra_name.clone())].into_iter());
        let server_config = make_server_config_with_client_verifier(*key_type, verifier, &provider);
        test_client_cert_resolve(*key_type, server_config.into(), expected_hint_subjects);
    }
}

#[test]
fn client_auth_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[test]
fn client_mandatory_auth_client_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let relevant_crls = vec![kt.client_crl()];
        // Only check the EE certificate status. See client_mandatory_auth_intermediate_revocation_works
        // for testing revocation status of the whole chain.
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(relevant_crls)
            .only_check_end_entity_revocation();
        let revoked_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // and uses the default behaviour of treating unknown revocation status as an error.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();
        let missing_client_crl_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // but change the builder to allow unknown revocation status.
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let allow_missing_client_crl_server_config = Arc::new(
            make_server_config_with_client_verifier(*kt, ee_verifier_builder, &provider),
        );

        for version_provider in all_versions(&provider) {
            // Connecting to the server with a CRL that indicates the client certificate is revoked
            // should fail with the expected error.
            let client_config = Arc::new(make_client_config_with_auth(*kt, &version_provider));
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &revoked_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // Connecting to the server missing CRL information for the client certificate should
            // fail with the expected unknown revocation status error.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                res,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            );
            // Connecting to the server missing CRL information for the client should not error
            // if the server's verifier allows unknown revocation status.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &allow_missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_mandatory_auth_intermediate_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the intermediate certificate
        // is revoked. We check the full chain for revocation status (default), and allow unknown
        // revocation status so the EE's unknown revocation status isn't an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_client_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();
        let full_chain_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            full_chain_verifier_builder,
            &provider,
        ));

        // Also create a server configuration that uses the same CRL, but that only checks the EE
        // cert revocation status.
        let ee_only_verifier_builder =
            webpki_client_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();
        let ee_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_only_verifier_builder,
            &provider,
        ));

        for version_provider in all_versions(&provider) {
            // When checking the full chain, we expect an error - the intermediate is revoked.
            let client_config = Arc::new(make_client_config_with_auth(*kt, &version_provider));
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &full_chain_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // However, when checking just the EE cert we expect no error - the intermediate's
            // revocation status should not be checked.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &ee_server_config);
            assert!(do_handshake_until_error(&mut client, &mut server).is_ok());
        }
    }
}

#[test]
fn client_optional_auth_client_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let crls = vec![kt.client_crl()];
        let server_config = Arc::new(make_server_config_with_optional_client_auth(
            *kt, crls, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            // Because the client certificate is revoked, the handshake should fail.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}

#[test]
fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    client
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = client.process_new_packets();
    assert!(err.is_err());
    err = client.process_new_packets();
    assert!(err.is_err());
}

#[test]
fn server_error_is_sticky() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    server
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = server.process_new_packets();
    assert!(err.is_err());
    err = server.process_new_packets();
    assert!(err.is_err());
}

#[allow(clippy::unnecessary_operation)]
#[test]
fn server_is_send_and_sync() {
    let (_, server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    &server as &dyn Send;
    &server as &dyn Sync;
}

#[allow(clippy::unnecessary_operation)]
#[test]
fn client_is_send_and_sync() {
    let (client, _) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    &client as &dyn Send;
    &client as &dyn Sync;
}

#[test]
fn server_config_is_clone() {
    let _ = make_server_config(KeyType::Rsa2048, &provider::default_provider());
}

#[test]
fn client_config_is_clone() {
    let _ = make_client_config(KeyType::Rsa2048, &provider::default_provider());
}

#[test]
fn client_connection_is_debug() {
    let (client, _) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    println!("{client:?}");
}

#[test]
fn server_connection_is_debug() {
    let (_, server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    println!("{server:?}");
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    for version_provider in all_versions(&provider) {
        let client_config = make_client_config(kt, &version_provider);
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            server_name("second.testserver.com"),
        )
        .unwrap();
        let mut server =
            ServerConnection::new(Arc::new(make_server_config(kt, &provider))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server);
        assert_eq!(
            Some(&DnsName::try_from("second.testserver.com").unwrap()),
            server.server_name()
        );
    }
}

#[test]
fn server_exposes_offered_sni_smashed_to_lowercase() {
    // webpki actually does this for us in its DnsName type
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    for version_provider in all_versions(&provider) {
        let client_config = make_client_config(kt, &version_provider);
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            server_name("SECOND.TESTServer.com"),
        )
        .unwrap();
        let mut server =
            ServerConnection::new(Arc::new(make_server_config(kt, &provider))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server);
        assert_eq!(
            Some(&DnsName::try_from("second.testserver.com").unwrap()),
            server.server_name()
        );
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version_provider in all_versions(&provider) {
        let client_config = make_client_config(kt, &version_provider);
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("thisdoesNOTexist.com"))
                .unwrap();

        assert_eq!(None, server.server_name());
        transfer(&mut client, &mut server);
        assert_eq!(
            server.process_new_packets(),
            Err(Error::General(
                "no server certificate chain resolved".to_string()
            ))
        );
        assert_eq!(
            Some(&DnsName::try_from("thisdoesnotexist.com").unwrap()),
            server.server_name()
        );
    }
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);
    resolver
        .add(
            DnsName::try_from("localhost").unwrap(),
            sign::CertifiedKey::new(kt.chain(), signing_key.clone()).expect("keys match"),
        )
        .unwrap();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("localhost"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client2 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("notlocalhost"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client2, &mut server2);
    assert_eq!(
        err,
        Err(ErrorFromPeer::Server(Error::General(
            "no server certificate chain resolved".into()
        )))
    );
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::Rsa2048;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            sign::CertifiedKey::new(kt.chain(), signing_key.clone()).expect("keys match")
        )
    );
    assert_eq!(
        Err(Error::InvalidCertificate(certificate_error_expecting_name(
            "not-localhost"
        ))),
        resolver.add(
            DnsName::try_from("not-localhost").unwrap(),
            sign::CertifiedKey::new(kt.chain(), signing_key.clone()).expect("keys match")
        )
    );
}

fn certificate_error_expecting_name(expected: &str) -> CertificateError {
    CertificateError::NotValidForNameContext {
        expected: ServerName::try_from(expected)
            .unwrap()
            .to_owned(),
        presented: vec![
            // ref. examples/internal/test_ca.rs
            r#"DnsName("testserver.com")"#.into(),
            r#"DnsName("second.testserver.com")"#.into(),
            r#"DnsName("localhost")"#.into(),
            "IpAddress(198.51.100.1)".into(),
            "IpAddress(2001:db8::1)".into(),
        ],
    }
}

#[test]
fn sni_resolver_lower_cases_configured_names() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("LOCALHOST").unwrap(),
            sign::CertifiedKey::new(kt.chain(), signing_key.clone()).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("localhost"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_lower_cases_queried_names() {
    // actually, the handshake parser does this, but the effect is the same.
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            sign::CertifiedKey::new(kt.chain(), signing_key.clone()).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("LOCALHOST"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::Rsa2048;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            sign::CertifiedKey::new_unchecked(vec![], signing_key.clone())
        ),
        Err(ApiMisuse::EmptyCertificateChain.into()),
    );

    let bad_chain = vec![CertificateDer::from(vec![0xa0])];
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            sign::CertifiedKey::new_unchecked(bad_chain, signing_key.clone())
        )
    );
}

#[test]
fn test_keys_match() {
    // Consistent: Both of these should have the same SPKI values
    let expect_consistent =
        sign::CertifiedKey::new(KeyType::Rsa2048.chain(), Arc::new(SigningKeySomeSpki));
    assert!(expect_consistent.is_ok());

    // Inconsistent: These should not have the same SPKI values
    let expect_inconsistent =
        sign::CertifiedKey::new(KeyType::EcdsaP256.chain(), Arc::new(SigningKeySomeSpki));
    assert!(matches!(
        expect_inconsistent,
        Err(Error::InconsistentKeys(InconsistentKeys::KeyMismatch))
    ));

    // Unknown: This signing key returns None for its SPKI, so we can't tell if the certified key is consistent
    assert!(matches!(
        sign::CertifiedKey::new(KeyType::Rsa2048.chain(), Arc::new(SigningKeyNoneSpki)),
        Err(Error::InconsistentKeys(InconsistentKeys::Unknown))
    ));
}

/// Represents a SigningKey that returns None for its SPKI via the default impl.
#[derive(Debug)]
struct SigningKeyNoneSpki;

impl sign::SigningKey for SigningKeyNoneSpki {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn sign::Signer>> {
        unimplemented!("Not meant to be called during tests")
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        unimplemented!("Not meant to be called during tests")
    }
}

/// Represents a SigningKey that returns Some for its SPKI.
#[derive(Debug)]
struct SigningKeySomeSpki;

impl sign::SigningKey for SigningKeySomeSpki {
    fn public_key(&self) -> Option<pki_types::SubjectPublicKeyInfoDer<'_>> {
        let chain = KeyType::Rsa2048.chain();
        let cert = ParsedCertificate::try_from(chain.first().unwrap()).unwrap();
        Some(
            cert.subject_public_key_info()
                .into_owned(),
        )
    }

    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn sign::Signer>> {
        unimplemented!("Not meant to be called during tests")
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        unimplemented!("Not meant to be called during tests")
    }
}

fn do_exporter_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (KeyingMaterialExporter, KeyingMaterialExporter) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(Some(Error::HandshakeNotComplete), client.exporter().err());
    assert_eq!(Some(Error::HandshakeNotComplete), server.exporter().err());
    do_handshake(&mut client, &mut server);

    let client_exporter = client.exporter().unwrap();
    let server_exporter = server.exporter().unwrap();

    assert_eq!(
        client.exporter().err(),
        Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
    );
    assert_eq!(
        server.exporter().err(),
        Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
    );

    assert!(
        client_exporter
            .derive(b"label", Some(b"context"), &mut client_secret)
            .is_ok()
    );
    assert!(
        server_exporter
            .derive(b"label", Some(b"context"), &mut server_secret)
            .is_ok()
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    let mut empty = vec![];
    assert_eq!(
        client_exporter
            .derive(b"label", Some(b"context"), &mut empty)
            .err(),
        Some(ApiMisuse::ExporterOutputZeroLength.into())
    );
    assert_eq!(
        server_exporter
            .derive(b"label", Some(b"context"), &mut empty)
            .err(),
        Some(ApiMisuse::ExporterOutputZeroLength.into())
    );

    assert!(
        client_exporter
            .derive(b"label", None, &mut client_secret)
            .is_ok()
    );
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert!(
        server_exporter
            .derive(b"label", None, &mut server_secret)
            .is_ok()
    );
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    (client_exporter, server_exporter)
}

#[test]
fn test_tls12_exporter() {
    let provider = provider::default_provider().with_only_tls12();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let server_config = make_server_config(*kt, &provider);

        let (client_exporter, _) = do_exporter_test(client_config, server_config);

        // additionally, tls1.2 contexts over 0xffff bytes in length are not prefix-free,
        // so outlaw them.
        client_exporter
            .derive(b"label", Some(&[0; 0xffff]), &mut [0])
            .unwrap();
        assert_eq!(
            Error::ApiMisuse(ApiMisuse::ExporterContextTooLong),
            client_exporter
                .derive(b"label", Some(&[0; 0x10000]), &mut [0])
                .unwrap_err()
        );
    }
}

#[test]
fn test_tls13_exporter() {
    let provider = provider::default_provider().with_only_tls13();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let server_config = make_server_config(*kt, &provider);

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter_maximum_output_length() {
    let provider = provider::default_provider().with_only_tls13();
    let client_config = make_client_config(KeyType::EcdsaP256, &provider);
    let server_config = make_server_config(KeyType::EcdsaP256, &provider);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        client.negotiated_cipher_suite(),
        Some(find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384))
    );

    let client_exporter = client.exporter().unwrap();
    let server_exporter = server.exporter().unwrap();

    let mut maximum_allowed_output_client = [0u8; 255 * 48];
    let mut maximum_allowed_output_server = [0u8; 255 * 48];

    client_exporter
        .derive(
            b"label",
            Some(b"context"),
            &mut maximum_allowed_output_client,
        )
        .unwrap();
    server_exporter
        .derive(
            b"label",
            Some(b"context"),
            &mut maximum_allowed_output_server,
        )
        .unwrap();

    assert_eq!(maximum_allowed_output_client, maximum_allowed_output_server);

    let mut too_long_output = [0u8; 255 * 48 + 1];
    assert_eq!(
        client_exporter
            .derive(b"label", Some(b"context"), &mut too_long_output)
            .err(),
        Some(ApiMisuse::ExporterOutputTooLong.into())
    );
    assert_eq!(
        server_exporter
            .derive(b"label", Some(b"context"), &mut too_long_output)
            .err(),
        Some(ApiMisuse::ExporterOutputTooLong.into())
    );
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    if let Some(found) = provider::ALL_TLS12_CIPHER_SUITES
        .iter()
        .find(|cs| cs.common.suite == suite)
    {
        return SupportedCipherSuite::Tls12(found);
    }

    if let Some(found) = provider::ALL_TLS13_CIPHER_SUITES
        .iter()
        .find(|cs| cs.common.suite == suite)
    {
        return SupportedCipherSuite::Tls13(found);
    }

    panic!("find_suite given unsupported suite {suite:?}");
}

fn test_ciphersuites() -> Vec<(ProtocolVersion, KeyType, CipherSuite)> {
    let mut v = vec![
        (
            ProtocolVersion::TLSv1_3,
            KeyType::Rsa2048,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            ProtocolVersion::TLSv1_3,
            KeyType::Rsa2048,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            ProtocolVersion::TLSv1_2,
            KeyType::EcdsaP384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            ProtocolVersion::TLSv1_2,
            KeyType::EcdsaP384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            ProtocolVersion::TLSv1_2,
            KeyType::Rsa2048,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            ProtocolVersion::TLSv1_2,
            KeyType::Rsa2048,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ),
    ];

    if !provider_is_fips() {
        v.extend_from_slice(&[
            (
                ProtocolVersion::TLSv1_3,
                KeyType::Rsa2048,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ),
            (
                ProtocolVersion::TLSv1_2,
                KeyType::EcdsaP256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
            (
                ProtocolVersion::TLSv1_2,
                KeyType::Rsa2048,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
        ]);
    }

    v
}

#[test]
fn negotiated_ciphersuite_default() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        do_suite_and_kx_test(
            make_client_config(*kt, &provider),
            make_server_config(*kt, &provider),
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            expected_kx_for_version(ProtocolVersion::TLSv1_3),
            ProtocolVersion::TLSv1_3,
        );
    }
}

#[test]
fn all_suites_covered() {
    assert_eq!(
        provider::DEFAULT_TLS12_CIPHER_SUITES.len() + provider::DEFAULT_TLS13_CIPHER_SUITES.len(),
        test_ciphersuites().len()
    );
}

#[test]
fn negotiated_ciphersuite_client() {
    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);
        let client_config = ClientConfig::builder_with_provider(
            provider_with_one_suite(&provider::default_provider(), scs).into(),
        )
        .finish(kt);

        do_suite_and_kx_test(
            client_config,
            make_server_config(kt, &provider::default_provider()),
            scs,
            expected_kx_for_version(version),
            version,
        );
    }
}

#[test]
fn negotiated_ciphersuite_server() {
    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);
        let server_config = ServerConfig::builder_with_provider(
            provider_with_one_suite(&provider::default_provider(), scs).into(),
        )
        .finish(kt);

        do_suite_and_kx_test(
            make_client_config(kt, &provider::default_provider()),
            server_config,
            scs,
            expected_kx_for_version(version),
            version,
        );
    }
}

#[test]
fn negotiated_ciphersuite_server_ignoring_client_preference() {
    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);

        // choose a distinct other suite for the same version
        let scs_other = match (version, scs.suite()) {
            (_, CipherSuite::TLS13_AES_256_GCM_SHA384) => {
                find_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
            }
            (ProtocolVersion::TLSv1_3, _) => find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            (_, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) => {
                find_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            (_, _) => find_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        };
        assert_ne!(scs, scs_other);

        let mut server_config = ServerConfig::builder_with_provider(
            provider_with_suites(&provider::default_provider(), &[scs, scs_other]).into(),
        )
        .finish(kt);
        server_config.ignore_client_order = true;

        let client_config = ClientConfig::builder_with_provider(
            provider_with_suites(&provider::default_provider(), &[scs_other, scs]).into(),
        )
        .finish(kt);

        do_suite_and_kx_test(
            client_config,
            server_config,
            scs,
            expected_kx_for_version(version),
            version,
        );
    }
}

fn expected_kx_for_version(version: ProtocolVersion) -> NamedGroup {
    match (version, provider_is_aws_lc_rs(), provider_is_fips()) {
        (ProtocolVersion::TLSv1_3, true, _) => NamedGroup::X25519MLKEM768,
        (_, _, true) => NamedGroup::secp256r1,
        (_, _, _) => NamedGroup::X25519,
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
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
        std::mem::take(&mut self.items.lock().unwrap())
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

#[test]
fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let provider = provider::default_provider().with_only_tls12();
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

    let provider = provider::default_provider().with_only_tls13();
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

struct ServerStorage {
    storage: Arc<dyn rustls::server::StoresServerSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    take_count: AtomicUsize,
}

impl ServerStorage {
    fn new() -> Self {
        Self {
            storage: rustls::server::ServerSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            take_count: AtomicUsize::new(0),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
    fn takes(&self) -> usize {
        self.take_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(put: {:?}, get: {:?}, take: {:?})",
            self.put_count, self.get_count, self.take_count
        )
    }
}

impl rustls::server::StoresServerSessions for ServerStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.take_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[test]
fn tls13_stateful_resumption() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider().with_only_tls13();
    let client_config = make_client_config(kt, &provider);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(client.tls13_tickets_received(), 2);
    assert_eq!(storage.puts(), 2);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 4);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 1);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 6);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 2);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn tls13_stateless_resumption() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider().with_only_tls13();
    let client_config = make_client_config(kt, &provider);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    server_config.ticketer = provider::Ticketer::new().unwrap();
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_identity()
            .map(|identity| match identity {
                PeerIdentity::X509(CertificateIdentity { intermediates, .. }) =>
                    intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn early_data_not_available() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    assert!(client.early_data().is_none());
}

fn early_data_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut client_config = make_client_config(kt, &provider);
    client_config.enable_early_data = true;
    client_config.resumption = Resumption::store(Arc::new(ClientStorage::new()));

    let mut server_config = make_server_config(kt, &provider);
    server_config.max_early_data_size = 1234;
    (Arc::new(client_config), Arc::new(server_config))
}

#[test]
fn early_data_is_available_on_resumption() {
    let (client_config, server_config) = early_data_configs();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    let client_early_exporter = client
        .early_data()
        .unwrap()
        .exporter()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .exporter()
            .err(),
        Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
    );
    do_handshake(&mut client, &mut server);

    let mut received_early_data = [0u8; 5];
    assert_eq!(
        server
            .early_data()
            .expect("early_data didn't happen")
            .read(&mut received_early_data)
            .expect("early_data failed unexpectedly"),
        5
    );
    assert_eq!(&received_early_data[..], b"hello");
    let server_early_exporter = server
        .early_data()
        .unwrap()
        .exporter()
        .unwrap();
    assert_eq!(
        server
            .early_data()
            .unwrap()
            .exporter()
            .err(),
        Some(Error::ApiMisuse(ApiMisuse::ExporterAlreadyUsed)),
    );

    // check exporters agree
    let client_secret = client_early_exporter
        .derive(b"label", Some(b"context"), [0u8; 32])
        .unwrap();
    let server_secret = server_early_exporter
        .derive(b"label", Some(b"context"), [0u8; 32])
        .unwrap();
    assert_eq!(client_secret, server_secret);
}

#[test]
fn early_data_not_available_on_server_before_client_hello() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::default_provider(),
    )))
    .unwrap();
    assert!(server.early_data().is_none());
}

#[test]
fn early_data_can_be_rejected_by_server() {
    let (client_config, server_config) = early_data_configs();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    server.reject_early_data();
    do_handshake(&mut client, &mut server);

    assert!(!client.is_early_data_accepted());
}

#[test]
fn early_data_is_limited_on_client() {
    let (client_config, server_config) = early_data_configs();

    // warm up
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(&[0xaa; 1234 + 1])
            .unwrap(),
        1234
    );
    do_handshake(&mut client, &mut server);

    let mut received_early_data = [0u8; 1234];
    assert_eq!(
        server
            .early_data()
            .expect("early_data didn't happen")
            .read(&mut received_early_data)
            .expect("early_data failed unexpectedly"),
        1234
    );
    assert_eq!(&received_early_data[..], [0xaa; 1234]);
}

fn early_data_configs_allowing_client_to_send_excess_data() -> (Arc<ClientConfig>, Arc<ServerConfig>)
{
    let (client_config, server_config) = early_data_configs();

    // adjust client session storage to corrupt received max_early_data_size
    let mut client_config = Arc::into_inner(client_config).unwrap();
    let mut storage = ClientStorage::new();
    storage.alter_max_early_data_size(1234, 2024);
    client_config.resumption = Resumption::store(Arc::new(storage));
    let client_config = Arc::new(client_config);

    // warm up
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);
    (client_config, server_config)
}

#[test]
fn server_detects_excess_early_data() {
    let (client_config, server_config) = early_data_configs_allowing_client_to_send_excess_data();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        2024
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(&[0xaa; 2024])
            .unwrap(),
        2024
    );
    assert_eq!(
        do_handshake_until_error(&mut client, &mut server),
        Err(ErrorFromPeer::Server(Error::PeerMisbehaved(
            PeerMisbehaved::TooMuchEarlyDataReceived
        ))),
    );
}

// regression test for https://github.com/rustls/rustls/issues/2096
#[test]
fn server_detects_excess_streamed_early_data() {
    let (client_config, server_config) = early_data_configs_allowing_client_to_send_excess_data();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        2024
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(&[0xaa; 1024])
            .unwrap(),
        1024
    );
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let mut received_early_data = [0u8; 1024];
    assert_eq!(
        server
            .early_data()
            .expect("early_data didn't happen")
            .read(&mut received_early_data)
            .expect("early_data failed unexpectedly"),
        1024
    );
    assert_eq!(&received_early_data[..], [0xaa; 1024]);

    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(&[0xbb; 1000])
            .unwrap(),
        1000
    );
    transfer(&mut client, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::TooMuchEarlyDataReceived
        ))
    );
}

#[test]
fn test_client_config_keyshare() {
    let provider = provider::default_provider();
    let kx_groups = vec![provider::kx_group::SECP384R1];
    let client_config =
        make_client_config_with_kx_groups(KeyType::Rsa2048, kx_groups.clone(), &provider);
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa2048, kx_groups, &provider);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let provider = provider::default_provider();
    let client_config = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    let server_config = make_server_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::X25519],
        &provider,
    );
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert!(do_handshake_until_error(&mut client, &mut server).is_err());
}

#[test]
fn exercise_all_key_exchange_methods() {
    for (version, version_provider) in [
        (
            ProtocolVersion::TLSv1_3,
            provider::default_provider().with_only_tls13(),
        ),
        (
            ProtocolVersion::TLSv1_2,
            provider::default_provider().with_only_tls12(),
        ),
    ] {
        for kx_group in provider::ALL_KX_GROUPS {
            if !kx_group
                .name()
                .usable_for_version(version)
            {
                continue;
            }

            let client_config = make_client_config_with_kx_groups(
                KeyType::Rsa2048,
                vec![*kx_group],
                &version_provider,
            );
            let server_config = make_server_config_with_kx_groups(
                KeyType::Rsa2048,
                vec![*kx_group],
                &version_provider,
            );
            let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
            assert!(do_handshake_until_error(&mut client, &mut server).is_ok());
            println!("kx_group {:?} is self-consistent", kx_group.name());
        }
    }
}

#[test]
fn test_client_sends_helloretryrequest() {
    let provider = provider::default_provider();
    // client sends a secp384r1 key share
    let mut client_config = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::SECP384R1, provider::kx_group::X25519],
        &provider,
    );

    let storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(storage.clone());

    // but server only accepts x25519, so a HRR is required
    let server_config = make_server_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::X25519],
        &provider,
    );

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.handshake_kind(), None);
    assert_eq!(server.handshake_kind(), None);

    // client sends hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 1);
    }

    assert_eq!(client.handshake_kind(), None);
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    // server sends HRR
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen < 100); // just the hello retry request
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // hello retry request and CCS
    }

    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    // client sends fixed hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200); // just the client hello retry
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // only a CCS & client hello retry
    }

    // server completes handshake
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert_eq!(pipe.writevs[0].len(), 2); // { server hello / encrypted exts / cert / cert-verify } / finished
    }

    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    do_handshake_until_error(&mut client, &mut server).unwrap();

    // client only did following storage queries:
    println!("storage {:#?}", storage.ops());
    assert_eq!(storage.ops().len(), 7);
    assert!(matches!(
        storage.ops()[0],
        ClientStorageOp::TakeTls13Ticket(_, false)
    ));
    assert!(matches!(
        storage.ops()[1],
        ClientStorageOp::GetTls12Session(_, false)
    ));
    assert!(matches!(
        storage.ops()[2],
        ClientStorageOp::GetKxHint(_, None)
    ));
    assert!(matches!(
        storage.ops()[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::X25519)
    ));
    assert!(matches!(
        storage.ops()[4],
        ClientStorageOp::RemoveTls12Session(_)
    ));
    // server sends 2 tickets by default
    assert!(matches!(
        storage.ops()[5],
        ClientStorageOp::InsertTls13Ticket(_)
    ));
    assert!(matches!(
        storage.ops()[6],
        ClientStorageOp::InsertTls13Ticket(_)
    ));
}

#[test]
fn test_client_attempts_to_use_unsupported_kx_group() {
    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());
    let provider = provider::default_provider();

    // first, client sends a secp-256 share and server agrees. secp-256 is inserted
    //   into kx group cache.
    let mut client_config_1 = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::SECP256R1],
        &provider,
    );
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config(KeyType::Rsa2048, &provider);

    // first handshake
    let (mut client_1, mut server) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server).unwrap();

    let ops = shared_storage.ops();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 7);
    assert!(matches!(
        ops[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp256r1)
    ));

    // second handshake
    let (mut client_2, mut server) = make_pair_for_configs(client_config_2, server_config);
    do_handshake_until_error(&mut client_2, &mut server).unwrap();

    let ops = shared_storage.ops();
    println!("storage {:?} {:#?}", ops.len(), ops);
    assert_eq!(ops.len(), 13);
    assert!(matches!(ops[7], ClientStorageOp::TakeTls13Ticket(_, true)));
    assert!(matches!(
        ops[8],
        ClientStorageOp::GetKxHint(_, Some(rustls::NamedGroup::secp256r1))
    ));
    assert!(matches!(
        ops[9],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp384r1)
    ));
}

#[test]
fn test_client_sends_share_for_less_preferred_group() {
    // this is a test for the case described in:
    // https://datatracker.ietf.org/doc/draft-davidben-tls-key-share-prediction/

    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());
    let provider = provider::default_provider();

    // first, client sends a secp384r1 share and server agrees. secp384r1 is inserted
    //   into kx group cache.
    let mut client_config_1 = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client supports (x25519, secp384r1) and so kx group cache
    //   contains a supported but less-preferred group.
    let mut client_config_2 = make_client_config_with_kx_groups(
        KeyType::Rsa2048,
        vec![provider::kx_group::X25519, provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config_with_kx_groups(
        KeyType::Rsa2048,
        provider::ALL_KX_GROUPS.to_vec(),
        &provider,
    );

    // first handshake
    let (mut client_1, mut server) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server).unwrap();
    assert_eq!(
        client_1
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
        Some(NamedGroup::secp384r1)
    );
    assert_eq!(client_1.handshake_kind(), Some(HandshakeKind::Full));

    let ops = shared_storage.ops();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 7);
    assert!(matches!(
        ops[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp384r1)
    ));

    // second handshake; HRR'd from secp384r1 to X25519
    let (mut client_2, mut server) = make_pair_for_configs(client_config_2, server_config);
    do_handshake(&mut client_2, &mut server);
    assert_eq!(
        client_2
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
        Some(NamedGroup::X25519)
    );
    assert_eq!(
        client_2.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
}

#[test]
fn test_tls13_client_resumption_does_not_reuse_tickets() {
    let shared_storage = Arc::new(ClientStorage::new());
    let provider = provider::default_provider();

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.resumption = Resumption::store(shared_storage.clone());
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.send_tls13_tickets = 5;
    let server_config = Arc::new(server_config);

    // first handshake: client obtains 5 tickets from server.
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();

    let ops = shared_storage.ops_and_reset();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 10);
    assert!(matches!(ops[5], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[6], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[7], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[8], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[9], ClientStorageOp::InsertTls13Ticket(_)));

    // 5 subsequent handshakes: all are resumptions

    // Note: we don't do complete the handshakes, because that means
    // we get five additional tickets per connection which is unhelpful
    // in this test.  It also acts to record a "Happy Eyeballs"-type use
    // case, where a client speculatively makes many connection attempts
    // in parallel without knowledge of which will work due to underlying
    // connectivity uncertainty.
    for _ in 0..5 {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        let ops = shared_storage.ops_and_reset();
        assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, true)));
    }

    // 6th subsequent handshake: cannot be resumed; we ran out of tickets
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let ops = shared_storage.ops_and_reset();
    println!("last {ops:?}");
    assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, false)));
}

fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {left} < {right}");
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(mem::size_of::<ServerConnection>(), 1600);
    assert_lt(mem::size_of::<ClientConnection>(), 1600);
    assert_lt(
        mem::size_of::<rustls::server::UnbufferedServerConnection>(),
        1600,
    );
    assert_lt(
        mem::size_of::<rustls::client::UnbufferedClientConnection>(),
        1600,
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_groups() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    server
        .read_tls(
            &mut encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                encoding::client_hello_with_extensions(vec![
                    encoding::Extension::new_sig_algs(),
                    encoding::Extension {
                        typ: ExtensionType::EllipticCurves,
                        body: encoding::len_u16(vec![]),
                    },
                    encoding::Extension {
                        typ: ExtensionType::KeyShare,
                        body: encoding::len_u16(vec![]),
                    },
                ]),
            )
            .as_slice(),
        )
        .unwrap();
    assert_eq!(
        server.process_new_packets(),
        Err(Error::InvalidMessage(InvalidMessage::IllegalEmptyList(
            "NamedGroups"
        )))
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_group_overlap() {
    for version_provider in all_versions(&provider::default_provider()) {
        let (mut client, mut server) = make_pair_for_configs(
            make_client_config_with_kx_groups(
                KeyType::Rsa2048,
                vec![provider::kx_group::X25519],
                &version_provider,
            ),
            ServerConfig::builder_with_provider(
                CryptoProvider {
                    kx_groups: vec![provider::kx_group::SECP384R1],
                    ..version_provider
                }
                .into(),
            )
            .finish(KeyType::Rsa2048),
        );
        transfer(&mut client, &mut server);
        assert_eq!(
            server.process_new_packets(),
            Err(Error::PeerIncompatible(
                PeerIncompatible::NoKxGroupsInCommon
            ))
        );
        transfer(&mut server, &mut client);
        assert_eq!(
            client.process_new_packets(),
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
        );
    }
}

#[test]
fn test_client_rejects_illegal_tls13_ccs() {
    fn corrupt_ccs(msg: &mut Message) -> Altered {
        if let MessagePayload::ChangeCipherSpec(_) = &mut msg.payload {
            println!("seen CCS {msg:?}");
            return Altered::Raw(encoding::message_framing(
                ContentType::ChangeCipherSpec,
                ProtocolVersion::TLSv1_2,
                vec![0x01, 0x02],
            ));
        }
        Altered::InPlace
    }

    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let (mut server, mut client) = (server.into(), client.into());

    transfer_altered(&mut server, corrupt_ccs, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec
        ))
    );
}

/// https://github.com/rustls/rustls/issues/797
#[test]
fn test_client_tls12_no_resume_after_server_downgrade() {
    let provider = provider::default_provider();
    let mut client_config = common::make_client_config(KeyType::Ed25519, &provider);
    let client_storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(client_storage.clone());
    let client_config = Arc::new(client_config);

    let server_config_1 = Arc::new(
        ServerConfig::builder_with_provider(
            provider
                .clone()
                .with_only_tls13()
                .into(),
        )
        .finish(KeyType::Ed25519),
    );

    let mut server_config_2 =
        ServerConfig::builder_with_provider(provider.with_only_tls12().into())
            .finish(KeyType::Ed25519);
    server_config_2.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    dbg!("handshake 1");
    let mut client_1 =
        ClientConnection::new(client_config.clone(), "localhost".try_into().unwrap()).unwrap();
    let mut server_1 = ServerConnection::new(server_config_1).unwrap();
    common::do_handshake(&mut client_1, &mut server_1);

    assert_eq!(client_storage.ops().len(), 7);
    println!("hs1 storage ops: {:#?}", client_storage.ops());
    assert!(matches!(
        client_storage.ops()[3],
        ClientStorageOp::SetKxHint(_, _)
    ));
    assert!(matches!(
        client_storage.ops()[4],
        ClientStorageOp::RemoveTls12Session(_)
    ));
    assert!(matches!(
        client_storage.ops()[5],
        ClientStorageOp::InsertTls13Ticket(_)
    ));

    dbg!("handshake 2");
    let mut client_2 =
        ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut server_2 = ServerConnection::new(Arc::new(server_config_2)).unwrap();
    common::do_handshake(&mut client_2, &mut server_2);
    println!("hs2 storage ops: {:#?}", client_storage.ops());
    assert_eq!(client_storage.ops().len(), 9);

    // attempt consumes a TLS1.3 ticket
    assert!(matches!(
        client_storage.ops()[7],
        ClientStorageOp::TakeTls13Ticket(_, true)
    ));

    // but ends up with TLS1.2
    assert_eq!(
        client_2.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

#[test]
fn test_no_warning_logging_during_successful_sessions() {
    CountingLogger::install();
    CountingLogger::reset();

    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt, &provider));
            do_handshake(&mut client, &mut server);
        }
    }

    if cfg!(feature = "log") {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert!(c.borrow().warn.is_empty());
            assert!(c.borrow().error.is_empty());
            assert!(c.borrow().info.is_empty());
            assert!(!c.borrow().trace.is_empty());
            assert!(!c.borrow().debug.is_empty());
        });
    } else {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert!(c.borrow().warn.is_empty());
            assert!(c.borrow().error.is_empty());
            assert!(c.borrow().info.is_empty());
            assert!(c.borrow().trace.is_empty());
            assert!(c.borrow().debug.is_empty());
        });
    }
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
    let provider = provider::default_provider();
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
            ServerConfig::builder_with_provider(provider_with_one_suite(&provider, suite).into())
                .with_no_client_auth()
                .with_single_cert(kt.chain(), kt.key())
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
            provider_with_one_suite(&provider::default_provider(), suite).into();

        let mut server_config = ServerConfig::builder_with_provider(provider.clone()).finish(kt);

        server_config.enable_secret_extraction = true;
        let server_config = Arc::new(server_config);

        let mut client_config = ClientConfig::builder_with_provider(provider).finish(kt);
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
        tls13_cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
        ..provider::default_provider()
    });

    for (server_enable, client_enable) in [(true, false), (false, true)] {
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_no_client_auth()
            .with_single_cert(kt.chain(), kt.key())
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
fn test_debug_server_name_from_ip() {
    assert_eq!(
        format!(
            "{:?}",
            ServerName::IpAddress(IpAddr::try_from("127.0.0.1").unwrap())
        ),
        "IpAddress(V4(Ipv4Addr([127, 0, 0, 1])))"
    )
}

#[test]
fn test_debug_server_name_from_string() {
    assert_eq!(
        format!("{:?}", ServerName::try_from("a.com").unwrap()),
        "DnsName(\"a.com\")"
    )
}

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
#[test]
fn test_explicit_provider_selection() {
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .finish(KeyType::Rsa2048);

    let server_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .finish(KeyType::Rsa2048);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
}

#[derive(Debug)]
struct FaultyRandom {
    // when empty, `fill_random` requests return `GetRandomFailed`
    rand_queue: Mutex<&'static [u8]>,
}

impl rustls::crypto::SecureRandom for FaultyRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        let mut queue = self.rand_queue.lock().unwrap();

        println!(
            "fill_random request for {} bytes (got {})",
            output.len(),
            queue.len()
        );

        if queue.len() < output.len() {
            return Err(rustls::crypto::GetRandomFailed);
        }

        let fixed_output = &queue[..output.len()];
        output.copy_from_slice(fixed_output);
        *queue = &queue[output.len()..];
        Ok(())
    }
}

#[test]
fn test_client_construction_fails_if_random_source_fails_in_first_request() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(b""),
    };

    let client_config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::default_provider()
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    assert_eq!(
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap_err(),
        Error::FailedToGetRandomBytes
    );
}

#[test]
fn test_client_construction_fails_if_random_source_fails_in_second_request() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(b"nice random number generator huh"),
    };

    let client_config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::default_provider()
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    assert_eq!(
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap_err(),
        Error::FailedToGetRandomBytes
    );
}

#[test]
fn test_client_construction_requires_66_bytes_of_random_material() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(
            b"nice random number generator !!!!!\
                                 it's really not very good is it?",
        ),
    };

    let client_config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::default_provider()
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    ClientConnection::new(Arc::new(client_config), server_name("localhost"))
        .expect("check how much random material ClientConnection::new consumes");
}

#[test]
fn test_client_removes_tls12_session_if_server_sends_undecryptable_first_message() {
    fn inject_corrupt_finished_message(msg: &mut Message) -> Altered {
        if let MessagePayload::ChangeCipherSpec(_) = msg.payload {
            // interdict "real" ChangeCipherSpec with its encoding, plus a faulty encrypted Finished.
            let mut raw_change_cipher_spec = encoding::message_framing(
                ContentType::ChangeCipherSpec,
                ProtocolVersion::TLSv1_2,
                vec![0x01],
            );
            let mut corrupt_finished = encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                vec![0u8; 0x28],
            );

            let mut both = vec![];
            both.append(&mut raw_change_cipher_spec);
            both.append(&mut corrupt_finished);

            Altered::Raw(both)
        } else {
            Altered::InPlace
        }
    }

    let provider = provider::default_provider().with_only_tls12();
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    let storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(storage.clone());
    let client_config = Arc::new(client_config);
    let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &provider));

    // successful handshake to allow resumption
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    // resumption
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut client = client.into();
    transfer_altered(
        &mut server.into(),
        inject_corrupt_finished_message,
        &mut client,
    );

    // discard storage operations up to this point, to observe the one we want to test for.
    storage.ops_and_reset();

    // client cannot decrypt faulty Finished, and deletes saved session in case
    // server resumption is buggy.
    assert_eq!(
        Some(Error::DecryptError),
        client.process_new_packets().err()
    );

    assert!(matches!(
        storage.ops()[0],
        ClientStorageOp::RemoveTls12Session(_)
    ));
}

#[test]
fn test_client_fips_service_indicator() {
    assert_eq!(
        make_client_config(KeyType::Rsa2048, &provider::default_provider()).fips(),
        provider_is_fips()
    );
}

#[test]
fn test_server_fips_service_indicator() {
    assert_eq!(
        make_server_config(KeyType::Rsa2048, &provider::default_provider()).fips(),
        provider_is_fips()
    );
}

#[test]
fn test_connection_fips_service_indicator() {
    let provider = provider::default_provider();
    let client_config = Arc::new(make_client_config(KeyType::Rsa2048, &provider));
    let server_config = Arc::new(make_server_config(KeyType::Rsa2048, &provider));
    let conn_pair = make_pair_for_arc_configs(&client_config, &server_config);
    // Each connection's FIPS status should reflect the FIPS status of the config it was created
    // from.
    assert_eq!(client_config.fips(), conn_pair.0.fips());
    assert_eq!(server_config.fips(), conn_pair.1.fips());
}

#[test]
fn test_client_fips_service_indicator_includes_require_ems() {
    if !provider_is_fips() {
        return;
    }

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider::default_provider());
    assert!(client_config.fips());
    client_config.require_ems = false;
    assert!(!client_config.fips());
}

#[test]
fn test_server_fips_service_indicator_includes_require_ems() {
    if !provider_is_fips() {
        return;
    }

    let mut server_config = make_server_config(KeyType::Rsa2048, &provider::default_provider());
    assert!(server_config.fips());
    server_config.require_ems = false;
    assert!(!server_config.fips());
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn test_client_fips_service_indicator_includes_ech_hpke_suite() {
    if !provider_is_fips() {
        return;
    }

    for suite in ALL_SUPPORTED_SUITES {
        let suite_id = suite.suite();
        let config_path = format!(
            "tests/data/{:?}-{:?}-{:?}-echconfigs.bin",
            suite_id.kem, suite_id.sym.kdf_id, suite_id.sym.aead_id
        );

        let ech_config = EchConfig::new(
            EchConfigListBytes::from(std::fs::read(&config_path).unwrap()),
            &[*suite],
        )
        .unwrap();

        // A ECH client configuration should only be considered FIPS approved if the
        // ECH HPKE suite is itself FIPS approved.
        let config = ClientConfig::builder_with_provider(
            provider::default_provider()
                .with_only_tls13()
                .into(),
        )
        .with_ech(EchMode::Enable(ech_config));
        let config = config.finish(KeyType::Rsa2048);
        assert_eq!(config.fips(), suite.fips());

        // The same applies if an ECH GREASE client configuration is used.
        let (public_key, _) = suite.generate_key_pair().unwrap();
        let config = ClientConfig::builder_with_provider(
            provider::default_provider()
                .with_only_tls13()
                .into(),
        )
        .with_ech(EchMode::Grease(EchGreaseConfig::new(*suite, public_key)));
        let config = config.finish(KeyType::Rsa2048);
        assert_eq!(config.fips(), suite.fips());

        // And a connection made from a client config should retain the fips status of the
        // config w.r.t the HPKE suite.
        let conn = ClientConnection::new(
            config.into(),
            ServerName::DnsName(DnsName::try_from("example.org").unwrap()),
        )
        .unwrap();
        assert_eq!(conn.fips(), suite.fips());
    }
}

#[test]
fn test_illegal_server_renegotiation_attempt_after_tls13_handshake() {
    let provider = provider::default_provider().with_only_tls13();
    let client_config = make_client_config(KeyType::Rsa2048, &provider);
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.enable_secret_extraction = true;

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    let mut raw_server = RawTls::new_server(server);

    let msg = PlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(encoding::handshake_framing(
            HandshakeType::HelloRequest,
            vec![],
        )),
    };
    raw_server.encrypt_and_send(&msg, &mut client);
    let err = client
        .process_new_packets()
        .unwrap_err();
    assert_eq!(
        err,
        Error::InappropriateHandshakeMessage {
            expect_types: vec![HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
            got_type: HandshakeType::HelloRequest
        }
    );
}

#[test]
fn test_illegal_server_renegotiation_attempt_after_tls12_handshake() {
    let provider = provider::default_provider().with_only_tls12();
    let client_config = make_client_config(KeyType::Rsa2048, &provider);
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.enable_secret_extraction = true;

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    let mut raw_server = RawTls::new_server(server);

    let msg = PlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(encoding::handshake_framing(
            HandshakeType::HelloRequest,
            vec![],
        )),
    };

    // one is allowed (and elicits a warning alert)
    raw_server.encrypt_and_send(&msg, &mut client);
    client.process_new_packets().unwrap();
    raw_server.receive_and_decrypt(&mut client, |m| {
        assert_eq!(format!("{m:?}"),
                   "Message { version: TLSv1_2, payload: Alert(AlertMessagePayload { level: Warning, description: NoRenegotiation }) }");
    });

    // second is fatal
    raw_server.encrypt_and_send(&msg, &mut client);
    assert_eq!(
        client
            .process_new_packets()
            .unwrap_err(),
        Error::PeerMisbehaved(PeerMisbehaved::TooManyRenegotiationRequests)
    );
}

#[test]
fn test_illegal_client_renegotiation_attempt_after_tls13_handshake() {
    let provider = provider::default_provider().with_only_tls13();
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.enable_secret_extraction = true;
    let server_config = make_server_config(KeyType::Rsa2048, &provider);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    let mut raw_client = RawTls::new_client(client);

    let msg = PlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: Payload::new(encoding::basic_client_hello(vec![])),
    };
    raw_client.encrypt_and_send(&msg, &mut server);
    let err = server
        .process_new_packets()
        .unwrap_err();
    assert_eq!(
        format!("{err:?}"),
        "InappropriateHandshakeMessage { expect_types: [KeyUpdate], got_type: ClientHello }"
    );
}

#[test]
fn test_illegal_client_renegotiation_attempt_during_tls12_handshake() {
    let provider = provider::default_provider().with_only_tls12();
    let server_config = make_server_config(KeyType::Rsa2048, &provider);
    let client_config = make_client_config(KeyType::Rsa2048, &provider);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    let mut client_hello = vec![];
    client
        .write_tls(&mut io::Cursor::new(&mut client_hello))
        .unwrap();

    server
        .read_tls(&mut io::Cursor::new(&client_hello))
        .unwrap();
    server
        .read_tls(&mut io::Cursor::new(&client_hello))
        .unwrap();
    assert_eq!(
        server
            .process_new_packets()
            .unwrap_err(),
        Error::InappropriateHandshakeMessage {
            expect_types: vec![HandshakeType::ClientKeyExchange],
            got_type: HandshakeType::ClientHello
        }
    );
}

#[test]
fn test_refresh_traffic_keys_during_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Ed25519, &provider::default_provider());
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
    let (mut client, mut server) = make_pair(KeyType::Ed25519, &provider::default_provider());
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
    let provider = aes_128_gcm_with_1024_confidentiality_limit(provider::default_provider());

    let client_config =
        ClientConfig::builder_with_provider(provider.clone()).finish(KeyType::Ed25519);
    let server_config = ServerConfig::builder_with_provider(provider).finish(KeyType::Ed25519);

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
    let provider = Arc::new(
        Arc::unwrap_or_clone(aes_128_gcm_with_1024_confidentiality_limit(dbg!(
            provider::default_provider()
        )))
        .with_only_tls12(),
    );

    let client_config =
        ClientConfig::builder_with_provider(provider.clone()).finish(KeyType::Ed25519);
    let server_config = ServerConfig::builder_with_provider(provider).finish(KeyType::Ed25519);

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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let key = provider
            .key_provider
            .load_private_key(kt.client_key())
            .unwrap();
        let _ = sign::CertifiedKey::new(kt.client_chain(), key).expect("keys match");
        println!("{kt:?} ok");
    }
}

#[test]
fn tls13_packed_handshake() {
    // transcript requires selection of X25519
    if provider_is_fips() {
        return;
    }

    // regression test for https://github.com/rustls/rustls/issues/2040
    // (did not affect the buffered api)
    let client_config = ClientConfig::builder_with_provider(unsafe_plaintext_crypto_provider(
        provider::default_provider(),
    ))
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(MockServerVerifier::rejects_certificate(
        CertificateError::UnknownIssuer.into(),
    )))
    .with_no_client_auth()
    .unwrap();

    let mut client =
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();

    let mut hello = Vec::new();
    client
        .write_tls(&mut io::Cursor::new(&mut hello))
        .unwrap();

    let first_flight = include_bytes!("data/bug2040-message-1.bin");
    client
        .read_tls(&mut io::Cursor::new(first_flight))
        .unwrap();
    client.process_new_packets().unwrap();

    let second_flight = include_bytes!("data/bug2040-message-2.bin");
    client
        .read_tls(&mut io::Cursor::new(second_flight))
        .unwrap();
    assert_eq!(
        client
            .process_new_packets()
            .unwrap_err(),
        Error::InvalidCertificate(CertificateError::UnknownIssuer),
    );
}

#[test]
fn large_client_hello() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::default_provider());
    let hello = include_bytes!("data/bug2227-clienthello.bin");
    let mut cursor = io::Cursor::new(hello);
    loop {
        if server.read_tls(&mut cursor).unwrap() == 0 {
            break;
        }
        server.process_new_packets().unwrap();
    }
}

#[test]
fn large_client_hello_acceptor() {
    let mut acceptor = rustls::server::Acceptor::default();
    let hello = include_bytes!("data/bug2227-clienthello.bin");
    let mut cursor = io::Cursor::new(hello);
    loop {
        acceptor.read_tls(&mut cursor).unwrap();

        if let Some(accepted) = acceptor.accept().unwrap() {
            println!("{accepted:?}");
            break;
        }
    }
}

#[test]
fn hybrid_kx_component_share_offered_but_server_chooses_something_else() {
    let kt = KeyType::Rsa2048;
    let client_config = ClientConfig::builder_with_provider(
        CryptoProvider {
            kx_groups: vec![&FakeHybrid, provider::kx_group::SECP384R1],
            ..provider::default_provider()
        }
        .into(),
    )
    .finish(kt);
    let provider = provider::default_provider();
    let server_config = make_server_config(kt, &provider);

    let (mut client_1, mut server) = make_pair_for_configs(client_config, server_config);
    let (mut client_2, _) = make_pair(kt, &provider);

    // client_2 supplies the ClientHello, client_1 receives the ServerHello
    transfer(&mut client_2, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client_1);
    assert_eq!(
        client_1
            .process_new_packets()
            .unwrap_err(),
        PeerMisbehaved::WrongGroupForKeyShare.into()
    );
}

#[derive(Debug)]
struct FakeHybrid;

impl SupportedKxGroup for FakeHybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(FakeHybridActive))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(0x1234)
    }
}

struct FakeHybridActive;

impl ActiveKeyExchange for FakeHybridActive {
    fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Err(PeerMisbehaved::InvalidKeyShare.into())
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((provider::kx_group::SECP384R1.name(), b"classical"))
    }

    fn pub_key(&self) -> &[u8] {
        b"hybrid"
    }

    fn group(&self) -> NamedGroup {
        FakeHybrid.name()
    }
}

const CONFIDENTIALITY_LIMIT: u64 = 1024;

#[test]
fn server_invalid_sni_policy() {
    const SERVER_NAME_GOOD: &str = "LXXXxxxXXXR";
    const SERVER_NAME_BAD: &str = "[XXXxxxXXX]";
    const SERVER_NAME_IPV4: &str = "10.11.12.13";

    fn replace_sni(sni_replacement: &str) -> impl Fn(&mut Message) -> Altered + '_ {
        assert_eq!(sni_replacement.len(), SERVER_NAME_GOOD.len());
        move |m: &mut Message| match &mut m.payload {
            MessagePayload::Handshake { parsed: _, encoded } => {
                let mut payload_bytes = encoded.bytes().to_vec();
                if let Some(ind) = payload_bytes
                    .windows(SERVER_NAME_GOOD.len())
                    .position(|w| w == SERVER_NAME_GOOD.as_bytes())
                {
                    payload_bytes[ind..][..SERVER_NAME_GOOD.len()]
                        .copy_from_slice(sni_replacement.as_bytes());
                }
                *encoded = Payload::new(payload_bytes);

                Altered::InPlace
            }
            _ => Altered::InPlace,
        }
    }

    #[derive(Debug)]
    enum ExpectedResult {
        Accept,
        AcceptNoSni,
        Reject,
    }
    use ExpectedResult::*;
    use rustls::server::InvalidSniPolicy as Policy;
    let test_cases = [
        (Policy::RejectAll, SERVER_NAME_GOOD, Accept),
        (Policy::RejectAll, SERVER_NAME_IPV4, Reject),
        (Policy::RejectAll, SERVER_NAME_BAD, Reject),
        (Policy::IgnoreAll, SERVER_NAME_GOOD, Accept),
        (Policy::IgnoreAll, SERVER_NAME_IPV4, AcceptNoSni),
        (Policy::IgnoreAll, SERVER_NAME_BAD, AcceptNoSni),
        (Policy::IgnoreIpAddresses, SERVER_NAME_GOOD, Accept),
        (Policy::IgnoreIpAddresses, SERVER_NAME_IPV4, AcceptNoSni),
        (Policy::IgnoreIpAddresses, SERVER_NAME_BAD, Reject),
    ];

    let accept_result = Err(Error::General(
        "no server certificate chain resolved".to_string(),
    ));
    let reject_result = Err(Error::PeerMisbehaved(
        PeerMisbehaved::ServerNameMustContainOneHostName,
    ));

    for (policy, sni, expected_result) in test_cases {
        let provider = provider::default_provider();
        let client_config = make_client_config(KeyType::EcdsaP256, &provider);
        let mut server_config = make_server_config(KeyType::EcdsaP256, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckSni {
            expect_sni: matches!(expected_result, ExpectedResult::Accept),
        });
        server_config.invalid_sni_policy = policy;

        let client =
            ClientConnection::new(Arc::new(client_config), server_name(SERVER_NAME_GOOD)).unwrap();
        let server = ServerConnection::new(Arc::new(server_config)).unwrap();
        let (mut client, mut server) = (client.into(), server.into());

        transfer_altered(&mut client, replace_sni(sni), &mut server);
        assert_eq!(
            &server.process_new_packets(),
            match expected_result {
                Accept | AcceptNoSni => &accept_result,
                Reject => &reject_result,
            }
        );
        println!(
            "test case (policy: {policy:?}, sni: {sni:?}, expected_result: {expected_result:?}) succeeded!"
        );
    }
}

#[derive(Debug)]
struct ServerCheckSni {
    expect_sni: bool,
}

impl ResolvesServerCert for ServerCheckSni {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        assert_eq!(client_hello.server_name().is_some(), self.expect_sni);

        None
    }
}
