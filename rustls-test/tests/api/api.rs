//! Assorted public API tests.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use core::fmt::Debug;
use std::borrow::Cow;
use std::io;
use std::sync::{Arc, Mutex};

use pki_types::{DnsName, SubjectPublicKeyInfoDer};
use provider::cipher_suite;
use rustls::client::Resumption;
use rustls::crypto::cipher::{Payload, PlainMessage};
use rustls::crypto::{
    CipherSuite, Credentials, CryptoProvider, Identity, InconsistentKeys, NamedGroup,
    SelectedCredential, SignatureScheme, Signer, SigningKey,
};
use rustls::enums::{ContentType, HandshakeType, ProtocolVersion};
use rustls::error::{AlertDescription, ApiMisuse, CertificateError, Error, PeerMisbehaved};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::server::{ClientHello, ParsedCertificate, ServerCredentialResolver};
use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, KeyingMaterialExporter, ServerConfig,
    ServerConnection, SupportedCipherSuite,
};
#[cfg(feature = "aws-lc-rs")]
use rustls::{
    client::{EchConfig, EchGreaseConfig, EchMode},
    crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    pki_types::EchConfigListBytes,
};
use rustls_test::{
    Altered, ClientConfigExt, ClientStorage, ClientStorageOp, ErrorFromPeer, KeyType,
    MockServerVerifier, RawTls, ServerConfigExt, do_handshake, do_handshake_until_error,
    do_suite_and_kx_test, encoding, make_client_config, make_client_config_with_auth, make_pair,
    make_pair_for_arc_configs, make_pair_for_configs, make_server_config,
    make_server_config_with_mandatory_client_auth, provider_with_one_suite, provider_with_suites,
    server_name, transfer, transfer_altered, unsafe_plaintext_crypto_provider,
};

use super::{
    ALL_VERSIONS, COUNTS, CountingLogger, provider, provider_is_aws_lc_rs, provider_is_fips,
    provider_is_ring,
};

fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version_provider in ALL_VERSIONS {
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
    let provider = provider::DEFAULT_PROVIDER;
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
    let provider = provider::DEFAULT_PROVIDER;
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
        [ProtocolVersion::TLSv1_3] => CryptoProvider {
            tls12_cipher_suites: Cow::Borrowed(&[]),
            ..provider
        },
        [ProtocolVersion::TLSv1_2] => CryptoProvider {
            tls13_cipher_suites: Cow::Borrowed(&[]),
            ..provider
        },
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
        ClientConfig::builder(
            CryptoProvider {
                kx_groups: Cow::Borrowed(&[]),
                ..provider::DEFAULT_PROVIDER
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
        ClientConfig::builder(
            CryptoProvider {
                tls12_cipher_suites: Cow::Borrowed(&[]),
                tls13_cipher_suites: Cow::Borrowed(&[]),
                ..provider::DEFAULT_PROVIDER
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
        ServerConfig::builder(
            CryptoProvider {
                kx_groups: Cow::Borrowed(&[]),
                ..provider::DEFAULT_PROVIDER
            }
            .into()
        )
        .with_no_client_auth()
        .with_single_cert(KeyType::EcdsaP256.identity(), KeyType::EcdsaP256.key())
        .err(),
        Some(ApiMisuse::NoKeyExchangeGroupsConfigured.into())
    );
}

#[test]
fn config_builder_for_server_rejects_empty_cipher_suites() {
    assert_eq!(
        ServerConfig::builder(
            CryptoProvider {
                tls12_cipher_suites: Cow::Borrowed(&[]),
                tls13_cipher_suites: Cow::Borrowed(&[]),
                ..provider::DEFAULT_PROVIDER
            }
            .into()
        )
        .with_no_client_auth()
        .with_single_cert(KeyType::EcdsaP256.identity(), KeyType::EcdsaP256.key())
        .err(),
        Some(ApiMisuse::NoCipherSuitesConfigured.into())
    );
}

#[test]
fn config_builder_for_client_with_time() {
    ClientConfig::builder_with_details(
        provider::DEFAULT_PROVIDER.into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    );
}

#[test]
fn config_builder_for_server_with_time() {
    ServerConfig::builder_with_details(
        provider::DEFAULT_PROVIDER.into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    );
}

#[test]
fn client_can_get_server_cert() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        for version_provider in ALL_VERSIONS {
            let client_config = make_client_config(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_configs(client_config, make_server_config(*kt, &provider));
            do_handshake(&mut client, &mut server);
            assert_eq!(client.peer_identity().unwrap(), &*kt.identity());
        }
    }
}

#[test]
fn client_can_get_server_cert_after_resumption() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = make_server_config(*kt, &provider);
        for version_provider in ALL_VERSIONS {
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
fn server_can_get_client_cert() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in ALL_VERSIONS {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
            assert_eq!(server.peer_identity().unwrap(), &*kt.client_identity());
        }
    }
}

#[test]
fn server_can_get_client_cert_after_resumption() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in ALL_VERSIONS {
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
fn test_config_builders_debug() {
    if !provider_is_ring() {
        return;
    }

    let b = ServerConfig::builder(
        CryptoProvider {
            tls13_cipher_suites: Cow::Owned(vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
            kx_groups: Cow::Owned(vec![provider::kx_group::X25519]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    );
    let _ = format!("{b:?}");
    let b = ServerConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into());
    let _ = format!("{b:?}");
    let b = b.with_no_client_auth();
    let _ = format!("{b:?}");

    let b = ClientConfig::builder(
        CryptoProvider {
            tls13_cipher_suites: Cow::Owned(vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
            kx_groups: Cow::Owned(vec![provider::kx_group::X25519]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    );
    let _ = format!("{b:?}");
    let b = ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into());
    let _ = format!("{b:?}");
}

#[test]
fn test_tls13_valid_early_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

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
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

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
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

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
fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
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
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
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
    let (_, server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    &server as &dyn Send;
    &server as &dyn Sync;
}

#[allow(clippy::unnecessary_operation)]
#[test]
fn client_is_send_and_sync() {
    let (client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    &client as &dyn Send;
    &client as &dyn Sync;
}

#[test]
fn server_config_is_clone() {
    let _ = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
}

#[test]
fn client_config_is_clone() {
    let _ = make_client_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
}

#[test]
fn client_connection_is_debug() {
    let (client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    println!("{client:?}");
}

#[test]
fn server_connection_is_debug() {
    let (_, server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    println!("{server:?}");
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    for version_provider in ALL_VERSIONS {
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
    let provider = provider::DEFAULT_PROVIDER;
    for version_provider in ALL_VERSIONS {
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
fn test_keys_match() {
    // Consistent: Both of these should have the same SPKI values
    let expect_consistent =
        Credentials::new(KeyType::Rsa2048.identity(), Box::new(SigningKeySomeSpki));
    assert!(expect_consistent.is_ok());

    // Inconsistent: These should not have the same SPKI values
    let expect_inconsistent =
        Credentials::new(KeyType::EcdsaP256.identity(), Box::new(SigningKeySomeSpki));
    assert!(matches!(
        expect_inconsistent,
        Err(Error::InconsistentKeys(InconsistentKeys::KeyMismatch))
    ));

    // Unknown: This signing key returns None for its SPKI, so we can't tell if the certified key is consistent
    assert!(matches!(
        Credentials::new(KeyType::Rsa2048.identity(), Box::new(SigningKeyNoneSpki)),
        Err(Error::InconsistentKeys(InconsistentKeys::Unknown))
    ));
}

/// Represents a SigningKey that returns None for its SPKI via the default impl.
#[derive(Debug)]
struct SigningKeyNoneSpki;

impl SigningKey for SigningKeyNoneSpki {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        unimplemented!("Not meant to be called during tests")
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }
}

/// Represents a SigningKey that returns Some for its SPKI.
#[derive(Debug)]
struct SigningKeySomeSpki;

impl SigningKey for SigningKeySomeSpki {
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let Identity::X509(identity) = &*KeyType::Rsa2048.identity() else {
            panic!("expected X509 identity");
        };

        let cert = ParsedCertificate::try_from(&identity.end_entity).unwrap();
        Some(
            cert.subject_public_key_info()
                .into_owned(),
        )
    }

    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
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
    let provider = provider::DEFAULT_TLS12_PROVIDER;
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
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let server_config = make_server_config(*kt, &provider);

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter_maximum_output_length() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
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
    let provider = provider::DEFAULT_PROVIDER;
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
        let client_config =
            ClientConfig::builder(provider_with_one_suite(&provider::DEFAULT_PROVIDER, scs).into())
                .finish(kt);

        do_suite_and_kx_test(
            client_config,
            make_server_config(kt, &provider::DEFAULT_PROVIDER),
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
        let server_config =
            ServerConfig::builder(provider_with_one_suite(&provider::DEFAULT_PROVIDER, scs).into())
                .finish(kt);

        do_suite_and_kx_test(
            make_client_config(kt, &provider::DEFAULT_PROVIDER),
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

        let mut server_config = ServerConfig::builder(
            provider_with_suites(&provider::DEFAULT_PROVIDER, &[scs, scs_other]).into(),
        )
        .finish(kt);
        server_config.ignore_client_order = true;

        let client_config = ClientConfig::builder(
            provider_with_suites(&provider::DEFAULT_PROVIDER, &[scs_other, scs]).into(),
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

fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {left} < {right}");
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(size_of::<ServerConnection>(), 1600);
    assert_lt(size_of::<ClientConnection>(), 1600);
    assert_lt(
        size_of::<rustls::server::UnbufferedServerConnection>(),
        1600,
    );
    assert_lt(
        size_of::<rustls::client::UnbufferedClientConnection>(),
        1600,
    );
}

#[test]
fn test_client_rejects_illegal_tls13_ccs() {
    fn corrupt_ccs(msg: &mut Message<'_>) -> Altered {
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

    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
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

#[test]
fn test_no_warning_logging_during_successful_sessions() {
    CountingLogger::install();
    CountingLogger::reset();

    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        for version_provider in ALL_VERSIONS {
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

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
#[test]
fn test_explicit_provider_selection() {
    let client_config =
        ClientConfig::builder(rustls_ring::DEFAULT_PROVIDER.into()).finish(KeyType::Rsa2048);

    let server_config = ServerConfig::builder(rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER.into())
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

    let client_config = ClientConfig::builder(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::DEFAULT_PROVIDER
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

    let client_config = ClientConfig::builder(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::DEFAULT_PROVIDER
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

    let client_config = ClientConfig::builder(
        CryptoProvider {
            secure_random: &FAULTY_RANDOM,
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    )
    .finish(KeyType::Rsa2048);

    ClientConnection::new(Arc::new(client_config), server_name("localhost"))
        .expect("check how much random material ClientConnection::new consumes");
}

#[test]
fn test_client_removes_tls12_session_if_server_sends_undecryptable_first_message() {
    fn inject_corrupt_finished_message(msg: &mut Message<'_>) -> Altered {
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

    let provider = provider::DEFAULT_TLS12_PROVIDER;
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
        make_client_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER).fips(),
        provider_is_fips()
    );
}

#[test]
fn test_server_fips_service_indicator() {
    assert_eq!(
        make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER).fips(),
        provider_is_fips()
    );
}

#[test]
fn test_connection_fips_service_indicator() {
    let provider = provider::DEFAULT_PROVIDER;
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

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(client_config.fips());
    client_config.require_ems = false;
    assert!(!client_config.fips());
}

#[test]
fn test_server_fips_service_indicator_includes_require_ems() {
    if !provider_is_fips() {
        return;
    }

    let mut server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
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
        let config = ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into())
            .with_ech(EchMode::Enable(ech_config));
        let config = config.finish(KeyType::Rsa2048);
        assert_eq!(config.fips(), suite.fips());

        // The same applies if an ECH GREASE client configuration is used.
        let (public_key, _) = suite.generate_key_pair().unwrap();
        let config = ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into())
            .with_ech(EchMode::Grease(EchGreaseConfig::new(*suite, public_key)));
        let config = config.finish(KeyType::Rsa2048);
        assert_eq!(config.fips(), suite.fips());

        // And a connection made from a client config should retain the fips status of the
        // config w.r.t the HPKE suite.
        let conn = ClientConnection::new(config.into(), server_name("example.org")).unwrap();
        assert_eq!(conn.fips(), suite.fips());
    }
}

#[test]
fn test_illegal_server_renegotiation_attempt_after_tls13_handshake() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
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
    let provider = provider::DEFAULT_TLS12_PROVIDER;
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
    let provider = provider::DEFAULT_TLS13_PROVIDER;
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
    let provider = provider::DEFAULT_TLS12_PROVIDER;
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
fn tls13_packed_handshake() {
    // transcript requires selection of X25519
    if provider_is_fips() {
        return;
    }

    // regression test for https://github.com/rustls/rustls/issues/2040
    // (did not affect the buffered api)
    let client_config =
        ClientConfig::builder(unsafe_plaintext_crypto_provider(provider::DEFAULT_PROVIDER))
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

    let first_flight = include_bytes!("../data/bug2040-message-1.bin");
    client
        .read_tls(&mut io::Cursor::new(first_flight))
        .unwrap();
    client.process_new_packets().unwrap();

    let second_flight = include_bytes!("../data/bug2040-message-2.bin");
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
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let hello = include_bytes!("../data/bug2227-clienthello.bin");
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
    let hello = include_bytes!("../data/bug2227-clienthello.bin");
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
fn server_invalid_sni_policy() {
    const SERVER_NAME_GOOD: &str = "LXXXxxxXXXR";
    const SERVER_NAME_BAD: &str = "[XXXxxxXXX]";
    const SERVER_NAME_IPV4: &str = "10.11.12.13";

    fn replace_sni(sni_replacement: &str) -> impl Fn(&mut Message<'_>) -> Altered + '_ {
        assert_eq!(sni_replacement.len(), SERVER_NAME_GOOD.len());
        move |m: &mut Message<'_>| match &mut m.payload {
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

    let accept_result = Err(Error::NoSuitableCertificate);
    let reject_result = Err(Error::PeerMisbehaved(
        PeerMisbehaved::ServerNameMustContainOneHostName,
    ));

    for (policy, sni, expected_result) in test_cases {
        let provider = provider::DEFAULT_PROVIDER;
        let client_config = make_client_config(KeyType::EcdsaP256, &provider);
        let mut server_config = make_server_config(KeyType::EcdsaP256, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckSni {
            expect_sni: matches!(expected_result, Accept),
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

impl ServerCredentialResolver for ServerCheckSni {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        assert_eq!(client_hello.server_name().is_some(), self.expect_sni);
        Err(Error::NoSuitableCertificate)
    }
}
