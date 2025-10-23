//! Assorted public API tests.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use core::sync::atomic::{AtomicUsize, Ordering};
use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{CertificateIdentity, Identity};
use rustls::enums::ProtocolVersion;
use rustls::error::{ApiMisuse, Error, PeerMisbehaved};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ServerConfig, ServerConnection};
use rustls_test::{
    ClientConfigExt, ClientStorage, ClientStorageOp, ErrorFromPeer, KeyType, ServerConfigExt,
    do_handshake, do_handshake_until_error, make_client_config, make_client_config_with_auth,
    make_pair, make_pair_for_arc_configs, make_pair_for_configs, make_server_config, transfer,
    webpki_server_verifier_builder,
};

use super::{ALL_VERSIONS, provider};

#[test]
fn client_only_attempts_resumption_with_compatible_security() {
    let provider = provider::DEFAULT_PROVIDER;
    let kt = KeyType::Rsa2048;

    let server_config = make_server_config(kt, &provider);
    for version_provider in ALL_VERSIONS {
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
        let client_config = ClientConfig::builder(Arc::new(version_provider.clone()))
            .add_root_certs(kt)
            .with_client_credential_resolver(
                make_client_config_with_auth(KeyType::EcdsaP256, &version_provider)
                    .resolver()
                    .clone(),
            )
            .unwrap();

        let (mut client, mut server) =
            make_pair_for_configs(client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));

        // disallowed case: unmatching `verifier`
        let mut client_config = ClientConfig::builder(Arc::new(version_provider.clone()))
            .dangerous()
            .with_custom_certificate_verifier(
                webpki_server_verifier_builder(kt.client_root_store(), &version_provider)
                    .allow_unknown_revocation_status()
                    .build()
                    .unwrap(),
            )
            .with_client_credential_resolver(client_config.resolver().clone())
            .unwrap();
        client_config.resumption = base_client_config.resumption.clone();

        let (mut client, mut server) =
            make_pair_for_configs(client_config.clone(), server_config.clone());
        do_handshake(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn resumption_combinations() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = make_server_config(*kt, &provider);
        for (version, version_provider) in [
            (ProtocolVersion::TLSv1_2, provider::DEFAULT_TLS12_PROVIDER),
            (ProtocolVersion::TLSv1_3, provider::DEFAULT_TLS13_PROVIDER),
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

fn expected_kx_for_version(version: ProtocolVersion) -> NamedGroup {
    match (
        version,
        super::provider_is_aws_lc_rs(),
        super::provider_is_fips(),
    ) {
        (ProtocolVersion::TLSv1_3, true, _) => NamedGroup::X25519MLKEM768,
        (_, _, true) => NamedGroup::secp256r1,
        (_, _, _) => NamedGroup::X25519,
    }
}

/// https://github.com/rustls/rustls/issues/797
#[test]
fn test_client_tls12_no_resume_after_server_downgrade() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut client_config = make_client_config(KeyType::Ed25519, &provider);
    let client_storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(client_storage.clone());
    let client_config = Arc::new(client_config);

    let server_config_1 = Arc::new(
        ServerConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into()).finish(KeyType::Ed25519),
    );

    let mut server_config_2 =
        ServerConfig::builder(provider::DEFAULT_TLS12_PROVIDER.into()).finish(KeyType::Ed25519);
    server_config_2.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    dbg!("handshake 1");
    let mut client_1 =
        ClientConnection::new(client_config.clone(), "localhost".try_into().unwrap()).unwrap();
    let mut server_1 = ServerConnection::new(server_config_1).unwrap();
    do_handshake(&mut client_1, &mut server_1);

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
    do_handshake(&mut client_2, &mut server_2);
    println!("hs2 storage ops: {:#?}", client_storage.ops());
    assert_eq!(client_storage.ops().len(), 9);

    // attempt consumes a TLS1.3 ticket
    assert!(matches!(
        client_storage.ops()[7],
        ClientStorageOp::TakeTls13Ticket(_, true)
    ));

    // but ends up with TLS1.2
    assert_eq!(client_2.protocol_version(), Some(ProtocolVersion::TLSv1_2));
}

#[test]
fn test_tls13_client_resumption_does_not_reuse_tickets() {
    let shared_storage = Arc::new(ClientStorage::new());
    let provider = provider::DEFAULT_PROVIDER;

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

#[test]
fn tls13_stateful_resumption() {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_TLS13_PROVIDER;
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
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
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let client_config = make_client_config(kt, &provider);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt, &provider);
    server_config.ticketer = Some(
        provider
            .ticketer_factory
            .ticketer()
            .unwrap(),
    );
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
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
                Identity::X509(CertificateIdentity { intermediates, .. }) => intermediates.len(),
                _ => 0,
            }),
        Some(2)
    );
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn early_data_not_available() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(client.early_data().is_none());
}

fn early_data_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
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
        &provider::DEFAULT_PROVIDER,
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
