//! Tests for key exchange and group negotiation.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::borrow::Cow;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::crypto::kx::{
    ActiveKeyExchange, HybridKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::error::{AlertDescription, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use rustls::internal::msgs::enums::ExtensionType;
use rustls::{ClientConfig, HandshakeKind, ServerConfig};
use rustls_test::{
    ClientConfigExt, ClientStorage, ClientStorageOp, KeyType, OtherSession, ServerConfigExt,
    do_handshake, do_handshake_until_error, encoding, make_client_config_with_kx_groups, make_pair,
    make_pair_for_configs, make_server_config, make_server_config_with_kx_groups, transfer,
};

use super::{ALL_VERSIONS, provider};

#[test]
fn test_client_config_keyshare() {
    let provider = provider::DEFAULT_PROVIDER;
    let kx_groups = vec![provider::kx_group::SECP384R1];
    let client_config =
        make_client_config_with_kx_groups(KeyType::Rsa2048, kx_groups.clone(), &provider);
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa2048, kx_groups, &provider);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let provider = provider::DEFAULT_PROVIDER;
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
        (ProtocolVersion::TLSv1_3, provider::DEFAULT_TLS13_PROVIDER),
        (ProtocolVersion::TLSv1_2, provider::DEFAULT_TLS12_PROVIDER),
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
    let provider = provider::DEFAULT_PROVIDER;
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
        ClientStorageOp::SetKxHint(_, NamedGroup::X25519)
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
    let provider = provider::DEFAULT_PROVIDER;

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
        ClientStorageOp::SetKxHint(_, NamedGroup::secp256r1)
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
        ClientStorageOp::GetKxHint(_, Some(NamedGroup::secp256r1))
    ));
    assert!(matches!(
        ops[9],
        ClientStorageOp::SetKxHint(_, NamedGroup::secp384r1)
    ));
}

#[test]
fn test_client_sends_share_for_less_preferred_group() {
    // this is a test for the case described in:
    // https://datatracker.ietf.org/doc/draft-davidben-tls-key-share-prediction/

    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());
    let provider = provider::DEFAULT_PROVIDER;

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
        ClientStorageOp::SetKxHint(_, NamedGroup::secp384r1)
    ));

    // second handshake; HRR'd from secp384r1 to X25519
    // (but resuming is possible, since the session storage is shared)
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
        Some(HandshakeKind::ResumedWithHelloRetryRequest)
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_groups() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
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
    for version_provider in ALL_VERSIONS {
        let (mut client, mut server) = make_pair_for_configs(
            make_client_config_with_kx_groups(
                KeyType::Rsa2048,
                vec![provider::kx_group::X25519],
                &version_provider,
            ),
            ServerConfig::builder(
                CryptoProvider {
                    kx_groups: Cow::Owned(vec![provider::kx_group::SECP384R1]),
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
fn hybrid_kx_component_share_offered_but_server_chooses_something_else() {
    let kt = KeyType::Rsa2048;
    let client_config = ClientConfig::builder(
        CryptoProvider {
            kx_groups: Cow::Owned(vec![&FakeHybrid, provider::kx_group::SECP384R1]),
            ..provider::DEFAULT_PROVIDER
        }
        .into(),
    )
    .finish(kt);
    let provider = provider::DEFAULT_PROVIDER;
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
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        Ok(StartedKeyExchange::Hybrid(Box::new(FakeHybridActive)))
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

    fn pub_key(&self) -> &[u8] {
        b"hybrid"
    }

    fn group(&self) -> NamedGroup {
        FakeHybrid.name()
    }
}

impl HybridKeyExchange for FakeHybridActive {
    fn component(&self) -> (NamedGroup, &[u8]) {
        (provider::kx_group::SECP384R1.name(), b"classical")
    }

    fn complete_component(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        unimplemented!()
    }

    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static) {
        self
    }

    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange> {
        self
    }
}
