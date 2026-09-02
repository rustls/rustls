//! Tests for key exchange and group negotiation.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::borrow::Cow;
use std::io::{IoSlice, Write};
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::crypto::kx::{
    ActiveKeyExchange, HybridKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::error::{AlertDescription, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use rustls::{ClientConfig, Connection, HandshakeKind, ServerConfig, VecInput};
use rustls_test::{
    ClientConfigExt, ClientStorage, ClientStorageOp, ErrorFromPeer, KeyType, MultiTest,
    OtherSession, ServerConfigExt, do_handshake, do_handshake_until_error, encoding,
    make_client_config_with_kx_groups, make_pair, make_pair_for_configs, make_server_config,
    make_server_config_with_kx_groups, transfer,
};

use super::provider;

#[test]
fn test_client_config_keyshare() {
    let provider = provider::DEFAULT_PROVIDER;
    let kx_groups = vec![provider::kx_group::SECP384R1];
    let client_config =
        make_client_config_with_kx_groups(KeyType::default(), kx_groups.clone(), &provider);
    let server_config = make_server_config_with_kx_groups(KeyType::default(), kx_groups, &provider);
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake_until_error(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    )
    .unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let provider = provider::DEFAULT_PROVIDER;
    let client_config = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    let server_config = make_server_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::X25519],
        &provider,
    );
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    assert_eq!(
        do_handshake_until_error(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server
        )
        .err(),
        Some(ErrorFromPeer::Server(
            PeerIncompatible::NoKxGroupsInCommon.into()
        ))
    );
}

#[test]
fn exercise_all_key_exchange_methods() {
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    for (client_config, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        for kx_group in provider::ALL_KX_GROUPS {
            if !kx_group
                .name()
                .usable_for_version(expect.version)
            {
                continue;
            }

            let client_config = make_client_config_with_kx_groups(
                expect.key_type,
                vec![*kx_group],
                client_config.provider(),
            );
            let server_config = make_server_config_with_kx_groups(
                expect.key_type,
                vec![*kx_group],
                server_config.provider(),
            );
            let mut client_output = Vec::new();
            let mut server_output = Vec::new();
            let (mut client, mut server) =
                make_pair_for_configs(client_config, server_config, &mut client_output);
            do_handshake_until_error(
                &mut client_input,
                &mut client_output,
                &mut client,
                &mut server_input,
                &mut server_output,
                &mut server,
            )
            .unwrap();
            println!("kx_group {:?} is self-consistent", kx_group.name());
        }
    }
}

#[test]
fn test_client_sends_helloretryrequest() {
    let provider = provider::DEFAULT_PROVIDER;
    // client sends a secp384r1 key share
    let mut client_config = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP384R1, provider::kx_group::X25519],
        &provider,
    );

    let storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(storage.clone());

    // but server only accepts x25519, so a HRR is required
    let server_config = make_server_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::X25519],
        &provider,
    );

    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    assert_eq!(client.handshake_kind(), None);
    assert_eq!(server.handshake_kind(), None);

    // client sends hello
    {
        let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
        let wrlen = pipe
            .write_vectored(&[IoSlice::new(&client_output)])
            .unwrap();
        client_output.clear();
        assert!(wrlen > 200);
        assert_eq!(pipe.record_lengths().len(), 1);
    }

    assert_eq!(client.handshake_kind(), None);
    assert_eq!(server.handshake_kind(), None);

    // server sends HRR
    {
        let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
        let wrlen = pipe
            .write_vectored(&[IoSlice::new(&server_output)])
            .unwrap();
        server_output.clear();
        assert!(wrlen < 100); // just the hello retry request
        assert_eq!(pipe.record_lengths().len(), 2); // hello retry request and CCS
    }

    assert_eq!(client.handshake_kind(), None);
    assert_eq!(server.handshake_kind(), None);

    // client sends fixed hello
    {
        let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
        let wrlen = pipe
            .write_vectored(&[IoSlice::new(&client_output)])
            .unwrap();
        client_output.clear();
        assert!(wrlen > 200); // just the client hello retry
        assert_eq!(pipe.record_lengths().len(), 2); // only a CCS & client hello retry
    }

    // server completes handshake
    {
        let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
        let wrlen = pipe
            .write_vectored(&[IoSlice::new(&server_output)])
            .unwrap();
        server_output.clear();
        assert!(wrlen > 200);
        assert_eq!(pipe.record_lengths().len(), 2); // { server hello / encrypted exts / cert / cert-verify } / finished
    }

    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );

    do_handshake_until_error(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    )
    .unwrap();

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
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    // first, client sends a secp-256 share and server agrees. secp-256 is inserted
    //   into kx group cache.
    let mut client_config_1 = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP256R1],
        &provider,
    );
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config(KeyType::default(), &provider);

    // first handshake
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client_1, mut server) =
        make_pair_for_configs(client_config_1, server_config.clone(), &mut client_output);
    do_handshake_until_error(
        &mut client_input,
        &mut client_output,
        &mut client_1,
        &mut server_input,
        &mut server_output,
        &mut server,
    )
    .unwrap();

    let ops = shared_storage.ops();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 7);
    assert!(matches!(
        ops[3],
        ClientStorageOp::SetKxHint(_, NamedGroup::secp256r1)
    ));

    // second handshake
    let (mut client_2, mut server) =
        make_pair_for_configs(client_config_2, server_config, &mut client_output);
    do_handshake_until_error(
        &mut client_input,
        &mut client_output,
        &mut client_2,
        &mut server_input,
        &mut server_output,
        &mut server,
    )
    .unwrap();

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
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    // first, client sends a secp384r1 share and server agrees. secp384r1 is inserted
    //   into kx group cache.
    let mut client_config_1 = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client supports (x25519, secp384r1) and so kx group cache
    //   contains a supported but less-preferred group.
    let mut client_config_2 = make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::X25519, provider::kx_group::SECP384R1],
        &provider,
    );
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config_with_kx_groups(
        KeyType::default(),
        provider::ALL_KX_GROUPS.to_vec(),
        &provider,
    );

    // first handshake
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client_1, mut server) =
        make_pair_for_configs(client_config_1, server_config.clone(), &mut client_output);
    do_handshake_until_error(
        &mut client_input,
        &mut client_output,
        &mut client_1,
        &mut server_input,
        &mut server_output,
        &mut server,
    )
    .unwrap();
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
    let (mut client_2, mut server) =
        make_pair_for_configs(client_config_2, server_config, &mut client_output);
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client_2,
        &mut server_input,
        &mut server_output,
        &mut server,
    );
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
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (_, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut server_input = VecInput::default();
    server_input
        .read(
            &mut encoding::record_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                encoding::client_hello_with_extensions(vec![
                    encoding::Extension::new_sig_algs(),
                    encoding::Extension {
                        typ: encoding::Extension::ELLIPTIC_CURVES,
                        body: encoding::len_u16(vec![]),
                    },
                    encoding::Extension {
                        typ: encoding::Extension::KEY_SHARE,
                        body: encoding::len_u16(vec![]),
                    },
                ]),
            )
            .as_slice(),
        )
        .unwrap();

    assert_eq!(
        server
            .read_tls(&mut server_input, &mut server_output)
            .handle_all(&mut Vec::new())
            .unwrap_err(),
        Error::InvalidMessage(InvalidMessage::IllegalEmptyList("NamedGroups"))
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_group_overlap() {
    for (client_config, _, expect) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let base_provider = client_config.provider();
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair_for_configs(
            make_client_config_with_kx_groups(
                expect.key_type,
                vec![provider::kx_group::X25519],
                base_provider,
            ),
            ServerConfig::builder(
                CryptoProvider {
                    kx_groups: Cow::Owned(vec![provider::kx_group::SECP384R1]),
                    ..CryptoProvider::clone(base_provider)
                }
                .into(),
            )
            .finish(KeyType::default()),
            &mut client_output,
        );

        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        transfer(&mut client_output, &mut server_input);
        assert_eq!(
            server
                .read_tls(&mut server_input, &mut server_output)
                .handle_all(&mut Vec::new())
                .unwrap_err(),
            Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
        );

        transfer(&mut server_output, &mut client_input);
        assert_eq!(
            client
                .read_tls(&mut client_input, &mut client_output)
                .handle_all(&mut Vec::new())
                .unwrap_err(),
            Error::AlertReceived(AlertDescription::HandshakeFailure),
        );
    }
}

#[test]
fn hybrid_kx_component_share_offered_but_server_chooses_something_else() {
    let kt = KeyType::default();
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

    let mut client_1_output = Vec::new();
    let mut client_2_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client_1, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_1_output);
    let (_client_2, _) = make_pair(kt, &provider, &mut client_2_output);
    let mut client_1_input = VecInput::default();
    let mut server_input = VecInput::default();

    // client_2 supplies the ClientHello, client_1 receives the ServerHello
    transfer(&mut client_2_output, &mut server_input);
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    transfer(&mut server_output, &mut client_1_input);
    assert_eq!(
        client_1
            .read_tls(&mut client_1_input, &mut client_1_output)
            .handle_all(&mut Vec::new())
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
