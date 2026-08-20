use std::borrow::Cow;

use rustls::{
    ClientConnection, Connection, Error, Protocol, ServerConnection, VecInput,
    crypto::{AntiReplay, CryptoProvider},
    enums::ProtocolVersion,
};
use rustls_test::{
    KeyType, do_handshake, make_client_config, make_pair_for_configs_with_protocol,
    make_server_config, transfer,
};

use super::provider;

fn setup_test(desired_version: ProtocolVersion) -> TestCase {
    let provider = match desired_version {
        ProtocolVersion::DTLSv1_2 => CryptoProvider {
            tls13_cipher_suites: Cow::Borrowed(&[]),
            ..provider::DEFAULT_PROVIDER
        },
        ProtocolVersion::DTLSv1_3 => CryptoProvider {
            tls12_cipher_suites: Cow::Borrowed(&[]),
            ..provider::DEFAULT_PROVIDER
        },
        _ => panic!("unhandled version {desired_version:?}"),
    };

    let client_config = make_client_config(KeyType::default(), &provider);
    let server_config = make_server_config(KeyType::default(), &provider);

    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair_for_configs_with_protocol(
        Protocol::Udp,
        client_config,
        server_config,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );
    assert_eq!(client.protocol_version().unwrap(), desired_version);
    assert_eq!(server.protocol_version().unwrap(), desired_version);

    return TestCase {
        client_input,
        client_output,
        client,
        server_input,
        server_output,
        server,
    };
}

struct TestCase {
    client_input: VecInput,
    client_output: Vec<u8>,
    client: ClientConnection,
    server_input: VecInput,
    server_output: Vec<u8>,
    server: ServerConnection,
}

fn anti_replay_test(version: ProtocolVersion) {
    let TestCase {
        mut client_output,
        mut client,
        mut server_input,
        mut server_output,
        mut server,
        ..
    } = setup_test(version);

    let client_message = b"client sends application data";
    client
        .write_tls(client_message.into(), &mut client_output)
        .unwrap();

    // Record contents of client_output so we can replay the message later.
    let mut replayed_message = client_output.clone();

    transfer(&mut client_output, &mut server_input);

    let mut server_recv = Vec::new();
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut server_recv)
        .unwrap();

    assert_eq!(server_recv.as_slice(), &client_message[..]);

    // Replay the recorded message into the server and it should get rejected.
    transfer(&mut replayed_message, &mut server_input);

    let err = server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap_err();
    assert_eq!(err, Error::DtlsRecordAntiReplay(AntiReplay::Replay));
}

#[test]
fn anti_replay_dtls_12() {
    anti_replay_test(ProtocolVersion::DTLSv1_2);
}

#[test]
fn anti_replay_dtls_13() {
    anti_replay_test(ProtocolVersion::DTLSv1_3);
}
