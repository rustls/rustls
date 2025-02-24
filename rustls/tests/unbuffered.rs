#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::num::NonZeroUsize;

use rustls::client::{ClientConnectionData, EarlyDataError, UnbufferedClientConnection};
use rustls::crypto::CryptoProvider;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, ReadTraffic,
    UnbufferedConnectionCommon, UnbufferedStatus, WriteTraffic,
};
use rustls::version::TLS13;
use rustls::{
    AlertDescription, CertificateError, ClientConfig, ConnectionTrafficSecrets, Error,
    InvalidMessage, ServerConfig, SideData,
};

use super::*;

mod common;
use common::*;
use provider::cipher_suite;

const MAX_ITERATIONS: usize = 100;

#[test]
fn tls12_handshake() {
    let outcome = handshake(&rustls::version::TLS12);

    assert_eq!(
        outcome.client_transcript, TLS12_CLIENT_TRANSCRIPT,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, TLS12_SERVER_TRANSCRIPT,
        "server transcript mismatch"
    );
}

#[test]
fn tls12_handshake_fragmented() {
    let outcome = handshake_config(&rustls::version::TLS12, |client, server| {
        client.max_fragment_size = Some(512);
        client.cert_decompressors = vec![];
        server.max_fragment_size = Some(512);
    });

    let mut expected_client = TLS12_CLIENT_TRANSCRIPT_FRAGMENTED.to_vec();
    let mut expected_server = TLS12_SERVER_TRANSCRIPT_FRAGMENTED.to_vec();
    if provider_is_aws_lc_rs() && cfg!(feature = "prefer-post-quantum") {
        // client hello is larger for X25519MLKEM768
        expected_client.splice(0..0, ["EncodeTlsData", "EncodeTlsData"]);
        expected_server.splice(0..0, ["BlockedHandshake", "BlockedHandshake"]);
    }
    assert_eq!(
        outcome.client_transcript, expected_client,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, expected_server,
        "server transcript mismatch"
    );
}

#[test]
fn tls13_handshake() {
    let outcome = handshake(&rustls::version::TLS13);

    assert_eq!(
        outcome.client_transcript, TLS13_CLIENT_TRANSCRIPT,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, TLS13_SERVER_TRANSCRIPT,
        "server transcript mismatch"
    );
}

#[test]
fn tls13_handshake_fragmented() {
    let outcome = handshake_config(&rustls::version::TLS13, |client, server| {
        client.max_fragment_size = Some(512);
        client.cert_decompressors = vec![];
        server.max_fragment_size = Some(512);
    });

    let mut expected_client = TLS13_CLIENT_TRANSCRIPT_FRAGMENTED.to_vec();
    let mut expected_server = TLS13_SERVER_TRANSCRIPT_FRAGMENTED.to_vec();

    if provider_is_aws_lc_rs() && cfg!(feature = "prefer-post-quantum") {
        // client hello is larger for X25519MLKEM768
        expected_client.splice(0..0, ["EncodeTlsData", "EncodeTlsData"]);
        expected_server.splice(0..0, ["BlockedHandshake", "BlockedHandshake"]);

        // and server flight
        expected_client.splice(4..4, ["BlockedHandshake", "BlockedHandshake"]);
        expected_server.splice(4..4, ["EncodeTlsData", "EncodeTlsData"]);
    }

    assert_eq!(
        outcome.client_transcript, expected_client,
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript, expected_server,
        "server transcript mismatch"
    );
}

fn handshake(version: &'static rustls::SupportedProtocolVersion) -> Outcome {
    handshake_config(version, |_, _| ())
}

fn handshake_config(
    version: &'static rustls::SupportedProtocolVersion,
    editor: impl Fn(&mut ClientConfig, &mut ServerConfig),
) -> Outcome {
    let mut server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
    let mut client_config = make_client_config(KeyType::Rsa2048);
    editor(&mut client_config, &mut server_config);

    run(
        Arc::new(client_config),
        &mut NO_ACTIONS.clone(),
        Arc::new(server_config),
        &mut NO_ACTIONS.clone(),
    )
}

#[test]
fn app_data_client_to_server() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
        let client_config = make_client_config(KeyType::Rsa2048);

        let mut client_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };

        let outcome = run(
            Arc::new(client_config),
            &mut client_actions,
            Arc::new(server_config),
            &mut NO_ACTIONS.clone(),
        );

        assert!(
            client_actions
                .app_data_to_send
                .is_none()
        );
        assert_eq!(
            [expected],
            outcome
                .server_received_app_data
                .as_slice()
        );
    }
}

#[test]
fn app_data_server_to_client() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
        let client_config = make_client_config(KeyType::Rsa2048);

        let mut server_actions = Actions {
            app_data_to_send: Some(expected),
            ..NO_ACTIONS
        };

        let outcome = run(
            Arc::new(client_config),
            &mut NO_ACTIONS.clone(),
            Arc::new(server_config),
            &mut server_actions,
        );

        assert!(
            server_actions
                .app_data_to_send
                .is_none()
        );
        assert_eq!(
            [expected],
            outcome
                .client_received_app_data
                .as_slice()
        );
    }
}

#[test]
fn early_data() {
    let expected: &[_] = b"hello";

    let mut server_config = make_server_config(KeyType::Rsa2048);
    server_config.max_early_data_size = 128;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config_with_versions(KeyType::Rsa2048, &[&TLS13]);
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    // first handshake allows the second to be a resumption and use 0-RTT
    run(
        client_config.clone(),
        &mut NO_ACTIONS.clone(),
        server_config.clone(),
        &mut NO_ACTIONS.clone(),
    );

    let mut client_actions = Actions {
        early_data_to_send: Some(expected),
        ..NO_ACTIONS
    };

    let outcome = run(
        client_config.clone(),
        &mut client_actions,
        server_config.clone(),
        &mut NO_ACTIONS.clone(),
    );

    assert_eq!(
        outcome.client_transcript,
        vec![
            "EncodeTlsData",
            "EncodeTlsData",
            "TransmitTlsData",
            "BlockedHandshake",
            "BlockedHandshake",
            "EncodeTlsData",
            "EncodeTlsData",
            "TransmitTlsData",
            "WriteTraffic",
            "WriteTraffic"
        ]
    );
    assert_eq!(
        outcome.server_transcript,
        vec![
            "BlockedHandshake",
            "EncodeTlsData",
            "EncodeTlsData",
            "EncodeTlsData",
            "ReadEarlyData",
            "TransmitTlsData",
            "BlockedHandshake",
            "EncodeTlsData",
            "TransmitTlsData",
            "WriteTraffic"
        ]
    );
    assert!(
        client_actions
            .early_data_to_send
            .is_none()
    );
    assert_eq!(
        [expected],
        outcome
            .server_received_early_data
            .as_slice()
    );
}

fn run(
    client_config: Arc<ClientConfig>,
    client_actions: &mut Actions,
    server_config: Arc<ServerConfig>,
    server_actions: &mut Actions,
) -> Outcome {
    let mut outcome = Outcome::default();
    let mut count = 0;
    let mut client_handshake_done = false;
    let mut server_handshake_done = false;

    let mut client =
        UnbufferedClientConnection::new(client_config.clone(), server_name("localhost")).unwrap();
    let mut server = UnbufferedServerConnection::new(server_config.clone()).unwrap();
    let mut buffers = BothBuffers::default();

    while !(client_handshake_done
        && server_handshake_done
        && client_actions.finished()
        && server_actions.finished())
    {
        match advance_client(
            &mut client,
            &mut buffers.client,
            *client_actions,
            &mut outcome.client_transcript,
        ) {
            State::EncodedTlsData => {}
            State::TransmitTlsData {
                sent_early_data,
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.client_send();
                if sent_app_data {
                    client_actions.app_data_to_send = None;
                }

                if sent_early_data {
                    client_actions.early_data_to_send = None;
                }

                if sent_close_notify {
                    client_actions.send_close_notify = false;
                }
            }
            State::BlockedHandshake => buffers.server_send(),
            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.client_send();

                if sent_app_data {
                    client_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    client_actions.send_close_notify = false;
                }

                client_handshake_done = true;
            }
            State::ReceivedAppData { records } => {
                outcome
                    .client_received_app_data
                    .extend(records);
            }
            State::PeerClosed => {
                outcome.client_saw_peer_closed_state = true;
            }
            State::Closed => {}
            state => unreachable!("{state:?}"),
        }

        match advance_server(
            &mut server,
            &mut buffers.server,
            *server_actions,
            &mut outcome.server_transcript,
        ) {
            State::EncodedTlsData => {}
            State::TransmitTlsData {
                sent_app_data,
                sent_close_notify,
                ..
            } => {
                buffers.server_send();

                if sent_app_data {
                    server_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    server_actions.send_close_notify = false;
                }
            }
            State::BlockedHandshake => buffers.client_send(),
            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            } => {
                buffers.server_send();

                if sent_app_data {
                    server_actions.app_data_to_send = None;
                }

                if sent_close_notify {
                    server_actions.send_close_notify = false;
                }

                server_handshake_done = true;
            }
            State::ReceivedEarlyData { records } => {
                outcome
                    .server_received_early_data
                    .extend(records);
            }
            State::ReceivedAppData { records } => {
                outcome
                    .server_received_app_data
                    .extend(records);
            }
            State::PeerClosed => {
                outcome.server_saw_peer_closed_state = true;
            }
            State::Closed => {}
        }

        count += 1;

        assert!(count <= MAX_ITERATIONS, "handshake was not completed");
    }

    println!("finished with:");
    println!(
        "  client: {:?} {:?} {:?}",
        client.protocol_version(),
        client.negotiated_cipher_suite(),
        client.handshake_kind()
    );
    println!(
        "  server: {:?} {:?} {:?}",
        server.protocol_version(),
        server.negotiated_cipher_suite(),
        server.handshake_kind()
    );

    outcome.server = Some(server);
    outcome.client = Some(client);
    outcome
}

#[test]
fn close_notify_client_to_server() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
        let client_config = make_client_config(KeyType::Rsa2048);

        let mut client_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };

        let outcome = run(
            Arc::new(client_config),
            &mut client_actions,
            Arc::new(server_config),
            &mut NO_ACTIONS.clone(),
        );

        assert!(!client_actions.send_close_notify);
        assert!(outcome.server_saw_peer_closed_state);
    }
}

#[test]
fn close_notify_server_to_client() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
        let client_config = make_client_config(KeyType::Rsa2048);

        let mut server_actions = Actions {
            send_close_notify: true,
            ..NO_ACTIONS
        };

        let outcome = run(
            Arc::new(client_config),
            &mut NO_ACTIONS.clone(),
            Arc::new(server_config),
            &mut server_actions,
        );

        assert!(!server_actions.send_close_notify);
        assert!(outcome.client_saw_peer_closed_state);
    }
}

#[test]
fn full_closure_server_to_client() {
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");
        let mut outcome = handshake(version);
        let mut client = outcome.client.take().unwrap();
        let mut server = outcome.server.take().unwrap();

        let mut buf = Buffer::default();

        // server sends message followed by close_notify, in one flight
        write_traffic(
            server.process_tls_records(&mut []),
            |mut wt: WriteTraffic<_>| {
                encrypt(&mut wt, b"hello", &mut buf);
                queue_close_notify(&mut wt, &mut buf);
            },
        );

        let (_, discard) = read_traffic(client.process_tls_records(buf.filled()), |mut rt| {
            assert_eq!(rt.peek_len(), NonZeroUsize::new(5));
            let app_data = rt.next_record().unwrap().unwrap();
            assert_eq!(app_data.payload, b"hello");
        });
        buf.discard(discard);

        let discard = peer_closed(client.process_tls_records(buf.filled()));
        buf.discard(discard);
        assert_eq!(buf.used, 0);

        // client replies with its own data and close_notify
        write_traffic(client.process_tls_records(&mut []), |mut wt| {
            encrypt(&mut wt, b"goodbye", &mut buf);
            queue_close_notify(&mut wt, &mut buf);
        });

        let (_, discard) = read_traffic(server.process_tls_records(buf.filled()), |mut rt| {
            assert_eq!(rt.peek_len(), NonZeroUsize::new(7));
            let app_data = rt.next_record().unwrap().unwrap();
            assert_eq!(app_data.payload, b"goodbye");
        });
        buf.discard(discard);

        let discard = peer_closed(server.process_tls_records(buf.filled()));
        buf.discard(discard);
        assert_eq!(buf.used, 0);

        closed(client.process_tls_records(&mut []));
        closed(server.process_tls_records(&mut []));
    }
}

#[test]
fn junk_after_close_notify_received() {
    // cf. test_junk_after_close_notify_received in api.rs
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();

    let mut client_send_buf = [0u8; 128];
    let mut len = dbg!(
        write_traffic(
            client.process_tls_records(&mut []),
            |mut wt: WriteTraffic<_>| wt.queue_close_notify(&mut client_send_buf),
        )
        .unwrap()
    );

    client_send_buf[len..len + 4].copy_from_slice(&[0x17, 0x03, 0x03, 0x01]);
    len += 4;

    let discard = match dbg!(server.process_tls_records(dbg!(&mut client_send_buf[..len]))) {
        UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::PeerClosed),
        } => {
            assert_eq!(discard, 24);
            discard
        }
        st => {
            panic!("unexpected server state {st:?} (wanted PeerClosed)");
        }
    };

    // further data in client_send_buf is ignored
    let UnbufferedStatus { discard, .. } =
        server.process_tls_records(dbg!(&mut client_send_buf[discard..len]));
    assert_eq!(discard, 0);
}

#[test]
fn queue_close_notify_is_idempotent() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();

    let mut client_send_buf = [0u8; 128];
    let (len_first, len_second) = write_traffic(
        client.process_tls_records(&mut []),
        |mut wt: WriteTraffic<_>| {
            (
                wt.queue_close_notify(&mut client_send_buf),
                wt.queue_close_notify(&mut client_send_buf),
            )
        },
    );

    assert!(len_first.unwrap() > 0);
    assert_eq!(len_second.unwrap(), 0);
}

#[test]
fn refresh_traffic_keys_on_tls12_connection() {
    let mut outcome = handshake(&rustls::version::TLS12);
    let mut client = outcome.client.take().unwrap();

    match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::WriteTraffic(wt)),
        } => {
            assert_eq!(
                wt.refresh_traffic_keys().unwrap_err(),
                Error::HandshakeNotComplete,
            );
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };
}

#[test]
fn refresh_traffic_keys_manually() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();

    match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::WriteTraffic(wt)),
        } => {
            wt.refresh_traffic_keys().unwrap();
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    let mut buffer = [0u8; 64];
    let used = match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::EncodeTlsData(mut etd)),
        } => {
            println!("EncodeTlsData");
            etd.encode(&mut buffer).unwrap()
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::TransmitTlsData(ttd)),
        } => {
            ttd.done();
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    println!("server WriteTraffic");
    let used = match server.process_tls_records(&mut buffer[..used]) {
        UnbufferedStatus {
            discard: actual_used,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } => {
            assert_eq!(used, actual_used);
            wt.encrypt(b"hello", &mut buffer)
                .unwrap()
        }
        st => {
            panic!("unexpected server state {st:?}");
        }
    };

    println!("client recv");
    match client.process_tls_records(&mut buffer[..used]) {
        UnbufferedStatus {
            discard: actual_used,
            state: Ok(ConnectionState::ReadTraffic(mut rt)),
        } => {
            assert_eq!(used, actual_used);
            let app_data = rt.next_record().unwrap().unwrap();
            assert_eq!(app_data.payload, b"hello");
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    println!("client reply");
    let used = match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } => wt
            .encrypt(b"world", &mut buffer)
            .unwrap(),
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    match server.process_tls_records(&mut buffer[..used]) {
        UnbufferedStatus {
            discard: actual_used,
            state: Ok(ConnectionState::ReadTraffic(mut rt)),
        } => {
            assert_eq!(used, actual_used);
            let app_data = rt.next_record().unwrap().unwrap();
            assert_eq!(app_data.payload, b"world");
        }
        st => {
            panic!("unexpected server state {st:?}");
        }
    };
}

#[test]
fn refresh_traffic_keys_automatically() {
    const fn encrypted_size(body: usize) -> usize {
        let padding = 1;
        let header = 5;
        let tag = 16;
        header + body + padding + tag
    }

    const KEY_UPDATE_SIZE: usize = encrypted_size(5);
    const CONFIDENTIALITY_LIMIT: usize = 1024;
    const CONFIDENTIALITY_LIMIT_PLUS_ONE: usize = CONFIDENTIALITY_LIMIT + 1;

    let client_config = finish_client_config(
        KeyType::Rsa2048,
        ClientConfig::builder_with_provider(aes_128_gcm_with_1024_confidentiality_limit())
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let server_config = make_server_config(KeyType::Rsa2048);
    let mut outcome = run(
        Arc::new(client_config),
        &mut NO_ACTIONS.clone(),
        Arc::new(server_config),
        &mut NO_ACTIONS.clone(),
    );
    let mut server = outcome.server.take().unwrap();
    let mut client = outcome.client.take().unwrap();

    match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } => {
            // Must happen on a single `WriteTraffic` instance, to
            // validate that handshake messages are included
            // in the TLS records returned by `WriteTraffic::encrypt`
            for i in 0..(CONFIDENTIALITY_LIMIT + 16) {
                let message = format!("{i:08}");

                let mut buffer = [0u8; 64];
                let used = wt
                    .encrypt(message.as_bytes(), &mut buffer)
                    .unwrap();

                assert_eq!(
                    used,
                    match i {
                        // The key_update message triggered by write N appears in write N+1
                        CONFIDENTIALITY_LIMIT_PLUS_ONE =>
                            KEY_UPDATE_SIZE + encrypted_size(message.len()),
                        _ => encrypted_size(message.len()),
                    }
                );

                match server.process_tls_records(&mut buffer[..used]) {
                    UnbufferedStatus {
                        discard: actual_used,
                        state: Ok(ConnectionState::ReadTraffic(mut rt)),
                    } => {
                        assert_eq!(used, actual_used);
                        let record = rt.next_record().unwrap().unwrap();
                        assert_eq!(record.payload, message.as_bytes());
                    }
                    st => {
                        panic!("unexpected server state {st:?}");
                    }
                };
                println!("{i}: wrote {used}");
            }
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };
}

#[test]
fn tls12_connection_fails_after_key_reaches_confidentiality_limit() {
    const CONFIDENTIALITY_LIMIT: usize = 1024;

    let client_config = finish_client_config(
        KeyType::Ed25519,
        ClientConfig::builder_with_provider(aes_128_gcm_with_1024_confidentiality_limit())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap(),
    );

    let server_config = make_server_config(KeyType::Ed25519);
    let mut outcome = run(
        Arc::new(client_config),
        &mut NO_ACTIONS.clone(),
        Arc::new(server_config),
        &mut NO_ACTIONS.clone(),
    );
    let mut server = outcome.server.take().unwrap();
    let mut client = outcome.client.take().unwrap();

    match client.process_tls_records(&mut []) {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::WriteTraffic(mut wt)),
        } => {
            for i in 0..CONFIDENTIALITY_LIMIT {
                let message = format!("{i:08}");

                let mut buffer = [0u8; 64];
                let used = match wt.encrypt(message.as_bytes(), &mut buffer) {
                    Ok(used) => used,
                    Err(EncryptError::EncryptExhausted) if i == CONFIDENTIALITY_LIMIT - 1 => {
                        break;
                    }
                    rc @ Err(_) => rc.unwrap(),
                };

                match server.process_tls_records(&mut buffer[..used]) {
                    UnbufferedStatus {
                        discard: actual_used,
                        state: Ok(ConnectionState::ReadTraffic(mut rt)),
                    } => {
                        assert_eq!(used, actual_used);
                        let record = rt.next_record().unwrap().unwrap();
                        assert_eq!(record.payload, message.as_bytes());
                    }
                    st => {
                        panic!("unexpected server state {st:?}");
                    }
                };
                println!("{i}: wrote {used}");
            }
        }
        st => {
            panic!("unexpected client state {st:?}");
        }
    };

    let (mut data, _) = encode_tls_data(client.process_tls_records(&mut []));
    let data_len = data.len();

    match server.process_tls_records(&mut data) {
        UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::PeerClosed),
        } if discard == data_len => {}
        st => panic!("unexpected server state {st:?}"),
    }
}

#[test]
fn tls13_packed_handshake() {
    // transcript requires selection of X25519
    if provider_is_fips() {
        return;
    }

    // regression test for https://github.com/rustls/rustls/issues/2040
    let client_config = ClientConfig::builder_with_provider(unsafe_plaintext_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MockServerVerifier::rejects_certificate(
            CertificateError::UnknownIssuer.into(),
        )))
        .with_no_client_auth();

    let mut client =
        UnbufferedClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();

    let (_hello, _) = encode_tls_data(client.process_tls_records(&mut []));
    confirm_transmit_tls_data(client.process_tls_records(&mut []));

    let mut first_flight = include_bytes!("data/bug2040-message-1.bin").to_vec();
    let (_ccs, discard) = encode_tls_data(client.process_tls_records(&mut first_flight[..]));
    assert_eq!(discard, first_flight.len());

    let mut second_flight = include_bytes!("data/bug2040-message-2.bin").to_vec();
    let UnbufferedStatus { state, .. } = client.process_tls_records(&mut second_flight[..]);
    assert_eq!(
        state.unwrap_err(),
        Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
}

#[test]
fn rejects_junk() {
    let mut server =
        UnbufferedServerConnection::new(Arc::new(make_server_config(KeyType::Rsa2048))).unwrap();

    let mut buf = [0xff; 5];
    let UnbufferedStatus { discard, state } = server.process_tls_records(&mut buf);
    assert_eq!(discard, 0);
    assert_eq!(
        state.unwrap_err(),
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
    );

    // sends alert
    let (data, _) = encode_tls_data(server.process_tls_records(&mut []));
    assert_eq!(
        data,
        &[
            0x15,
            0x03,
            0x03,
            0x00,
            0x02,
            0x02,
            u8::from(AlertDescription::DecodeError)
        ]
    );
    confirm_transmit_tls_data(server.process_tls_records(&mut []));
}

#[test]
fn read_traffic_not_consumed_too_early() {
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();

    let mut client_to_server_buf = Buffer::default();
    write_traffic(client.process_tls_records(&mut []), |mut wt| {
        encrypt(&mut wt, b"hello", &mut client_to_server_buf)
    });

    // if we just peek, we are presented the same data again
    let (_, discard) = read_traffic(
        server.process_tls_records(client_to_server_buf.filled()),
        |rt| assert_eq!(rt.peek_len(), NonZeroUsize::new(5)),
    );
    assert!(discard > 0);
    client_to_server_buf.discard(discard);

    // ditto
    let (_, discard) = read_traffic(
        server.process_tls_records(client_to_server_buf.filled()),
        |rt| assert_eq!(rt.peek_len(), NonZeroUsize::new(5)),
    );
    assert_eq!(discard, 0);

    // now consume
    let (data, discard) = read_traffic(
        server.process_tls_records(client_to_server_buf.filled()),
        |mut rt| {
            rt.next_record()
                .unwrap()
                .unwrap()
                .payload
                .to_vec()
        },
    );
    assert_eq!(discard, 0);
    assert_eq!(data, b"hello");

    // server is now idle
    write_traffic(
        server.process_tls_records(client_to_server_buf.filled()),
        |_| (),
    );
}

fn write_traffic<T: SideData, R, F: FnMut(WriteTraffic<T>) -> R>(
    status: UnbufferedStatus<'_, '_, T>,
    mut f: F,
) -> R {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    match state.unwrap() {
        ConnectionState::WriteTraffic(state) => f(state),
        other => panic!("unexpected state {other:?} (wanted WriteTraffic)"),
    }
}

fn read_traffic<T: SideData, R, F: FnMut(ReadTraffic<T>) -> R>(
    status: UnbufferedStatus<'_, '_, T>,
    mut f: F,
) -> (R, usize) {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::ReadTraffic(state) => (f(state), discard),
        other => panic!("unexpected state {other:?} (wanted ReadTraffic)"),
    }
}

fn peer_closed<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> usize {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::PeerClosed => discard,
        other => panic!("unexpected state {other:?} (wanted PeerClosed)"),
    }
}

fn closed<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> usize {
    let UnbufferedStatus { discard, state } = status;
    match state.unwrap() {
        ConnectionState::Closed => discard,
        other => panic!("unexpected state {other:?} (wanted Closed)"),
    }
}

fn encode_tls_data<T: SideData>(status: UnbufferedStatus<'_, '_, T>) -> (Vec<u8>, usize) {
    match status {
        UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::EncodeTlsData(mut etd)),
        } => {
            let len = match etd.encode(&mut []) {
                Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                    required_size
                }
                e => panic!("unexpected encode {e:?}"),
            };
            let mut buf = vec![0u8; len];
            etd.encode(&mut buf).unwrap();
            (buf, discard)
        }
        _ => {
            panic!("unexpected state {status:?} (wanted EncodeTlsData)");
        }
    }
}

fn confirm_transmit_tls_data<T: SideData>(status: UnbufferedStatus<'_, '_, T>) {
    match status {
        UnbufferedStatus {
            discard: 0,
            state: Ok(ConnectionState::TransmitTlsData(ttd)),
        } => {
            ttd.done();
        }
        _ => {
            panic!("unexpected state {status:?} (wanted TransmitTlsData)");
        }
    }
}

#[derive(Debug)]
enum State {
    Closed,
    PeerClosed,
    EncodedTlsData,
    TransmitTlsData {
        sent_app_data: bool,
        sent_close_notify: bool,
        sent_early_data: bool,
    },
    BlockedHandshake,
    ReceivedAppData {
        records: Vec<Vec<u8>>,
    },
    ReceivedEarlyData {
        records: Vec<Vec<u8>>,
    },
    WriteTraffic {
        sent_app_data: bool,
        sent_close_notify: bool,
    },
}

const NO_ACTIONS: Actions = Actions {
    app_data_to_send: None,
    early_data_to_send: None,
    send_close_notify: false,
};

#[derive(Clone, Copy, Debug)]
struct Actions<'a> {
    app_data_to_send: Option<&'a [u8]>,
    early_data_to_send: Option<&'a [u8]>,
    send_close_notify: bool,
}

impl Actions<'_> {
    fn finished(&self) -> bool {
        self.app_data_to_send.is_none()
            && self.early_data_to_send.is_none()
            && !self.send_close_notify
    }
}

#[derive(Default)]
struct Outcome {
    server: Option<UnbufferedServerConnection>,
    server_transcript: Vec<String>,
    server_received_early_data: Vec<Vec<u8>>,
    server_received_app_data: Vec<Vec<u8>>,
    server_saw_peer_closed_state: bool,
    client: Option<UnbufferedClientConnection>,
    client_transcript: Vec<String>,
    client_received_app_data: Vec<Vec<u8>>,
    client_saw_peer_closed_state: bool,
}

fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    let UnbufferedStatus { discard, state } = conn.process_tls_records(buffers.incoming.filled());
    let state = state.unwrap();

    transcript.push(format!("{:?}", state));

    let state = match state {
        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_early_data = false;
            if let (Some(early_data), Some(mut state)) =
                (actions.early_data_to_send, state.may_encrypt_early_data())
            {
                write_with_buffer_size_checks(
                    |out_buf| state.encrypt(early_data, out_buf),
                    |e| {
                        println!("encrypt error: {e}");
                        match e {
                            EarlyDataError::Encrypt(EncryptError::InsufficientSize(ise)) => ise,
                            _ => unreachable!(),
                        }
                    },
                    &mut buffers.outgoing,
                );
                sent_early_data = true;
            }
            state.done();
            State::TransmitTlsData {
                sent_app_data: false,
                sent_close_notify: false,
                sent_early_data,
            }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

fn advance_server(
    conn: &mut UnbufferedConnectionCommon<ServerConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    let UnbufferedStatus { discard, state } = conn.process_tls_records(buffers.incoming.filled());
    let state = state.unwrap();

    transcript.push(format!("{:?}", state));

    let state = match state {
        ConnectionState::ReadEarlyData(mut state) => {
            let mut records = vec![];
            let mut peeked_len = state.peek_len();

            while let Some(res) = state.next_record() {
                let payload = res.unwrap().payload.to_vec();
                assert_eq!(NonZeroUsize::new(payload.len()), peeked_len);
                records.push(payload);
                peeked_len = state.peek_len();
            }

            assert_eq!(None, peeked_len);

            State::ReceivedEarlyData { records }
        }

        state => handle_state(state, &mut buffers.outgoing, actions),
    };
    buffers.incoming.discard(discard);

    state
}

fn handle_state<Data>(
    state: ConnectionState<'_, '_, Data>,
    outgoing: &mut Buffer,
    actions: Actions,
) -> State {
    match dbg!(state) {
        ConnectionState::EncodeTlsData(mut state) => {
            write_with_buffer_size_checks(
                |out_buf| state.encode(out_buf),
                |e| {
                    println!("encode error: {e}");
                    match e {
                        EncodeError::InsufficientSize(ise) => ise,
                        _ => unreachable!(),
                    }
                },
                outgoing,
            );

            assert!(matches!(
                state.encode(&mut []).unwrap_err(),
                EncodeError::AlreadyEncoded
            ));

            State::EncodedTlsData
        }

        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_app_data = false;
            if let (Some(app_data), Some(mut state)) =
                (actions.app_data_to_send, state.may_encrypt_app_data())
            {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            let mut sent_close_notify = false;
            if let Some(mut state) = state.may_encrypt_app_data() {
                if actions.send_close_notify {
                    queue_close_notify(&mut state, outgoing);
                    sent_close_notify = true;
                }
            }

            // this should be called *after* the data has been transmitted but it's easier to
            // do it in reverse
            state.done();
            State::TransmitTlsData {
                sent_app_data,
                sent_early_data: false,
                sent_close_notify,
            }
        }

        ConnectionState::BlockedHandshake { .. } => State::BlockedHandshake,

        ConnectionState::WriteTraffic(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            let mut sent_close_notify = false;
            if actions.send_close_notify {
                queue_close_notify(&mut state, outgoing);
                sent_close_notify = true;
            }

            State::WriteTraffic {
                sent_app_data,
                sent_close_notify,
            }
        }

        ConnectionState::ReadTraffic(mut state) => {
            let mut records = vec![];
            let mut peeked_len = state.peek_len();

            while let Some(res) = state.next_record() {
                let payload = res.unwrap().payload.to_vec();
                assert_eq!(NonZeroUsize::new(payload.len()), peeked_len);
                records.push(payload);
                peeked_len = state.peek_len();
            }

            assert_eq!(None, peeked_len);

            State::ReceivedAppData { records }
        }

        ConnectionState::PeerClosed => State::PeerClosed,
        ConnectionState::Closed => State::Closed,

        _ => unreachable!(),
    }
}

fn queue_close_notify<Data>(state: &mut WriteTraffic<'_, Data>, outgoing: &mut Buffer) {
    write_with_buffer_size_checks(
        |out_buf| state.queue_close_notify(out_buf),
        map_encrypt_error,
        outgoing,
    );
}

fn encrypt<Data>(state: &mut WriteTraffic<'_, Data>, app_data: &[u8], outgoing: &mut Buffer) {
    write_with_buffer_size_checks(
        |out_buf| state.encrypt(app_data, out_buf),
        map_encrypt_error,
        outgoing,
    );
}

fn map_encrypt_error(e: EncryptError) -> InsufficientSizeError {
    match e {
        EncryptError::InsufficientSize(ise) => ise,
        _ => unreachable!(),
    }
}

fn write_with_buffer_size_checks<E: core::fmt::Debug>(
    mut try_write: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> InsufficientSizeError,
    outgoing: &mut Buffer,
) {
    let required_size = map_err(try_write(&mut []).unwrap_err()).required_size;
    let written = try_write(outgoing.unfilled()).unwrap();
    assert_eq!(required_size, written);
    outgoing.advance(written);
}

#[derive(Default)]
struct BothBuffers {
    client: Buffers,
    server: Buffers,
}

impl BothBuffers {
    fn client_send(&mut self) {
        let client_data = self.client.outgoing.filled();
        let num_bytes = client_data.len();
        if num_bytes == 0 {
            return;
        }
        self.server.incoming.append(client_data);
        self.client.outgoing.clear();
        eprintln!("client sent {num_bytes}B");
    }

    fn server_send(&mut self) {
        let server_data = self.server.outgoing.filled();
        let num_bytes = server_data.len();
        if num_bytes == 0 {
            return;
        }
        self.client.incoming.append(server_data);
        self.server.outgoing.clear();
        eprintln!("server sent {num_bytes}B");
    }
}

#[derive(Default)]
struct Buffers {
    incoming: Buffer,
    outgoing: Buffer,
}

struct Buffer {
    inner: Vec<u8>,
    used: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            inner: vec![0; 16 * 1024],
            used: 0,
        }
    }
}

impl Buffer {
    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn append(&mut self, bytes: &[u8]) {
        let num_bytes = bytes.len();
        self.unfilled()[..num_bytes].copy_from_slice(bytes);
        self.advance(num_bytes)
    }

    fn clear(&mut self) {
        self.used = 0;
    }

    fn discard(&mut self, discard: usize) {
        if discard != 0 {
            assert!(discard <= self.used);

            self.inner
                .copy_within(discard..self.used, 0);
            self.used -= discard;
        }
    }

    fn filled(&mut self) -> &mut [u8] {
        &mut self.inner[..self.used]
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.inner[self.used..]
    }
}

fn make_connection_pair(
    version: &'static rustls::SupportedProtocolVersion,
) -> (UnbufferedClientConnection, UnbufferedServerConnection) {
    let server_config = make_server_config(KeyType::Rsa2048);
    let client_config = make_client_config_with_versions(KeyType::Rsa2048, &[version]);

    let client =
        UnbufferedClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let server = UnbufferedServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}

#[test]
fn server_receives_handshake_byte_by_byte() {
    let (mut client, mut server) = make_connection_pair(&TLS13);

    let mut client_hello_buffer = vec![0u8; 2048];
    let UnbufferedStatus { discard, state } = client.process_tls_records(&mut []);

    assert_eq!(discard, 0);
    match state.unwrap() {
        ConnectionState::EncodeTlsData(mut inner) => {
            let wr = inner
                .encode(&mut client_hello_buffer)
                .expect("client hello too big");
            client_hello_buffer.truncate(wr);
        }
        _ => panic!("unexpected first client event"),
    };

    println!("client hello: {:?}", client_hello_buffer);

    for prefix in 0..client_hello_buffer.len() - 1 {
        let UnbufferedStatus { discard, state } =
            server.process_tls_records(&mut client_hello_buffer[..prefix]);
        println!("prefix {prefix:?}: ({discard:?}, {state:?}");
        assert!(matches!(state.unwrap(), ConnectionState::BlockedHandshake));
    }

    let UnbufferedStatus { discard, state } =
        server.process_tls_records(&mut client_hello_buffer[..]);

    assert!(matches!(state.unwrap(), ConnectionState::EncodeTlsData(_)));
    assert_eq!(client_hello_buffer.len(), discard);
}

#[test]
fn server_receives_incorrect_first_handshake_message() {
    let (_, mut server) = make_connection_pair(&TLS13);

    let mut junk_buffer = [0x16, 0x3, 0x1, 0x0, 0x4, 0xff, 0x0, 0x0, 0x0];
    let junk_buffer_len = junk_buffer.len();

    let UnbufferedStatus { discard, state } = server.process_tls_records(&mut junk_buffer[..]);

    assert_eq!(discard, junk_buffer_len);
    assert_eq!(
        format!("{state:?}"),
        "Err(InappropriateHandshakeMessage { expect_types: [ClientHello], got_type: HandshakeType(0xff) })"
    );

    let UnbufferedStatus { discard, state } = server.process_tls_records(&mut []);
    assert_eq!(discard, 0);

    match state.unwrap() {
        ConnectionState::EncodeTlsData(mut inner) => {
            let mut alert_buffer = [0u8; 7];
            let wr = inner.encode(&mut alert_buffer).unwrap();
            assert_eq!(wr, 7);
            assert_eq!(alert_buffer, &[0x15, 0x3, 0x3, 0x0, 0x2, 0x2, 0xa][..]);
        }
        _ => panic!("unexpected alert sending state"),
    };
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
    for suite in [
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        #[cfg(not(feature = "fips"))]
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        #[cfg(not(feature = "fips"))]
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ] {
        let version = suite.version();
        println!("Testing suite {:?}", suite.suite().as_str());

        // Only offer the cipher suite (and protocol version) that we're testing
        let mut server_config = ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: vec![suite],
                ..provider::default_provider()
            }
            .into(),
        )
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap();
        // Opt into secret extraction from both sides
        server_config.enable_secret_extraction = true;
        let server_config = Arc::new(server_config);

        let mut client_config = make_client_config(kt);
        client_config.enable_secret_extraction = true;

        let mut outcome = run(
            Arc::new(client_config),
            &mut NO_ACTIONS.clone(),
            server_config.clone(),
            &mut NO_ACTIONS.clone(),
        );

        let client = outcome.client.take().unwrap();
        let server = outcome.server.take().unwrap();

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

const TLS12_CLIENT_TRANSCRIPT: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "WriteTraffic",
];

const TLS12_SERVER_TRANSCRIPT: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS12_CLIENT_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "WriteTraffic",
];

const TLS12_SERVER_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS13_CLIENT_TRANSCRIPT: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
    "WriteTraffic",
];

const TLS13_SERVER_TRANSCRIPT: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];

const TLS13_CLIENT_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
    "WriteTraffic",
];

const TLS13_SERVER_TRANSCRIPT_FRAGMENTED: &[&str] = &[
    "BlockedHandshake",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "EncodeTlsData",
    "TransmitTlsData",
    "BlockedHandshake",
    "EncodeTlsData",
    "TransmitTlsData",
    "WriteTraffic",
];
