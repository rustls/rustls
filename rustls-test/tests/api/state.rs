//! Tests for mid-level state-based API

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::{ClientState, ClientTraffic};
use rustls::server::{ServerState, ServerTraffic};
use rustls::state::{ReceiveTrafficState, SliceInput, TlsInputBuffer};
use rustls::{Connection, ServerConnection};
use rustls_test::{KeyType, make_client_config, make_server_config};

use super::provider;

#[test]
fn test_client_smoke() {
    let server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let mut server = ServerConnection::new(server_config.into()).unwrap();

    server
        .writer()
        .write_all(b"hello from server")
        .unwrap();

    let mut client_config = make_client_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    client_config.max_fragment_size = Some(64);
    let mut client =
        ClientState::new(client_config.into(), "localhost".try_into().unwrap(), None).unwrap();
    let mut server_to_client = vec![];
    for _ in 0..5 {
        visit_client(&client);
        client = match client {
            ClientState::AwaitServerFlight(asf) => {
                let mut slice_input = SliceInput::new(&mut server_to_client);
                let next = asf
                    .input_data(&mut slice_input)
                    .unwrap();
                let used = slice_input.into_used();
                server_to_client.drain(0..used);
                next
            }
            ClientState::SendClientFlight(mut scf) => {
                while let Some(data) = scf.take_data() {
                    server
                        .read_tls(&mut data.as_slice())
                        .unwrap();
                    server.process_new_packets().unwrap();
                    server
                        .write_tls(&mut &mut server_to_client)
                        .unwrap();
                    println!("data send: {data:x?}");
                }
                scf.into_next()
            }
            ClientState::Traffic(traffic) => {
                let ClientTraffic {
                    mut send,
                    receive,
                    outputs,
                } = *traffic;
                println!("traffic kind: {:?}", outputs.handshake_kind());

                if !server_to_client.is_empty() {
                    let mut slice_input = SliceInput::new(&mut server_to_client);

                    let ReceiveTrafficState::Available(avail) =
                        receive.read(&mut slice_input).unwrap()
                    else {
                        panic!("receive failed");
                    };

                    println!("received data: {:?}", avail.data);

                    let (discard, _recv) = avail.into_next();
                    println!("received used: {:?}", discard);
                    slice_input.discard(discard);
                    let used = slice_input.into_used();
                    server_to_client.drain(0..used);
                    assert!(server_to_client.is_empty());

                    let buffers = send
                        .write(b"client says hi".as_slice().into())
                        .unwrap();

                    for b in buffers {
                        server
                            .read_tls(&mut b.as_slice())
                            .unwrap();
                    }
                    let closure = send.close();
                    server
                        .read_tls(&mut closure.as_slice())
                        .unwrap();
                    let io_state = server.process_new_packets().unwrap();
                    assert_eq!(0, io_state.tls_bytes_to_write());
                    assert_eq!(14, io_state.plaintext_bytes_to_read());
                    assert!(io_state.peer_has_closed());

                    let mut received = vec![];
                    server
                        .reader()
                        .read_to_end(&mut received)
                        .unwrap();
                    println!("server received {:x?}", received);
                }

                break;
            }
            _ => todo!(),
        };
    }
}

fn visit_client(st: &ClientState) {
    println!(
        "client state: {st:?} ech={:?} alpn={:?} hs_kind={:?}",
        st.ech_status(),
        st.alpn_protocol(),
        st.handshake_kind()
    );
}

#[test]
fn test_server_smoke() {
    let client_config = Arc::new(make_client_config(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    ));
    let mut client = client_config
        .connect("localhost".try_into().unwrap())
        .build()
        .unwrap();

    client
        .writer()
        .write_all(b"hello from client")
        .unwrap();

    let mut server = ServerState::new();
    let mut client_to_server = vec![];

    client
        .write_tls(&mut &mut client_to_server)
        .unwrap();

    for _ in 0..5 {
        visit_server(&server);
        server = match dbg!(server) {
            ServerState::AwaitClientFlight(asf) => {
                let mut slice_input = SliceInput::new(&mut client_to_server);
                let next = asf
                    .input_data(&mut slice_input)
                    .unwrap();
                let used = slice_input.into_used();
                client_to_server.drain(0..used);
                next
            }
            ServerState::ChooseConfig(cc) => {
                println!("client hello {:?}", cc.client_hello());
                println!("client hello bytes {:x?}", cc.client_hello_bytes());
                cc.with_config(Arc::new(make_server_config(
                    KeyType::Rsa2048,
                    &provider::DEFAULT_PROVIDER,
                )))
                .unwrap()
            }
            ServerState::SendServerFlight(mut scf) => {
                while let Some(data) = scf.take_data() {
                    client
                        .read_tls(&mut data.as_slice())
                        .unwrap();
                    client.process_new_packets().unwrap();
                    client
                        .write_tls(&mut &mut client_to_server)
                        .unwrap();
                    println!("data send: {data:x?}");
                }
                scf.into_next()
            }
            ServerState::Traffic(traffic) => {
                let ServerTraffic {
                    mut send,
                    receive,
                    outputs,
                } = *traffic;
                println!("traffic kind: {:?}", outputs.handshake_kind());

                if !client_to_server.is_empty() {
                    let mut slice_input = SliceInput::new(&mut client_to_server);

                    let ReceiveTrafficState::Available(avail) =
                        receive.read(&mut slice_input).unwrap()
                    else {
                        panic!("receive failed");
                    };

                    println!("received data: {:?}", avail.data);

                    let (discard, _recv) = avail.into_next();
                    println!("received used: {:?}", discard);
                    slice_input.discard(discard);
                    let used = slice_input.into_used();
                    client_to_server.drain(0..used);
                    assert!(client_to_server.is_empty());

                    let buffers = send
                        .write(b"client says hi".as_slice().into())
                        .unwrap();
                    for b in buffers {
                        client
                            .read_tls(&mut b.as_slice())
                            .unwrap();
                    }
                    let closure = send.close();
                    client
                        .read_tls(&mut closure.as_slice())
                        .unwrap();
                    let io_state = client.process_new_packets().unwrap();
                    assert_eq!(0, io_state.tls_bytes_to_write());
                    assert_eq!(14, io_state.plaintext_bytes_to_read());
                    assert!(io_state.peer_has_closed());

                    let mut received = vec![];
                    client
                        .reader()
                        .read_to_end(&mut received)
                        .unwrap();
                    println!("client received {:x?}", received);
                }

                break;
            }
            _ => todo!(),
        };
    }
}

fn visit_server(st: &ServerState) {
    println!(
        "server state: {st:?} server_name={:?}, resumption_data={:?} alpn={:?} hs_kind={:?}",
        st.server_name(),
        st.received_resumption_data(),
        st.alpn_protocol(),
        st.handshake_kind()
    );
}
