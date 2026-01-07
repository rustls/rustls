//! Tests for mid-level state-based API

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::io::{Read, Write};

use rustls::ServerConnection;
use rustls::client::{ClientState, ReceivedTrafficState};
use rustls::state::{ReceivedData, SliceInput};
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
            ClientState::Traffic(mut send, recv, outputs) => {
                println!("traffic kind: {:?}", outputs.handshake_kind());

                if !server_to_client.is_empty() {
                    let mut slice_input = SliceInput::new(&mut server_to_client);

                    let ReceivedTrafficState::Available(avail) =
                        recv.read(&mut slice_input).unwrap()
                    else {
                        panic!("recieve failed");
                    };

                    println!("received data: {:?}", avail.data);

                    let (discard, _recv) = avail.into_next();
                    println!("received used: {:?}", discard);
                    slice_input.discard(discard);
                    let used = slice_input.into_used();
                    server_to_client.drain(0..used);
                    assert!(server_to_client.is_empty());

                    let mut client_to_server = [0u8; 128];
                    let sent = send
                        .write(b"client says hi", &mut client_to_server)
                        .unwrap();
                    server
                        .read_tls(&mut &client_to_server[..sent])
                        .unwrap();
                    let sent = send
                        .close(&mut client_to_server)
                        .unwrap();
                    server
                        .read_tls(&mut &client_to_server[..sent])
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
