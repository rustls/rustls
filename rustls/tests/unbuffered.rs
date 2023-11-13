#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use std::sync::Arc;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, UnbufferedConnectionCommon, UnbufferedStatus};

use crate::common::*;

mod common;

#[test]
fn handshake() {
    for version in rustls::ALL_VERSIONS {
        let server_config = make_server_config(KeyType::Rsa);
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);

        let mut client =
            UnbufferedClientConnection::new(Arc::new(client_config), server_name("localhost"))
                .unwrap();
        let mut server = UnbufferedServerConnection::new(Arc::new(server_config)).unwrap();
        let mut buffers = BothBuffers::default();

        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client) {
                State::EncodedTlsData => {}
                State::TransmitTlsData => buffers.client_send(),
                State::BlockedHandshake => buffers.server_send(),
                State::WriteTraffic => client_handshake_done = true,
            }

            match advance_server(&mut server, &mut buffers.server) {
                State::EncodedTlsData => {}
                State::TransmitTlsData => buffers.server_send(),
                State::BlockedHandshake => buffers.client_send(),
                State::WriteTraffic => server_handshake_done = true,
            }

            count += 1;

            assert!(count <= 100, "handshake {version:?} was not completed");
        }
    }
}

#[derive(Debug)]
enum State {
    EncodedTlsData,
    BlockedHandshake,
    WriteTraffic,
    TransmitTlsData,
}

fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = handle_state(state, &mut buffers.outgoing);
    buffers.incoming.discard(discard);

    state
}

fn advance_server(
    conn: &mut UnbufferedConnectionCommon<ServerConnectionData>,
    buffers: &mut Buffers,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = handle_state(state, &mut buffers.outgoing);
    buffers.incoming.discard(discard);

    state
}

fn handle_state<Data>(state: ConnectionState<'_, '_, Data>, outgoing: &mut Buffer) -> State {
    match state {
        ConnectionState::EncodeTlsData(mut state) => {
            let written = state
                .encode(outgoing.unfilled())
                .unwrap();
            outgoing.advance(written);

            State::EncodedTlsData
        }

        ConnectionState::TransmitTlsData(state) => {
            // this should be called *after* the data has been transmitted but it's easier to
            // do it in reverse
            state.done();
            State::TransmitTlsData
        }

        ConnectionState::BlockedHandshake { .. } => State::BlockedHandshake,

        ConnectionState::WriteTraffic(_) => State::WriteTraffic,

        _ => unreachable!(),
    }
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
