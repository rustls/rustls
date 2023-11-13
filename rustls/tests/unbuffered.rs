#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use std::sync::Arc;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    ConnectionState, WriteTraffic, UnbufferedConnectionCommon, UnbufferedStatus,
};

use crate::common::*;

mod common;

const MAX_ITERATIONS: usize = 100;

#[test]
fn handshake() {
    for version in rustls::ALL_VERSIONS {
        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::TransmitTlsData {
                    sent_app_data: false,
                } => buffers.client_send(),
                State::BlockedHandshake => buffers.server_send(),
                State::WriteTraffic {
                    sent_app_data: false,
                } => client_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::TransmitTlsData {
                    sent_app_data: false,
                } => buffers.server_send(),
                State::BlockedHandshake => buffers.client_send(),
                State::WriteTraffic {
                    sent_app_data: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }
    }
}

#[test]
fn app_data_client_to_server() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut client_actions = Actions {
            app_data_to_send: Some(expected),
        };
        let mut received_app_data = vec![];
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, client_actions) {
                State::EncodedTlsData => {}
                State::TransmitTlsData { sent_app_data } => {
                    buffers.client_send();

                    if sent_app_data {
                        client_actions.app_data_to_send = None;
                    }
                }
                State::BlockedHandshake => buffers.server_send(),
                State::WriteTraffic { sent_app_data } => {
                    if sent_app_data {
                        buffers.client_send();
                        client_actions.app_data_to_send = None;
                    }

                    client_handshake_done = true
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::TransmitTlsData {
                    sent_app_data: false,
                } => buffers.server_send(),
                State::BlockedHandshake => buffers.client_send(),
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                State::WriteTraffic {
                    sent_app_data: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(client_handshake_done);
        assert!(server_handshake_done);

        assert!(client_actions
            .app_data_to_send
            .is_none());
        assert_eq!([expected], received_app_data.as_slice());
    }
}

#[test]
fn app_data_server_to_client() {
    let expected: &[_] = b"hello";
    for version in rustls::ALL_VERSIONS {
        eprintln!("{version:?}");

        let (mut client, mut server) = make_connection_pair(version);
        let mut buffers = BothBuffers::default();

        let mut server_actions = Actions {
            app_data_to_send: Some(expected),
        };
        let mut received_app_data = vec![];
        let mut count = 0;
        let mut client_handshake_done = false;
        let mut server_handshake_done = false;
        while !client_handshake_done || !server_handshake_done {
            match advance_client(&mut client, &mut buffers.client, NO_ACTIONS) {
                State::EncodedTlsData => {}
                State::TransmitTlsData {
                    sent_app_data: false,
                } => buffers.client_send(),
                State::BlockedHandshake => buffers.server_send(),
                State::WriteTraffic {
                    sent_app_data: false,
                } => client_handshake_done = true,
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                state => unreachable!("{state:?}"),
            }

            match advance_server(&mut server, &mut buffers.server, server_actions) {
                State::EncodedTlsData => {}
                State::TransmitTlsData { sent_app_data } => {
                    buffers.server_send();
                    if sent_app_data {
                        server_actions.app_data_to_send = None;
                    }
                }
                State::BlockedHandshake => buffers.client_send(),
                State::ReceivedAppData { records } => {
                    received_app_data.extend(records);
                }
                // server does not need to reach this state to send data to the client
                State::WriteTraffic {
                    sent_app_data: false,
                } => server_handshake_done = true,
                state => unreachable!("{state:?}"),
            }

            count += 1;

            assert!(
                count <= MAX_ITERATIONS,
                "handshake {version:?} was not completed"
            );
        }

        assert!(client_handshake_done);
        assert!(server_handshake_done);

        assert!(server_actions
            .app_data_to_send
            .is_none());
        assert_eq!([expected], received_app_data.as_slice());
    }
}

#[derive(Debug)]
enum State {
    EncodedTlsData,
    TransmitTlsData { sent_app_data: bool },
    BlockedHandshake,
    ReceivedAppData { records: Vec<Vec<u8>> },
    WriteTraffic { sent_app_data: bool },
}

const NO_ACTIONS: Actions = Actions {
    app_data_to_send: None,
};

#[derive(Clone, Copy, Debug)]
struct Actions<'a> {
    app_data_to_send: Option<&'a [u8]>,
}

fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = handle_state(state, &mut buffers.outgoing, actions);
    buffers.incoming.discard(discard);

    state
}

fn advance_server(
    conn: &mut UnbufferedConnectionCommon<ServerConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
) -> State {
    let UnbufferedStatus { discard, state } = conn
        .process_tls_records(buffers.incoming.filled())
        .unwrap();

    let state = handle_state(state, &mut buffers.outgoing, actions);
    buffers.incoming.discard(discard);

    state
}

fn handle_state<Data>(
    state: ConnectionState<'_, '_, Data>,
    outgoing: &mut Buffer,
    actions: Actions,
) -> State {
    match state {
        ConnectionState::EncodeTlsData(mut state) => {
            let written = state
                .encode(outgoing.unfilled())
                .unwrap();
            outgoing.advance(written);

            State::EncodedTlsData
        }

        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                if let Some(mut state) = state.may_encrypt_app_data() {
                    encrypt(&mut state, app_data, outgoing);
                    sent_app_data = true;
                }
            }

            // this should be called *after* the data has been transmitted but it's easier to
            // do it in reverse
            state.done();
            State::TransmitTlsData { sent_app_data }
        }

        ConnectionState::BlockedHandshake { .. } => State::BlockedHandshake,

        ConnectionState::WriteTraffic(mut state) => {
            let mut sent_app_data = false;
            if let Some(app_data) = actions.app_data_to_send {
                encrypt(&mut state, app_data, outgoing);
                sent_app_data = true;
            }

            State::WriteTraffic { sent_app_data }
        }

        ConnectionState::ReadTraffic(mut state) => {
            let mut records = vec![];

            while let Some(res) = state.next_record() {
                records.push(res.unwrap().payload.to_vec());
            }

            State::ReceivedAppData { records }
        }

        _ => unreachable!(),
    }
}

fn encrypt<Data>(state: &mut WriteTraffic<'_, Data>, app_data: &[u8], outgoing: &mut Buffer) {
    let written = state
        .encrypt(app_data, outgoing.unfilled())
        .unwrap();
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
    let server_config = make_server_config(KeyType::Rsa);
    let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);

    let client =
        UnbufferedClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let server = UnbufferedServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}
