#[macro_use]
mod macros;

test_for_each_provider! {

use std::num::NonZeroUsize;
use std::sync::Arc;

use rustls::client::{ClientConnectionData, EarlyDataError, UnbufferedClientConnection};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedConnectionCommon,
    UnbufferedStatus, WriteTraffic,
};
use rustls::version::TLS13;
use rustls::{ClientConfig, ServerConfig, SideData};

mod common;
use common::*;

const MAX_ITERATIONS: usize = 100;

#[test]
fn tls12_handshake() {
    let outcome = handshake(&rustls::version::TLS12);
    assert_eq!(
        outcome.client_transcript,
        vec![
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(WriteTraffic)"
        ],
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript,
        vec![
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(WriteTraffic)"
        ],
        "server transcript mismatch"
    );
}

#[test]
fn tls13_handshake() {
    let outcome = handshake(&rustls::version::TLS13);
    assert_eq!(
        outcome.client_transcript,
        vec![
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)"
        ],
        "client transcript mismatch"
    );
    assert_eq!(
        outcome.server_transcript,
        vec![
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(WriteTraffic)"
        ],
        "server transcript mismatch"
    );
}

fn handshake(version: &'static rustls::SupportedProtocolVersion) -> Outcome {
    let server_config = make_server_config_with_versions(KeyType::Rsa2048, &[version]);
    let client_config = make_client_config(KeyType::Rsa2048);

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

        assert!(client_actions
            .app_data_to_send
            .is_none());
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

        assert!(server_actions
            .app_data_to_send
            .is_none());
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
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)",
            "Ok(WriteTraffic)"
        ]
    );
    assert_eq!(
        outcome.server_transcript,
        vec![
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(ReadEarlyData)",
            "Ok(TransmitTlsData)",
            "Ok(BlockedHandshake)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(EncodeTlsData)",
            "Ok(TransmitTlsData)",
            "Ok(WriteTraffic)"
        ]
    );
    assert!(client_actions
        .early_data_to_send
        .is_none());
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
            State::Closed => {
                client_handshake_done = true;
                outcome.client_reached_connection_closed_state = true
            }
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
            State::Closed => {
                server_handshake_done = true;
                outcome.server_reached_connection_closed_state = true
            }
        }

        count += 1;

        assert!(count <= MAX_ITERATIONS, "handshake was not completed");
    }

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
        assert!(outcome.server_reached_connection_closed_state);
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
        assert!(outcome.client_reached_connection_closed_state);
    }
}

#[test]
fn junk_after_close_notify_received() {
    // cf. test_junk_after_close_notify_received in api.rs
    let mut outcome = handshake(&rustls::version::TLS13);
    let mut client = outcome.client.take().unwrap();
    let mut server = outcome.server.take().unwrap();

    let mut client_send_buf = [0u8; 128];
    let mut len = dbg!(write_traffic(
        client.process_tls_records(&mut []),
        |mut wt: WriteTraffic<_>| wt.queue_close_notify(&mut client_send_buf),
    )
    .unwrap());

    client_send_buf[len..len + 4].copy_from_slice(&[0x17, 0x03, 0x03, 0x01]);
    len += 4;

    let discard = match dbg!(server.process_tls_records(dbg!(&mut client_send_buf[..len]))) {
        UnbufferedStatus {
            discard,
            state: Ok(ConnectionState::Closed),
        } => {
            assert_eq!(discard, 24);
            discard
        }
        st => {
            panic!("unexpected server state {st:?} (wanted Closed)");
        }
    };

    // further data in client_send_buf is ignored
    let UnbufferedStatus { discard, .. } =
        server.process_tls_records(dbg!(&mut client_send_buf[discard..len]));
    assert_eq!(discard, 0);
}

fn write_traffic<T: SideData, F: FnMut(WriteTraffic<T>) -> Result<usize, EncryptError>>(
    status: UnbufferedStatus<'_, '_, T>,
    mut f: F,
) -> Result<usize, EncryptError> {
    let UnbufferedStatus { discard, state } = status;
    assert_eq!(discard, 0);
    let state = state.unwrap();
    if let ConnectionState::WriteTraffic(state) = state {
        f(state)
    } else {
        panic!("unexpected client state {state:?} (wanted WriteTraffic)");
    }
}

#[derive(Debug)]
enum State {
    Closed,
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
    server_reached_connection_closed_state: bool,
    client: Option<UnbufferedClientConnection>,
    client_transcript: Vec<String>,
    client_received_app_data: Vec<Vec<u8>>,
    client_reached_connection_closed_state: bool,
}

fn advance_client(
    conn: &mut UnbufferedConnectionCommon<ClientConnectionData>,
    buffers: &mut Buffers,
    actions: Actions,
    transcript: &mut Vec<String>,
) -> State {
    let UnbufferedStatus { discard, state } = conn.process_tls_records(buffers.incoming.filled());

    transcript.push(format!("{:?}", state));

    let state = match state.unwrap() {
        ConnectionState::TransmitTlsData(mut state) => {
            let mut sent_early_data = false;
            if let Some(early_data) = actions.early_data_to_send {
                if let Some(mut state) = state.may_encrypt_early_data() {
                    write_with_buffer_size_checks(
                        |out_buf| state.encrypt(early_data, out_buf),
                        |e| {
                            println!("encrypt error: {e}");
                            if let EarlyDataError::Encrypt(EncryptError::InsufficientSize(ise)) = e
                            {
                                ise
                            } else {
                                unreachable!()
                            }
                        },
                        &mut buffers.outgoing,
                    );
                    sent_early_data = true;
                }
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

    transcript.push(format!("{:?}", state));

    let state = match state.unwrap() {
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
                    if let EncodeError::InsufficientSize(ise) = e {
                        ise
                    } else {
                        unreachable!()
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
            if let Some(app_data) = actions.app_data_to_send {
                if let Some(mut state) = state.may_encrypt_app_data() {
                    encrypt(&mut state, app_data, outgoing);
                    sent_app_data = true;
                }
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
    if let EncryptError::InsufficientSize(ise) = e {
        ise
    } else {
        unreachable!()
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

    let mut client_hello_buffer = vec![0u8; 1024];
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
        "Err(InappropriateHandshakeMessage { expect_types: [ClientHello], got_type: Unknown(255) })"
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

} // test_for_each_provider!
