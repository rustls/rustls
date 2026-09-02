#![allow(
    clippy::disallowed_types,
    clippy::duplicate_mod,
    clippy::std_instead_of_core
)]

use std::io::Cursor;

use rustls::crypto::cipher::OutboundPlain;
use rustls::error::{AlertDescription, ApiMisuse, InvalidMessage};
use rustls::server::ServerSide;
use rustls::split::{ReceiveTraffic, ReceiveTrafficState, SplitConnection};
use rustls::{Connection, Error, SideData, SliceInput, VecInput};
use rustls_test::{
    KeyType, do_handshake, make_client_config, make_pair, make_pair_for_configs, make_server_config,
};

#[test]
fn split_pairwise() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let client_split = client.split().unwrap();
    println!("{client_split:?}");

    let SplitConnection {
        send: mut client_send,
        receive: mut client_recv,
        outputs: client_outputs,
    } = client_split;
    let SplitConnection {
        send: mut server_send,
        receive: mut server_recv,
        outputs: server_outputs,
    } = server.split().unwrap();

    assert_eq!(
        client_outputs.alpn_protocol(),
        server_outputs.alpn_protocol()
    );
    assert_eq!(
        client_outputs.handshake_kind(),
        server_outputs.handshake_kind()
    );
    assert_eq!(
        client_outputs.protocol_version(),
        server_outputs.protocol_version()
    );
    assert_eq!(
        client_outputs.negotiated_cipher_suite(),
        server_outputs.negotiated_cipher_suite()
    );
    assert_eq!(
        client_outputs
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
        server_outputs
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
    );

    let mut flight = Vec::new();
    client_send.write(b"client to server".as_slice().into(), &mut flight);
    server_recv = check_receive_all(
        server_recv,
        flight,
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    )
    .unwrap();

    let mut flight = Vec::new();
    server_send.write(b"server to client".as_slice().into(), &mut flight);
    client_recv = check_receive_all(
        client_recv,
        flight,
        ExpectData {
            expected: b"server to client",
            then: ExpectReadMore,
        },
    )
    .unwrap();

    let mut flight = Vec::new();
    client_send.close(&mut flight);
    check_receive_all(server_recv, flight, ExpectCloseNotify);
    let mut flight = Vec::new();
    server_send.close(&mut flight);
    check_receive_all(client_recv, flight, ExpectCloseNotify);
}

#[test]
fn split_incremental() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection {
        send: mut client_send,
        receive: _,
        outputs: _,
    } = client.split().unwrap();
    let SplitConnection {
        send: _,
        receive: mut server_recv,
        outputs: _,
    } = server.split().unwrap();

    let mut flight = Vec::new();
    client_send.write(b"client to server".as_slice().into(), &mut flight);

    // messages are not consumed until they are fully provided.
    for ll in 1..flight.len() - 1 {
        let (_, cont_recv) = check_receive(server_recv, flight[..ll].to_vec(), ExpectReadMore);
        server_recv = cont_recv.unwrap();
    }

    check_receive_all(
        server_recv,
        flight,
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    );
}

#[test]
fn split_client_tickets_received() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    assert_eq!(
        client
            .split()
            .unwrap()
            .receive
            .tls13_tickets_received(),
        2
    );
}

#[test]
fn split_fails_during_handshake() {
    let mut client_output = Vec::new();
    let (client, server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    assert_eq!(
        client.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitDuringHandshake))
    );
    assert_eq!(
        server.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitDuringHandshake))
    );
}

#[test]
fn key_update() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection {
        send: mut client_send,
        receive: client_recv,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        send: mut server_send,
        receive: mut server_recv,
        ..
    } = server.split().unwrap();

    let mut flight = Vec::new();
    client_send
        .refresh_traffic_keys(&mut flight)
        .unwrap();
    server_recv = check_receive_all(
        server_recv,
        flight,
        ExpectFlushSender {
            then: ExpectReadMore,
        },
    )
    .unwrap();

    let mut flight = Vec::new();
    server_send.write(b"server to client".as_slice().into(), &mut flight);
    check_receive_all(
        client_recv,
        flight,
        ExpectData {
            expected: b"server to client",
            then: ExpectReadMore,
        },
    );

    let mut flight = Vec::new();
    client_send.write(b"client to server".as_slice().into(), &mut flight);
    check_receive_all(
        server_recv,
        flight,
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    );
}

#[test]
fn key_update_alongside_data() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection {
        send: mut client_send,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        receive: server_recv,
        ..
    } = server.split().unwrap();

    // arrange a flight that contains a key-update followed by application data.
    // both the application data and `FlushSender` should be emitted.
    let mut flight = Vec::new();
    client_send
        .refresh_traffic_keys(&mut flight)
        .unwrap();
    client_send.write(b"client to server".as_slice().into(), &mut flight);
    check_receive_all(
        server_recv,
        flight,
        ExpectData {
            expected: b"client to server",
            then: ExpectFlushSender {
                then: ExpectReadMore,
            },
        },
    );
}

#[test]
fn close_alongside_data() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection {
        send: mut client_send,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        receive: server_recv,
        ..
    } = server.split().unwrap();

    let mut flight = Vec::new();
    client_send.write(b"client to server".as_slice().into(), &mut flight);
    client_send.close(&mut flight);
    flight.extend(b"rubbish");

    // receive of appdata does not consume subsequent data
    let (flight, server_recv) = check_receive(
        server_recv,
        flight,
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    );
    // receive of close_notify also consumes and ignores remainder of buffer
    check_receive_all(server_recv.unwrap(), flight, ExpectCloseNotify);
}

#[test]
fn read_invalid_data_and_send_alert() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &super::provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection { send, receive, .. } = client.split().unwrap();

    let err = receive
        .read(&mut SliceInput::new(&mut [0u8; 5]))
        .err()
        .unwrap();
    assert_eq!(
        err,
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
    );

    client_output.clear();
    send.close(&mut client_output);

    server_input
        .read(&mut Cursor::new(&mut client_output))
        .unwrap();
    assert_eq!(
        server
            .read_tls(&mut server_input, &mut server_output)
            .handle_all(&mut Vec::new())
            .err(),
        Some(Error::AlertReceived(AlertDescription::DecodeError))
    );
}

#[test]
fn kernel_conversion_fails_with_pending_send_data() {
    // converting with a queued key-update response is refused: it would be
    // discarded, having already consumed a send sequence number
    let conn = split_server_with_queued_key_update();
    assert_eq!(
        conn.dangerous_into_kernel_connection()
            .err(),
        Some(ApiMisuse::KernelConnectionWithPendingSendData.into())
    );

    // flushing the send half first makes conversion possible
    let SplitConnection {
        send: mut server_send,
        receive: server_recv,
        outputs: server_outputs,
    } = split_server_with_queued_key_update();
    let mut flight = Vec::new();
    server_send.write(OutboundPlain::new_empty(), &mut flight);
    assert!(!flight.is_empty());
    SplitConnection {
        send: server_send,
        receive: server_recv,
        outputs: server_outputs,
    }
    .dangerous_into_kernel_connection()
    .unwrap();
}

/// Handshake a pair, then deliver a `key_update` request to the server's
/// receive half.
///
/// This queues an encrypted response on the server's send half, awaiting the
/// next send-side operation.
fn split_server_with_queued_key_update() -> SplitConnection<ServerSide> {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let mut server_config =
        make_server_config(KeyType::default(), &super::provider::DEFAULT_PROVIDER);
    server_config.enable_secret_extraction = true;
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config(KeyType::default(), &super::provider::DEFAULT_PROVIDER),
        server_config,
        &mut client_output,
    );
    let (mut client_input, mut server_input) = (VecInput::default(), VecInput::default());
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let SplitConnection {
        send: mut client_send,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        send: server_send,
        receive: server_recv,
        outputs: server_outputs,
    } = server.split().unwrap();

    let mut flight = Vec::new();
    client_send
        .refresh_traffic_keys(&mut flight)
        .unwrap();
    let server_recv = check_receive_all(
        server_recv,
        flight,
        ExpectFlushSender {
            then: ExpectReadMore,
        },
    )
    .unwrap();

    SplitConnection {
        send: server_send,
        receive: server_recv,
        outputs: server_outputs,
    }
}

#[track_caller]
fn check_receive<Side: SideData>(
    recv: ReceiveTraffic<Side>,
    mut chunk: Vec<u8>,
    mut consume_state: impl ConsumeReceiveState,
) -> (Vec<u8>, Option<ReceiveTraffic<Side>>) {
    let mut inp = SliceInput::new(&mut chunk);
    let recv = consume_state.consume(dbg!(recv.read(&mut inp).unwrap()));
    let used = inp.into_used();
    chunk.drain(..used);
    (chunk, recv)
}

#[track_caller]
fn check_receive_all<Side: SideData>(
    recv: ReceiveTraffic<Side>,
    mut chunk: Vec<u8>,
    mut consume_state: impl ConsumeReceiveState,
) -> Option<ReceiveTraffic<Side>> {
    let mut inp = SliceInput::new(&mut chunk);
    let recv = consume_state.consume(dbg!(recv.read(&mut inp).unwrap()));
    assert_eq!(inp.into_used(), chunk.len());
    recv
}

trait ConsumeReceiveState {
    fn consume<'a, Side: SideData>(
        &mut self,
        state: ReceiveTrafficState<'a, Side>,
    ) -> Option<ReceiveTraffic<Side>>;
}

struct ExpectData<'a, T: ConsumeReceiveState> {
    expected: &'a [u8],
    then: T,
}

impl<T: ConsumeReceiveState> ConsumeReceiveState for ExpectData<'_, T> {
    fn consume<'a, Side: SideData>(
        &mut self,
        state: ReceiveTrafficState<'a, Side>,
    ) -> Option<ReceiveTraffic<Side>> {
        match state {
            ReceiveTrafficState::Available(mut received) => {
                assert_eq!(received.data(), self.expected);
                self.then.consume(received.into_next())
            }
            other => panic!("unexpected state for ExpectData: got {other:?}"),
        }
    }
}

struct ExpectFlushSender<T: ConsumeReceiveState> {
    then: T,
}

impl<T: ConsumeReceiveState> ConsumeReceiveState for ExpectFlushSender<T> {
    fn consume<'a, Side: SideData>(
        &mut self,
        state: ReceiveTrafficState<'a, Side>,
    ) -> Option<ReceiveTraffic<Side>> {
        match state {
            ReceiveTrafficState::FlushSender(service_sender) => self
                .then
                .consume(service_sender.into_next()),
            other => panic!("unexpected state for ExpectFlushSender: got {other:?}"),
        }
    }
}

struct ExpectReadMore;

impl ConsumeReceiveState for ExpectReadMore {
    fn consume<'a, Side: SideData>(
        &mut self,
        state: ReceiveTrafficState<'a, Side>,
    ) -> Option<ReceiveTraffic<Side>> {
        match state {
            ReceiveTrafficState::ReadMore(receive_traffic) => Some(receive_traffic),
            other => panic!("unexpected state for ExpectReadMore: got {other:?}"),
        }
    }
}

struct ExpectCloseNotify;

impl ConsumeReceiveState for ExpectCloseNotify {
    fn consume<'a, Side: SideData>(
        &mut self,
        state: ReceiveTrafficState<'a, Side>,
    ) -> Option<ReceiveTraffic<Side>> {
        match state {
            ReceiveTrafficState::CloseNotify => None,
            other => panic!("unexpected state for ExpectCloseNotify: got {other:?}"),
        }
    }
}
