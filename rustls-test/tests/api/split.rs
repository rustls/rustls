#![allow(
    clippy::disallowed_types,
    clippy::duplicate_mod,
    clippy::std_instead_of_core
)]

use std::io::{Cursor, Write};

use rustls::error::{AlertDescription, ApiMisuse, InvalidMessage};
use rustls::split::{ReceiveTraffic, ReceiveTrafficState, SplitConnection};
use rustls::{Connection, Error, SideData, SliceInput};
use rustls_test::{KeyType, do_handshake, make_pair};

#[test]
fn split_pairwise() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

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

    let flight = client_send.write(b"client to server".as_slice().into());
    server_recv = check_receive_all(
        server_recv,
        single(flight),
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    )
    .unwrap();

    let flight = server_send.write(b"server to client".as_slice().into());
    client_recv = check_receive_all(
        client_recv,
        single(flight),
        ExpectData {
            expected: b"server to client",
            then: ExpectReadMore,
        },
    )
    .unwrap();

    check_receive_all(server_recv, single(client_send.close()), ExpectCloseNotify);
    check_receive_all(client_recv, single(server_send.close()), ExpectCloseNotify);
}

#[test]
fn split_incremental() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

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

    let flight = client_send.write(b"client to server".as_slice().into());
    let flight = single(flight);

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
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

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
    let (client, server) = make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
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
fn split_fails_with_pending_plaintext() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    assert_eq!(client.writer().write(b"huh").unwrap(), 3);
    assert_eq!(server.writer().write(b"hmm").unwrap(), 3);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        server.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitWithPendingBuffers))
    );
    assert_eq!(
        client.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitWithPendingBuffers))
    );
}

#[test]
fn key_update() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

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

    client_send
        .refresh_traffic_keys()
        .unwrap();
    server_recv = check_receive_all(
        server_recv,
        single(client_send.take_data()),
        ExpectFlushSender {
            then: ExpectReadMore,
        },
    )
    .unwrap();

    let flight = server_send.write(b"server to client".as_slice().into());
    check_receive_all(
        client_recv,
        flight.concat(),
        ExpectData {
            expected: b"server to client",
            then: ExpectReadMore,
        },
    );

    let flight = client_send.write(b"client to server".as_slice().into());
    check_receive_all(
        server_recv,
        single(flight),
        ExpectData {
            expected: b"client to server",
            then: ExpectReadMore,
        },
    );
}

#[test]
fn key_update_alongside_data() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

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
    client_send
        .refresh_traffic_keys()
        .unwrap();
    let flight = client_send.write(b"client to server".as_slice().into());
    check_receive_all(
        server_recv,
        flight.concat(),
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
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let SplitConnection {
        send: mut client_send,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        receive: server_recv,
        ..
    } = server.split().unwrap();

    let mut flight = client_send.write(b"client to server".as_slice().into());
    flight.extend(client_send.close());
    let mut flight = flight.concat();
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
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let receive = client.split().unwrap().receive;

    let mut err = receive
        .read(&mut SliceInput::new(&mut [0u8; 5]))
        .err()
        .unwrap();
    let data = err.take_tls_data().unwrap();
    assert_eq!(
        err.error,
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
    );

    server
        .read_tls(&mut Cursor::new(data))
        .unwrap();
    assert_eq!(
        server.process_new_packets().err(),
        Some(Error::AlertReceived(AlertDescription::DecodeError))
    );
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

#[track_caller]
fn single(mut flight: Vec<Vec<u8>>) -> Vec<u8> {
    assert_eq!(flight.len(), 1);
    flight.remove(0)
}
