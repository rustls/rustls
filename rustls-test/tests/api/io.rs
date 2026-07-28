//! Tests around IO, buffering, and data management.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]
#![allow(clippy::std_instead_of_core)] // awaits core::io::IoSlice in stable (1.98)

use core::fmt::Debug;
use core::mem;
use std::io::{self, BufRead, IoSlice, Read, Write};
use std::sync::Arc;

use pki_types::DnsName;
use rustls::enums::{ContentType, HandshakeType, ProtocolVersion};
use rustls::error::{
    AlertDescription, ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved,
};
use rustls::server::ServerHandshake;
use rustls::{
    ClientConfig, Connection, HandshakeKind, ServerConfig, ServerConnection, SliceInput, VecInput,
};
use rustls_test::{
    ClientConfigExt, KeyType, MultiTest, OtherSession, ServerConfigExt, TestNonBlockIo,
    check_fill_buf, check_fill_buf_err, check_iter, check_read, check_read_err, do_handshake,
    do_handshake_collecting, encoding, make_client_config, make_client_config_with_auth,
    make_client_config_with_kx_groups, make_disjoint_suite_configs, make_pair,
    make_pair_for_arc_configs, make_pair_for_configs, make_server_config,
    make_server_config_with_kx_groups, make_server_config_with_mandatory_client_auth, server_name,
    transfer, transfer_eof,
};
use rustls_util::{Stream, StreamOwned, complete_io};

use super::provider;

#[test]
fn client_data_sent() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();

        assert_eq!(
            client
                .write_tls(b"hello".into(), &mut client_output)
                .unwrap_err(),
            ApiMisuse::WriteTlsBeforeHandshakeComplete.into()
        );

        // The client's buffered plaintext may be delivered as part of the final handshake
        // flight, so collect it during the handshake as well as afterwards.
        let mut server_received = Vec::new();
        do_handshake_collecting(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut Vec::new(),
            &mut server_input,
            &mut server_output,
            &mut server,
            &mut server_received,
        );

        client
            .write_tls(b"hello".into(), &mut client_output)
            .unwrap();
        transfer(&mut client_output, &mut server_input);
        server
            .process_new_packets(&mut server_input, &mut server_output)
            .handle_all(&mut server_received)
            .unwrap();

        assert_eq!(&server_received, b"hello");
    }
}

#[test]
fn server_data_sent() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();

        assert_eq!(
            server
                .write_tls(b"hello".into(), &mut server_output)
                .unwrap_err(),
            ApiMisuse::WriteTlsBeforeHandshakeComplete.into()
        );

        // The server's buffered plaintext may be delivered as part of the final handshake
        // flight, so collect it during the handshake as well as afterwards.
        let mut client_received = Vec::new();
        do_handshake_collecting(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut client_received,
            &mut server_input,
            &mut server_output,
            &mut server,
            &mut Vec::new(),
        );

        server
            .write_tls(b"hello".into(), &mut server_output)
            .unwrap();
        transfer(&mut server_output, &mut client_input);
        client
            .process_new_packets(&mut client_input, &mut client_output)
            .handle_all(&mut client_received)
            .unwrap();

        assert_eq!(&client_received, b"hello");
    }
}

#[test]
fn both_data_sent() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();

        let mut client_received = Vec::new();
        let mut server_received = Vec::new();
        do_handshake_collecting(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut client_received,
            &mut server_input,
            &mut server_output,
            &mut server,
            &mut server_received,
        );

        server
            .write_tls(b"from-server!".into(), &mut server_output)
            .unwrap();
        client
            .write_tls(b"from-client!".into(), &mut client_output)
            .unwrap();

        transfer(&mut server_output, &mut client_input);
        client
            .process_new_packets(&mut client_input, &mut client_output)
            .handle_all(&mut client_received)
            .unwrap();
        transfer(&mut client_output, &mut server_input);
        server
            .process_new_packets(&mut server_input, &mut server_output)
            .handle_all(&mut server_received)
            .unwrap();

        assert_eq!(&client_received, b"from-server!");
        assert_eq!(&server_received, b"from-client!");
    }
}

#[test]
fn client_detects_broken_write_impl() {
    // see https://github.com/rustls/rustls/issues/2316
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();

    assert!(!client_output.is_empty());
    let err = complete_io(
        &mut BrokenWrite,
        &mut client_input,
        &mut Vec::new(),
        &mut client_output,
        &mut client,
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(
        format!("{err:?}")
            .starts_with("Custom { kind: Other, error: \"illegal write() return value (9999 > ")
    );
    // the buffer is consumed: the amount actually written is unknown, so none
    // of it can be meaningfully retried.
    assert!(client_output.is_empty());

    struct BrokenWrite;

    impl Write for BrokenWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Ok(9999)
        }

        fn flush(&mut self) -> io::Result<()> {
            unreachable!()
        }
    }

    impl Read for BrokenWrite {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }
    }
}

#[test]
fn buf_read() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    // Write two separate messages ensuring that empty messages are not written
    client
        .write_tls(b"".into(), &mut client_output)
        .unwrap();
    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();
    transfer(&mut client_output, &mut server_input);
    client
        .write_tls(b"world".into(), &mut client_output)
        .unwrap();
    client
        .write_tls(b"".into(), &mut client_output)
        .unwrap();
    transfer(&mut client_output, &mut server_input);
    let mut iter = server.process_new_packets(&mut server_input, &mut server_output);

    let mut i = 0;
    while let Some(result) = iter.next_payload() {
        let payload = result.unwrap();
        match i {
            0 => assert_eq!(payload.bytes(), b"hello"),
            1 => assert_eq!(payload.bytes(), b"world"),
            _ => panic!("unexpected chunk"),
        }
        i += 1;
    }
}

#[test]
fn new_server_returns_initial_io_state() {
    let mut server_output = Vec::new();
    let (_, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut Vec::new(),
    );
    let mut server_input = VecInput::default();
    let io_state = server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    println!("IoState is Debug {io_state:?}");
    assert!(!io_state.peer_has_closed());
    assert!(server_output.is_empty());
}

#[test]
fn new_client_returns_initial_io_state() {
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    assert!(client_output.len() > 200);
    let mut client_input = VecInput::default();
    let io_state = client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    println!("IoState is Debug {io_state:?}");
    assert!(!io_state.peer_has_closed());
}

#[test]
fn client_complete_io_for_handshake() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = complete_io(
        &mut OtherSession::new(&mut server_input, &mut server_output, &mut server),
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
    )
    .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(client_output.is_empty());
}

#[test]
fn buffered_client_complete_io_for_handshake() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = complete_io(
        &mut OtherSession::new_buffered(&mut server_input, &mut server_output, &mut server),
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
    )
    .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(client_output.is_empty());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut input = io::Cursor::new(Vec::new());
    let mut received_plaintext = Vec::new();

    assert!(client.is_handshaking());
    let err = complete_io(
        &mut input,
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
    )
    .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        client
            .write_tls(b"01234567890123456789".into(), &mut client_output)
            .unwrap();
        client
            .write_tls(b"01234567890123456789".into(), &mut client_output)
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
            let (rdlen, wrlen) = complete_io(
                &mut pipe,
                &mut client_input,
                &mut received_plaintext,
                &mut client_output,
                &mut client,
            )
            .unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.message_lengths());
            assert_eq!(pipe.message_lengths(), vec![42, 42]);
            assert_eq!(&pipe.received, b"0123456789012345678901234567890123456789",);
        }
    }
}

#[test]
fn client_complete_io_with_nonblocking_io() {
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    // absolutely no progress writing ClientHello
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo::default(),
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );

    // a little progress writing ClientHello
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                writes: vec![1],
                reads: vec![],
            },
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap(),
        (0, 1)
    );

    // complete writing ClientHello
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                writes: vec![4096],
                reads: vec![],
            },
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );

    // complete writing ClientHello, partial read of ServerHello
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let (rd, wr) = dbg!(complete_io(
        &mut TestNonBlockIo {
            writes: vec![4096],
            reads: vec![vec![ContentType::Handshake.into()]],
        },
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client
    ))
    .unwrap();
    assert_eq!(rd, 1);
    assert!(wr > 1);

    // data phase:
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    // read
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                reads: vec![vec![ContentType::ApplicationData.into()]],
                writes: vec![],
            },
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap(),
        (1, 0)
    );

    // write
    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();

    // no progress
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                reads: vec![],
                writes: vec![],
            },
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );

    // some write progress
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                reads: vec![],
                writes: vec![1],
            },
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap(),
        (0, 1)
    );
}

#[test]
fn buffered_client_complete_io_for_write() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        client
            .write_tls(b"01234567890123456789".into(), &mut client_output)
            .unwrap();
        client
            .write_tls(b"01234567890123456789".into(), &mut client_output)
            .unwrap();
        {
            let mut pipe =
                OtherSession::new_buffered(&mut server_input, &mut server_output, &mut server);
            let (rdlen, wrlen) = complete_io(
                &mut pipe,
                &mut client_input,
                &mut received_plaintext,
                &mut client_output,
                &mut client,
            )
            .unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.message_lengths());
            assert_eq!(pipe.message_lengths(), vec![42, 42]);
            assert_eq!(&pipe.received, b"0123456789012345678901234567890123456789",);
        }
    }
}

#[test]
fn client_complete_io_for_read() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        server
            .write_tls(b"01234567890123456789".into(), &mut server_output)
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
            let (rdlen, wrlen) = complete_io(
                &mut pipe,
                &mut client_input,
                &mut received_plaintext,
                &mut client_output,
                &mut client,
            )
            .unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        assert_eq!(&received_plaintext, b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        assert!(server.is_handshaking());
        let (rdlen, wrlen) = complete_io(
            &mut OtherSession::new(&mut client_input, &mut client_output, &mut client),
            &mut server_input,
            &mut received_plaintext,
            &mut server_output,
            &mut server,
        )
        .unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert!(!server.is_handshaking());
        assert!(server_output.is_empty());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let mut server_output = Vec::new();
    let (_, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut Vec::new(),
    );
    let mut server_input = VecInput::default();
    let mut input = io::Cursor::new(Vec::new());
    let mut received_plaintext = Vec::new();

    assert!(server.is_handshaking());
    let err = complete_io(
        &mut input,
        &mut server_input,
        &mut received_plaintext,
        &mut server_output,
        &mut server,
    )
    .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        server
            .write_tls(b"01234567890123456789".into(), &mut server_output)
            .unwrap();
        server
            .write_tls(b"01234567890123456789".into(), &mut server_output)
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
            let (rdlen, wrlen) = complete_io(
                &mut pipe,
                &mut server_input,
                &mut received_plaintext,
                &mut server_output,
                &mut server,
            )
            .unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.message_lengths(), vec![42, 42]);
            assert_eq!(&pipe.received, b"0123456789012345678901234567890123456789",);
        }
    }
}

#[test]
fn server_complete_io_for_write_eof() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        // Queue 20 bytes to write.
        server
            .write_tls(b"01234567890123456789".into(), &mut server_output)
            .unwrap();
        {
            const BYTES_BEFORE_EOF: usize = 5;
            let mut eof_writer = EofWriter::<BYTES_BEFORE_EOF>::default();

            // Only BYTES_BEFORE_EOF should be written.
            let (rdlen, wrlen) = complete_io(
                &mut eof_writer,
                &mut server_input,
                &mut received_plaintext,
                &mut server_output,
                &mut server,
            )
            .unwrap();
            assert_eq!(rdlen, 0);
            assert_eq!(wrlen, BYTES_BEFORE_EOF);

            // Now nothing should be written.
            let (rdlen, wrlen) = complete_io(
                &mut eof_writer,
                &mut server_input,
                &mut received_plaintext,
                &mut server_output,
                &mut server,
            )
            .unwrap();
            assert_eq!(rdlen, 0);
            assert_eq!(wrlen, 0);
        }
    }
}

#[derive(Default)]
struct EofWriter<const N: usize> {
    written: usize,
}

impl<const N: usize> Write for EofWriter<N> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let prev = self.written;
        self.written = N.min(self.written + buf.len());
        Ok(self.written - prev)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<const N: usize> Read for EofWriter<N> {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!() // This is a writer, it should not be read from.
    }
}

#[test]
fn server_complete_io_for_read() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        client
            .write_tls(b"01234567890123456789".into(), &mut client_output)
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
            let (rdlen, wrlen) = complete_io(
                &mut pipe,
                &mut server_input,
                &mut received_plaintext,
                &mut server_output,
                &mut server,
            )
            .unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        assert_eq!(&received_plaintext, b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake_ending_with_alert() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    assert!(server.is_handshaking());

    let mut pipe = OtherSession::new_fails(&mut client_input, &mut client_output, &mut client);
    let rc = complete_io(
        &mut pipe,
        &mut server_input,
        &mut received_plaintext,
        &mut server_output,
        &mut server,
    );
    assert!(rc.is_err(), "server io failed due to handshake failure");
    assert!(server_output.is_empty(), "but server did send its alert");
    assert_eq!(
        format!("{:?}", pipe.last_error),
        "Some(AlertReceived(HandshakeFailure))",
        "which was received by client"
    );
}

#[test]
fn client_stream_write() {
    test_client_stream_write(StreamKind::Ref);
    test_client_stream_write(StreamKind::Owned);
}

#[test]
fn server_stream_write() {
    test_server_stream_write(StreamKind::Ref);
    test_server_stream_write(StreamKind::Owned);
}

#[derive(Debug, Copy, Clone)]
enum StreamKind {
    Owned,
    Ref,
}

fn test_client_stream_write(stream_kind: StreamKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();
        let data = b"hello";

        let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
        match stream_kind {
            StreamKind::Ref => {
                let mut stream = Stream::new(
                    &mut client_input,
                    &mut received_plaintext,
                    &mut client_output,
                    &mut client,
                    &mut pipe,
                );
                assert_eq!(stream.write(data).unwrap(), 5);
                assert_eq!(&pipe.received, data);
            }
            StreamKind::Owned => {
                let mut stream = StreamOwned::new(client, pipe, client_output);
                assert_eq!(stream.write(data).unwrap(), 5);
                let (_, pipe) = stream.into_parts();
                assert_eq!(&pipe.received, data);
            }
        }
    }
}

fn test_server_stream_write(stream_kind: StreamKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();
        let data = b"hello";

        let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
        match stream_kind {
            StreamKind::Ref => {
                let mut stream = Stream::new(
                    &mut server_input,
                    &mut received_plaintext,
                    &mut server_output,
                    &mut server,
                    &mut pipe,
                );
                assert_eq!(stream.write(data).unwrap(), 5);
                assert_eq!(&pipe.received, data);
            }
            StreamKind::Owned => {
                let mut stream = StreamOwned::new(server, pipe, server_output);
                assert_eq!(stream.write(data).unwrap(), 5);
                let (_, pipe) = stream.into_parts();
                assert_eq!(&pipe.received, data);
            }
        }
    }
}

#[test]
fn client_stream_read() {
    test_client_stream_read(StreamKind::Ref, ReadKind::Buf);
    test_client_stream_read(StreamKind::Owned, ReadKind::Buf);
    test_client_stream_read(StreamKind::Ref, ReadKind::BufRead);
    test_client_stream_read(StreamKind::Owned, ReadKind::BufRead);
}

#[test]
fn server_stream_read() {
    test_server_stream_read(StreamKind::Ref, ReadKind::Buf);
    test_server_stream_read(StreamKind::Owned, ReadKind::Buf);
    test_server_stream_read(StreamKind::Ref, ReadKind::BufRead);
    test_server_stream_read(StreamKind::Owned, ReadKind::BufRead);
}

#[derive(Debug, Copy, Clone)]
enum ReadKind {
    Buf,
    BufRead,
}

fn test_stream_read(read_kind: ReadKind, mut stream: impl BufRead, data: &[u8]) {
    match read_kind {
        ReadKind::Buf => {
            check_read(&mut stream, data);
            check_read_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
        ReadKind::BufRead => {
            check_fill_buf(&mut stream, data);
            check_fill_buf_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
    }
}

fn test_client_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        let data = b"world";
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );
        server
            .write_tls(data.into(), &mut server_output)
            .unwrap();

        {
            let mut pipe = OtherSession::new(&mut server_input, &mut server_output, &mut server);
            transfer_eof(&mut client_input);

            let stream: Box<dyn BufRead> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(
                    &mut client_input,
                    &mut received_plaintext,
                    &mut client_output,
                    &mut client,
                    &mut pipe,
                )),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe, client_output)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

fn test_server_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) = make_pair(*kt, &provider, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let mut received_plaintext = Vec::new();

        let data = b"world";
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );
        client
            .write_tls(data.into(), &mut client_output)
            .unwrap();

        {
            let mut pipe = OtherSession::new(&mut client_input, &mut client_output, &mut client);
            transfer_eof(&mut server_input);

            let stream: Box<dyn BufRead> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(
                    &mut server_input,
                    &mut received_plaintext,
                    &mut server_output,
                    &mut server,
                    &mut pipe,
                )),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe, server_output)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

struct FailsWrites {
    errkind: io::ErrorKind,
    after: usize,
}

impl Read for FailsWrites {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for FailsWrites {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.after > 0 {
            self.after -= 1;
            Ok(b.len())
        } else {
            Err(io::Error::new(self.errkind, "oops"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_write_reports_underlying_io_error_before_plaintext_processed() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 0,
    };
    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();

    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );
    let rc = client_stream.write(b"world");
    assert!(rc.is_err());
    let err = rc.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 1,
    };
    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();

    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );

    let rc = client_stream.write(b"world");
    assert_eq!(format!("{rc:?}"), "Ok(5)");
}

#[test]
fn stream_write_would_block_while_handshaking() {
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();

    // the transport accepts the full ClientHello but yields only a partial
    // reply, so the handshake makes progress without completing
    let mut pipe = TestNonBlockIo {
        writes: vec![4096],
        reads: vec![vec![ContentType::Handshake.into()]],
    };
    let mut received_plaintext = Vec::new();
    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );
    assert_eq!(
        client_stream
            .write(b"hello")
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(client.is_handshaking());
}

#[test]
fn stream_write_respects_output_limit() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    // the transport accepts nothing, so buffered TLS output can only grow
    let mut pipe = TestNonBlockIo::default();
    let mut received_plaintext = Vec::new();
    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );
    client_stream.limit = 48;

    // a write larger than the limit consumes only what fits
    assert_eq!(
        client_stream
            .write(&[b'a'; 100])
            .unwrap(),
        48
    );

    // with the output buffer full and the transport blocked, writes are refused
    assert_eq!(
        client_stream
            .write(&[b'a'; 100])
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );

    transfer(&mut client_output, &mut server_input);
    let iter = server.process_new_packets(&mut server_input, &mut server_output);
    check_iter(iter, &[b'a'; 48]);
}

#[test]
fn stream_write_would_block_when_output_over_limit() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    // buffer three 42-byte records
    for _ in 0..3 {
        client
            .write_tls((&[b'a'; 20]).into(), &mut client_output)
            .unwrap();
    }
    assert_eq!(client_output.len(), 126);

    // the transport accepts a partial write, but the buffered output
    // remains over the limit, so no further plaintext is accepted
    let mut pipe = TestNonBlockIo {
        writes: vec![14],
        reads: vec![],
    };
    let mut received_plaintext = Vec::new();
    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );
    client_stream.limit = 100;
    assert_eq!(
        client_stream
            .write(&[b'a'; 100])
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );

    // nothing was encrypted beyond the partial flush of existing output
    assert_eq!(client_output.len(), 112);
}

#[test]
fn stream_write_vectored_respects_output_limit() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    let mut pipe = TestNonBlockIo::default();
    let mut received_plaintext = Vec::new();
    let mut client_stream = Stream::new(
        &mut client_input,
        &mut received_plaintext,
        &mut client_output,
        &mut client,
        &mut pipe,
    );
    client_stream.limit = 48;

    // the first slice fits under the limit; the second is truncated
    let bufs = [IoSlice::new(&[b'a'; 30]), IoSlice::new(&[b'b'; 30])];
    assert_eq!(
        client_stream
            .write_vectored(&bufs)
            .unwrap(),
        48
    );
    assert_eq!(
        client_stream
            .write_vectored(&bufs)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );

    transfer(&mut client_output, &mut server_input);
    let iter = server.process_new_packets(&mut server_input, &mut server_output);
    let mut expected = vec![b'a'; 30];
    expected.extend_from_slice(&[b'b'; 18]);
    check_iter(iter, &expected);
}

#[test]
fn client_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    {
        let mut pipe = OtherSession::new_fails(&mut server_input, &mut server_output, &mut server);
        let mut client_stream = Stream::new(
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client,
            &mut pipe,
        );

        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{rc:?}"),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );

        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{rc:?}"),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );
    }
}

#[test]
fn client_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut server_input = VecInput::default();

    let pipe = OtherSession::new_fails(&mut server_input, &mut server_output, &mut server);
    let mut client_stream = StreamOwned::new(client, pipe, client_output);
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{rc:?}"),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{rc:?}"),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );

    let (_, _) = client_stream.into_parts();
}

#[test]
fn server_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    {
        let mut pipe = OtherSession::new_fails(&mut client_input, &mut client_output, &mut client);
        let mut server_stream = Stream::new(
            &mut server_input,
            &mut received_plaintext,
            &mut server_output,
            &mut server,
            &mut pipe,
        );

        let mut bytes = [0u8; 5];
        let rc = server_stream.read(&mut bytes);
        assert!(rc.is_err());
        assert_eq!(
            format!("{rc:?}"),
            "Err(Custom { kind: InvalidData, error: PeerIncompatible(NoCipherSuitesInCommon) })"
        );
    }
}

#[test]
fn server_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let mut client_output = Vec::new();
    let (mut client, server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();

    let pipe = OtherSession::new_fails(&mut client_input, &mut client_output, &mut client);
    let mut server_stream = StreamOwned::new(server, pipe, Vec::new());
    let mut bytes = [0u8; 5];
    let rc = server_stream.read(&mut bytes);
    assert!(rc.is_err());
    assert_eq!(
        format!("{rc:?}"),
        "Err(Custom { kind: InvalidData, error: PeerIncompatible(NoCipherSuitesInCommon) })"
    );
}

#[test]
fn server_appdata_record_layout() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    server
        .write_tls(b"01234567890123456789".into(), &mut server_output)
        .unwrap();
    server
        .write_tls(b"01234567890123456789".into(), &mut server_output)
        .unwrap();
    assert_eq!(84, server_output.len());
    assert_eq!(message_lengths(&server_output), vec![42, 42]);
    transfer(&mut server_output, &mut client_input);
    let mut received = Vec::new();
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut received)
        .unwrap();
    assert_eq!(&received, b"0123456789012345678901234567890123456789");
}

#[test]
fn client_appdata_record_layout() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    client
        .write_tls(b"01234567890123456789".into(), &mut client_output)
        .unwrap();
    client
        .write_tls(b"01234567890123456789".into(), &mut client_output)
        .unwrap();
    assert_eq!(84, client_output.len());
    assert_eq!(message_lengths(&client_output), vec![42, 42]);
    transfer(&mut client_output, &mut server_input);
    let mut received = Vec::new();
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut received)
        .unwrap();
    assert_eq!(&received, b"0123456789012345678901234567890123456789");
}

#[test]
fn server_handshake_with_half_rtt_data() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.send_half_rtt_data = true;
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config_with_auth(KeyType::Rsa2048, &provider),
        server_config,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    transfer(&mut client_output, &mut server_input);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    server
        .write_tls(b"01234567890123456789".into(), &mut server_output)
        .unwrap();
    server
        .write_tls(b"0123456789".into(), &mut server_output)
        .unwrap();

    // don't assert exact sizes here, to avoid a brittle test
    assert!(server_output.len() > 2400); // its pretty big (contains cert chain)
    assert_eq!(message_lengths(&server_output).len(), 5); // at least a server hello/ccs/cert/serverkx/0.5rtt data
    transfer(&mut server_output, &mut client_input);

    // The client decrypts the 0.5-RTT application data as part of this flight.
    let mut received = Vec::new();
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut received)
        .unwrap();
    assert_eq!(&received, b"012345678901234567890123456789");
    transfer(&mut client_output, &mut server_input);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    // 2 tickets (in one flight)
    assert_eq!(server_output.len(), 184);
    transfer(&mut server_output, &mut client_input);
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
}

fn check_half_rtt_does_not_work(server_config: ServerConfig) {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config_with_auth(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER),
        server_config,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    transfer(&mut client_output, &mut server_input);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    // 0.5-rtt data may not be sent at this point
    assert_eq!(
        server
            .write_tls(b"01234567890123456789".into(), &mut server_output)
            .unwrap_err(),
        ApiMisuse::WriteTlsBeforeHandshakeComplete.into()
    );

    // don't assert exact sizes here, to avoid a brittle test
    assert!(server_output.len() > 2400); // its pretty big (contains cert chain)
    assert_eq!(message_lengths(&server_output).len(), 3); // at least a server hello/ccs/cert/serverkx data
    transfer(&mut server_output, &mut client_input);

    // client second flight
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    transfer(&mut client_output, &mut server_input);

    // when client auth is enabled, we don't sent 0.5-rtt data, as we'd be sending
    // it to an unauthenticated peer. so it happens here, after the server's second
    // flight (42 and 32 are lengths of appdata sent below).
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    server
        .write_tls(b"01234567890123456789".into(), &mut server_output)
        .unwrap();
    server
        .write_tls(b"0123456789".into(), &mut server_output)
        .unwrap();
    assert_eq!(server_output.len(), 258);
    let lengths = message_lengths(&server_output);
    assert_eq!(lengths[lengths.len() - 2..], [42, 32]);
    transfer(&mut server_output, &mut client_input);
    let mut received = Vec::new();
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut received)
        .unwrap();
    assert_eq!(&received, b"012345678901234567890123456789");

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
}

#[test]
fn server_handshake_no_half_rtt_with_client_auth() {
    let mut server_config = make_server_config_with_mandatory_client_auth(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    );
    server_config.send_half_rtt_data = true; // ask even though it will be ignored
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn server_handshake_no_half_rtt_by_default() {
    let server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(!server_config.send_half_rtt_data);
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn client_handshake_flights() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    // don't assert exact sizes here, to avoid a brittle test
    assert!(client_output.len() > 200); // just the client hello
    assert_eq!(message_lengths(&client_output).len(), 1); // only a client hello
    transfer(&mut client_output, &mut server_input);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    transfer(&mut server_output, &mut client_input);
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    client
        .write_tls(b"01234567890123456789".into(), &mut client_output)
        .unwrap();
    client
        .write_tls(b"0123456789".into(), &mut client_output)
        .unwrap();

    // CCS, finished, then two application data records
    assert_eq!(client_output.len(), 138);
    assert_eq!(message_lengths(&client_output), vec![6, 58, 42, 32]);
    transfer(&mut client_output, &mut server_input);
    let mut received = Vec::new();
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut received)
        .unwrap();
    assert_eq!(&received, b"012345678901234567890123456789");

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
}

#[test]
fn test_client_mtu_reduction() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_config = Arc::unwrap_or_clone(client_config);
        client_config.max_fragment_size = Some(64);

        let mut client_output = Vec::new();
        let (_client, _server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config, &mut client_output);

        for length in message_lengths(&client_output) {
            assert!(length <= 64);
        }
    }
}

#[test]
fn test_server_mtu_reduction() {
    for (client_config, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut server_config = Arc::unwrap_or_clone(server_config);
        server_config.max_fragment_size = Some(64);
        server_config.send_half_rtt_data = true;

        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &Arc::new(server_config), &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();

        let big_data = [0u8; 2048];

        transfer(&mut client_output, &mut server_input);
        server
            .process_new_packets(&mut server_input, &mut server_output)
            .handle_all(&mut Vec::new())
            .unwrap();

        let mut received = Vec::new();
        if expect.version == ProtocolVersion::TLSv1_3 && !expect.client_auth {
            // The 0.5-RTT application data is delivered across the handshake flights (fragmented by
            // the reduced MTU), so accumulate everything the client decrypts.
            server
                .write_tls((&big_data).into(), &mut server_output)
                .unwrap();
            for length in message_lengths(&server_output) {
                assert!(length <= 64);
            }
            transfer(&mut server_output, &mut client_input);
        }

        client
            .process_new_packets(&mut client_input, &mut client_output)
            .handle_all(&mut received)
            .unwrap();
        transfer(&mut client_output, &mut server_input);
        server
            .process_new_packets(&mut server_input, &mut server_output)
            .handle_all(&mut Vec::new())
            .unwrap();
        for length in message_lengths(&server_output) {
            assert!(length <= 64);
        }
        transfer(&mut server_output, &mut client_input);

        if expect.version == ProtocolVersion::TLSv1_3 && !expect.client_auth {
            client
                .process_new_packets(&mut client_input, &mut client_output)
                .handle_all(&mut received)
                .unwrap();
            assert_eq!(received, big_data);
        }
    }
}

fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let provider = provider::DEFAULT_PROVIDER;
    let mut client_config = make_client_config(KeyType::default(), &provider);
    client_config.max_fragment_size = Some(size);
    Arc::new(client_config)
        .connect(server_name("localhost"))
        .build(&mut Vec::new())
        .err()
}

#[test]
fn bad_client_max_fragment_sizes() {
    assert_eq!(
        check_client_max_fragment_size(31),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(check_client_max_fragment_size(32), None);
    assert_eq!(check_client_max_fragment_size(64), None);
    assert_eq!(check_client_max_fragment_size(1460), None);
    assert_eq!(check_client_max_fragment_size(0x4000), None);
    assert_eq!(check_client_max_fragment_size(0x4005), None);
    assert_eq!(
        check_client_max_fragment_size(0x4006),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(
        check_client_max_fragment_size(0xffff),
        Some(Error::BadMaxFragmentSize)
    );
}

#[test]
fn handshakes_complete_and_data_flows_with_gratuitous_max_fragment_sizes() {
    // general exercising of msgs::fragmenter and msgs::deframer
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_config = Arc::unwrap_or_clone(client_config);
        let mut server_config = Arc::unwrap_or_clone(server_config);

        // no hidden significance to these numbers
        for frag_size in [37, 61, 101, 257] {
            println!("test configs={client_config:?}/{server_config:?} frag={frag_size:?}");
            client_config.max_fragment_size = Some(frag_size);
            server_config.max_fragment_size = Some(frag_size);

            let mut client_output = Vec::new();
            let mut server_output = Vec::new();
            let (mut client, mut server) = make_pair_for_configs(
                client_config.clone(),
                server_config.clone(),
                &mut client_output,
            );
            let mut client_input = VecInput::default();
            let mut server_input = VecInput::default();
            do_handshake(
                &mut client_input,
                &mut client_output,
                &mut client,
                &mut server_input,
                &mut server_output,
                &mut server,
            );

            // check server -> client data flow
            let pattern = (0x00..=0xffu8).collect::<Vec<u8>>();
            server
                .write_tls((&pattern).into(), &mut server_output)
                .unwrap();
            transfer(&mut server_output, &mut client_input);
            let iter = client.process_new_packets(&mut client_input, &mut client_output);
            check_iter(iter, &pattern);

            // and client -> server
            client
                .write_tls((&pattern).into(), &mut client_output)
                .unwrap();
            transfer(&mut client_output, &mut server_input);
            let iter = server.process_new_packets(&mut server_input, &mut server_output);
            check_iter(iter, &pattern);
        }
    }
}

#[test]
fn test_full_server_handshake() {
    for (client_config, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        println!("expect: {expect:?}");
        let mut buf = Vec::new();
        let mut client = client_config
            .connect(server_name("localhost"))
            .build(&mut buf)
            .unwrap();

        // client first flight
        let receive = ServerHandshake::start();
        let mut acceptor_input = VecInput::default();
        acceptor_input
            .read(&mut buf.as_slice())
            .unwrap();

        // server first flight and config choice
        let mut server_output = vec![];
        let ServerHandshake::Accepted(accepted) = receive
            .process(&mut acceptor_input, &mut server_output)
            .unwrap()
        else {
            panic!("unexpected state");
        };
        let mut server = accepted
            .choose_config(server_config, &mut server_output)
            .unwrap();
        assert!(!server_output.is_empty());

        // client receives server flight, producing its second flight
        let mut client_output = vec![];
        client
            .process_new_packets(&mut SliceInput::new(&mut server_output), &mut client_output)
            .handle_all(&mut Vec::new())
            .unwrap();

        // client second flight
        let mut server_output = vec![];
        let mut client_input = SliceInput::new(&mut client_output);
        server = if let ServerHandshake::NeedsInput(receive) = server {
            receive
                .process(&mut client_input, &mut server_output)
                .unwrap()
        } else {
            panic!("unexpected state");
        };

        // client certificate verification, if client auth was in use
        server = match server {
            ServerHandshake::VerifyClientIdentity(vci) => {
                assert!(expect.client_auth);
                println!("client identity {:?}", vci.presented_identity());
                let ServerHandshake::NeedsInput(receive) = vci
                    .use_verifier_trait(&mut server_output)
                    .unwrap()
                else {
                    panic!("unexpected state");
                };
                receive
                    .process(&mut client_input, &mut server_output)
                    .unwrap()
            }
            server => {
                assert!(!expect.client_auth);
                server
            }
        };

        client
            .process_new_packets(&mut SliceInput::new(&mut server_output), &mut client_output)
            .handle_all(&mut Vec::new())
            .unwrap();

        assert!(matches!(server, ServerHandshake::Complete(_)));
        assert!(!client.is_handshaking());
    }
}

#[test]
fn test_server_handshake() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut buf = Vec::new();
        let client = client_config
            .connect(server_name("localhost"))
            .build(&mut buf)
            .unwrap();
        drop(client);

        let receive = ServerHandshake::start();
        let mut acceptor_input = VecInput::default();
        acceptor_input
            .read(&mut buf.as_slice())
            .unwrap();
        let mut output = vec![];
        let ServerHandshake::Accepted(accepted) = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap()
        else {
            panic!("unexpected state");
        };
        let ch = accepted.client_hello();
        assert_eq!(
            ch.server_name(),
            Some(&DnsName::try_from("localhost").unwrap())
        );
        assert!(!ch.named_groups().unwrap().is_empty());

        let _server = accepted
            .choose_config(server_config, &mut output)
            .unwrap();
        assert!(!output.is_empty());

        // (Reusing `accepted` is not possible)

        let receive = ServerHandshake::start();
        let mut acceptor_input = VecInput::default();
        let mut output = vec![];
        let ServerHandshake::NeedsInput(receive) = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap()
        else {
            panic!("unexpected state");
        };
        assert!(output.is_empty());

        acceptor_input
            .read(&mut &buf[..3])
            .unwrap(); // incomplete message
        let ServerHandshake::NeedsInput(receive) = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap()
        else {
            panic!("unexpected state");
        };
        assert!(output.is_empty());

        acceptor_input
            .read(&mut [0x80, 0x00].as_ref())
            .unwrap(); // invalid message (len = 32k bytes)
        let error = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap_err();
        assert_eq!(
            error,
            Error::InvalidMessage(InvalidMessage::MessageTooLarge)
        );
        let alert_content = mem::take(&mut output);
        let expected = encoding::alert(AlertDescription::DecodeError, &[]);
        assert_eq!(alert_content, expected);

        let receive = ServerHandshake::start();
        let mut acceptor_input = VecInput::default();
        // Minimal valid 1-byte application data message is not a handshake message
        acceptor_input
            .read(
                &mut encoding::message_framing(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    vec![0x00],
                )
                .as_slice(),
            )
            .unwrap();
        let error = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap_err();
        assert!(matches!(error, Error::InappropriateMessage { .. }));
        let alert_content = mem::take(&mut output);
        let expected = encoding::alert(AlertDescription::UnexpectedMessage, &[]);
        assert_eq!(alert_content, expected);

        let receive = ServerHandshake::start();
        let mut acceptor_input = VecInput::default();
        // Minimal 1-byte ClientHello message is not a legal handshake message
        acceptor_input
            .read(
                &mut encoding::message_framing(
                    ContentType::Handshake,
                    ProtocolVersion::TLSv1_2,
                    encoding::handshake_framing(HandshakeType::ClientHello, vec![0x00]),
                )
                .as_slice(),
            )
            .unwrap();
        let error = receive
            .process(&mut acceptor_input, &mut output)
            .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidMessage(InvalidMessage::MissingData(_))
        ));
        let alert_content = mem::take(&mut output);
        let expected = encoding::alert(AlertDescription::DecodeError, &[]);
        assert_eq!(alert_content, expected);
    }
}

#[test]
fn test_acceptor_continues_tls13_hrr_with_compatibility_ccs() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    let client_config = Arc::new(make_client_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::SECP384R1, provider::kx_group::X25519],
        &provider,
    ));
    let mut client_output = Vec::new();
    let mut client = client_config
        .connect(server_name("localhost"))
        .build(&mut client_output)
        .unwrap();
    let client_hello = mem::take(&mut client_output);

    let server_config = Arc::new(make_server_config_with_kx_groups(
        KeyType::default(),
        vec![provider::kx_group::X25519],
        &provider,
    ));

    let mut server_input = VecInput::default();
    server_input
        .read(&mut client_hello.as_slice())
        .unwrap();

    let receive = ServerHandshake::start();
    let mut output = vec![];
    let ServerHandshake::Accepted(accepted) = receive
        .process(&mut server_input, &mut output)
        .unwrap()
    else {
        panic!("unexpected state");
    };
    let ServerHandshake::NeedsInput(receive) = accepted
        .choose_config(server_config, &mut output)
        .unwrap()
    else {
        panic!("unexpected state");
    };
    let mut server = receive.into_buffered_connection();
    let mut server_output = Vec::new();

    let mut client_input = VecInput::default();
    client_input
        .read(&mut io::Cursor::new(output))
        .unwrap();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
}

#[test]
fn test_acceptor_rejected_handshake() {
    let client_config =
        ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into()).finish(KeyType::default());
    let mut buf = Vec::new();
    let client = Arc::new(client_config)
        .connect(server_name("localhost"))
        .build(&mut buf)
        .unwrap();
    drop(client);

    let server_config =
        ServerConfig::builder(provider::DEFAULT_TLS12_PROVIDER.into()).finish(KeyType::default());
    let receive = ServerHandshake::start();
    let mut acceptor_input = VecInput::default();
    acceptor_input
        .read(&mut buf.as_slice())
        .unwrap();
    let mut output = vec![];
    let ServerHandshake::Accepted(accepted) = receive
        .process(&mut acceptor_input, &mut output)
        .unwrap()
    else {
        panic!("unexpected state");
    };
    let ch = accepted.client_hello();
    assert_eq!(
        ch.server_name(),
        Some(&DnsName::try_from("localhost").unwrap())
    );

    let error = accepted
        .choose_config(server_config.into(), &mut output)
        .unwrap_err();
    assert_eq!(
        error,
        Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled)
    );

    let alert_content = mem::take(&mut output);
    let expected = encoding::alert(AlertDescription::ProtocolVersion, &[]);
    assert_eq!(alert_content, expected);
}

#[test]
fn server_close_notify() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        // check that alerts don't overtake appdata
        server
            .write_tls(b"from-server!".into(), &mut server_output)
            .unwrap();
        client
            .write_tls(b"from-client!".into(), &mut client_output)
            .unwrap();
        server.send_close_notify(&mut server_output);

        transfer(&mut server_output, &mut client_input);
        let iter = client.process_new_packets(&mut client_input, &mut client_output);
        let mut received = Vec::with_capacity(16);
        let state = iter.handle_all(&mut received).unwrap();
        assert_eq!(received, b"from-server!");
        assert!(state.peer_has_closed());

        transfer(&mut client_output, &mut server_input);
        let iter = server.process_new_packets(&mut server_input, &mut server_output);
        check_iter(iter, b"from-client!");
    }
}

#[test]
fn client_close_notify() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        // check that alerts don't overtake appdata
        server
            .write_tls(b"from-server!".into(), &mut server_output)
            .unwrap();
        client
            .write_tls(b"from-client!".into(), &mut client_output)
            .unwrap();
        client.send_close_notify(&mut client_output);

        transfer(&mut client_output, &mut server_input);
        let iter = server.process_new_packets(&mut server_input, &mut server_output);
        let mut received = Vec::with_capacity(16);
        let state = iter.handle_all(&mut received).unwrap();
        assert_eq!(received, b"from-client!");
        assert!(state.peer_has_closed());

        transfer(&mut server_output, &mut client_input);
        let iter = client.process_new_packets(&mut client_input, &mut client_output);
        check_iter(iter, b"from-server!");
    }
}

#[test]
fn server_closes_uncleanly() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        // check that unclean EOF reporting does not overtake appdata
        server
            .write_tls(b"from-server!".into(), &mut server_output)
            .unwrap();
        client
            .write_tls(b"from-client!".into(), &mut client_output)
            .unwrap();

        transfer(&mut server_output, &mut client_input);
        transfer_eof(&mut client_input);
        let iter = client.process_new_packets(&mut client_input, &mut client_output);
        let mut received = Vec::with_capacity(16);
        let state = iter.handle_all(&mut received).unwrap();
        assert!(!state.peer_has_closed());

        // may still transmit pending frames
        transfer(&mut client_output, &mut server_input);
        let iter = server.process_new_packets(&mut server_input, &mut server_output);
        check_iter(iter, b"from-client!");
    }
}

#[test]
fn client_closes_uncleanly() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER) {
        let mut client_output = Vec::new();
        let mut server_output = Vec::new();
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &server_config, &mut client_output);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );

        // check that unclean EOF reporting does not overtake appdata
        server
            .write_tls(b"from-server!".into(), &mut server_output)
            .unwrap();
        client
            .write_tls(b"from-client!".into(), &mut client_output)
            .unwrap();

        transfer(&mut client_output, &mut server_input);
        transfer_eof(&mut server_input);
        let iter = server.process_new_packets(&mut server_input, &mut server_output);
        let mut received = Vec::with_capacity(16);
        let state = iter.handle_all(&mut received).unwrap();
        assert_eq!(&received, b"from-client!");
        assert!(!state.peer_has_closed());

        // may still transmit pending frames
        transfer(&mut server_output, &mut client_input);
        let iter = client.process_new_packets(&mut client_input, &mut client_output);
        check_iter(iter, b"from-server!");
    }
}

#[test]
fn test_complete_io_errors_if_close_notify_received_too_early() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    )))
    .unwrap();
    let client_hello_followed_by_close_notify_alert = b"\
        \x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03\xec\x12\xdd\x17\x64\
        \xa4\x39\xfd\x7e\x8c\x85\x46\xb8\x4d\x1e\xa0\x6e\xb3\xd7\xa0\x51\
        \xf0\x3c\xb8\x17\x47\x0d\x4c\x54\xc5\xdf\x72\x00\x00\x1c\xea\xea\
        \xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\
        \x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x00\x7f\xda\xda\
        \x00\x00\xff\x01\x00\x01\x00\x00\x00\x00\x16\x00\x14\x00\x00\x11\
        \x77\x77\x77\x2e\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x2e\x6f\x72\
        \x67\x00\x17\x00\x00\x00\x23\x00\x00\x00\x0d\x00\x14\x00\x12\x04\
        \x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\
        \x01\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x00\x10\
        \x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\
        \x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x0a\x00\x08\
        \x1a\x1a\x00\x1d\x00\x17\x00\x18\x1a\x1a\x00\x01\x00\
        \x15\x03\x03\x00\x02\x01\x00";

    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();
    let mut server_output = Vec::new();
    let mut stream = FakeStream(client_hello_followed_by_close_notify_alert);
    assert_eq!(
        complete_io(
            &mut stream,
            &mut server_input,
            &mut received_plaintext,
            &mut server_output,
            &mut server
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn test_complete_io_with_no_io_needed() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    let mut received_plaintext = Vec::new();

    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();
    client.send_close_notify(&mut client_output);
    transfer(&mut client_output, &mut server_input);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    server
        .write_tls(b"hello".into(), &mut server_output)
        .unwrap();
    server.send_close_notify(&mut server_output);
    transfer(&mut server_output, &mut client_input);
    client
        .process_new_packets(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    // neither want any IO: both directions are closed.
    assert!(client_output.is_empty());
    assert!(!client.wants_read());
    assert!(server_output.is_empty());
    assert!(!server.wants_read());

    assert_eq!(
        complete_io(
            &mut FakeStream(&[]),
            &mut client_input,
            &mut received_plaintext,
            &mut client_output,
            &mut client
        )
        .unwrap(),
        (0, 0)
    );

    assert_eq!(
        complete_io(
            &mut FakeStream(&[]),
            &mut server_input,
            &mut received_plaintext,
            &mut server_output,
            &mut server
        )
        .unwrap(),
        (0, 0)
    );
}

#[test]
fn test_junk_after_close_notify_received() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );
    client
        .write_tls(b"hello".into(), &mut client_output)
        .unwrap();
    client.send_close_notify(&mut client_output);

    let mut client_buffer = mem::take(&mut client_output);

    // add some junk that will be dropped from the deframer buffer
    // after the close_notify
    client_buffer.extend_from_slice(&[0x17, 0x03, 0x03, 0x01]);

    let mut final_input = SliceInput::new(&mut client_buffer);
    let mut received_data = Vec::new();
    for _ in 0..2 {
        // check for desync
        server
            .process_new_packets(&mut final_input, &mut server_output)
            .handle_all(&mut received_data)
            .unwrap();
    }

    // can read data received prior to close_notify
    assert_eq!(&received_data, b"hello");
}

#[test]
fn test_data_after_close_notify_is_ignored() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );

    client
        .write_tls(b"before".into(), &mut client_output)
        .unwrap();
    client.send_close_notify(&mut client_output);
    assert_eq!(
        client
            .write_tls(b"after".into(), &mut client_output)
            .unwrap_err(),
        ApiMisuse::WriteTlsAfterSendPathClosed.into()
    );
    transfer(&mut client_output, &mut server_input);

    let mut received_data = Vec::with_capacity(128);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut received_data)
        .unwrap();
    assert_eq!(&received_data, b"before");
}

#[test]
fn test_close_notify_sent_prior_to_handshake_complete() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
    )))
    .unwrap();

    let mut server_input = VecInput::default();
    let mut server_output = Vec::new();
    server_input
        .read(
            &mut encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                encoding::basic_client_hello(vec![]),
            )
            .as_slice(),
        )
        .unwrap();
    server_input
        .read(&mut encoding::warning_alert(AlertDescription::CloseNotify).as_slice())
        .unwrap();

    assert_eq!(
        server
            .process_new_packets(&mut server_input, &mut server_output)
            .handle_all(&mut Vec::new())
            .err(),
        Some(PeerMisbehaved::IllegalWarningAlert(AlertDescription::CloseNotify).into())
    );
}

#[test]
fn test_subsequent_close_notify_ignored() {
    let mut client_output = Vec::new();
    let (mut client, _) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    client_output.clear();
    let mut server_input = VecInput::default();
    client.send_close_notify(&mut client_output);
    assert!(transfer(&mut client_output, &mut server_input) > 0);

    // does nothing
    client.send_close_notify(&mut client_output);
    assert_eq!(transfer(&mut client_output, &mut server_input), 0);
}

#[test]
fn test_second_close_notify_after_handshake() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );
    client.send_close_notify(&mut client_output);
    assert!(transfer(&mut client_output, &mut server_input) > 0);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    // does nothing
    client.send_close_notify(&mut client_output);
    assert_eq!(transfer(&mut client_output, &mut server_input), 0);
}

#[test]
fn test_read_tls_artificial_eof_after_close_notify() {
    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) = make_pair(
        KeyType::default(),
        &provider::DEFAULT_PROVIDER,
        &mut client_output,
    );
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();
    do_handshake(
        &mut client_input,
        &mut client_output,
        &mut client,
        &mut server_input,
        &mut server_output,
        &mut server,
    );
    client.send_close_notify(&mut client_output);
    assert!(transfer(&mut client_output, &mut server_input) > 0);
    server
        .process_new_packets(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();

    let buf = [1, 2, 3, 4];
    assert_eq!(
        server_input
            .read(&mut io::Cursor::new(buf))
            .unwrap(),
        0
    );
}

fn message_lengths(mut tls: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    while !tls.is_empty() {
        let length = 5 + u16::from_be_bytes([tls[3], tls[4]]) as usize;
        lengths.push(length);
        tls = &tls[length..];
    }
    lengths
}

struct FakeStream<'a>(&'a [u8]);

impl Read for FakeStream<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let take = core::cmp::min(b.len(), self.0.len());
        let (taken, remain) = self.0.split_at(take);
        b[..take].copy_from_slice(taken);
        self.0 = remain;
        Ok(take)
    }
}

impl Write for FakeStream<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
