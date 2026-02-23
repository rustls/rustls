//! Tests around IO, buffering, and data management.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use core::fmt::Debug;
use std::borrow::Cow;
use std::io::{self, BufRead, IoSlice, Read, Write};
use std::sync::Arc;

use pki_types::DnsName;
use rustls::crypto::CryptoProvider;
use rustls::crypto::kx::NamedGroup;
use rustls::enums::{ContentType, HandshakeType, ProtocolVersion};
use rustls::error::{
    AlertDescription, ApiMisuse, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved,
};
use rustls::{ClientConfig, Connection, ServerConfig, ServerConnection};
use rustls_test::{
    ClientConfigExt, KeyType, OtherSession, ServerConfigExt, TestNonBlockIo, check_fill_buf,
    check_fill_buf_err, check_read, check_read_and_close, check_read_err, do_handshake, encoding,
    make_client_config, make_client_config_with_auth, make_disjoint_suite_configs, make_pair,
    make_pair_for_arc_configs, make_pair_for_configs, make_server_config,
    make_server_config_with_mandatory_client_auth, server_name, transfer, transfer_eof,
};
use rustls_util::{Stream, StreamOwned, complete_io};

use super::{ALL_VERSIONS, provider};

#[test]
fn buffered_client_data_sent() {
    let server_config = Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    ));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config(KeyType::Rsa2048, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(0, server.writer().write(b"").unwrap());
        assert_eq!(5, client.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut server.reader(), b"hello");
    }
}

#[test]
fn buffered_server_data_sent() {
    let server_config = Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    ));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config(KeyType::Rsa2048, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(0, server.writer().write(b"").unwrap());
        assert_eq!(5, server.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"hello");
    }
}

#[test]
fn buffered_both_data_sent() {
    let server_config = Arc::new(make_server_config(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    ));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config(KeyType::Rsa2048, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        do_handshake(&mut client, &mut server);

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"from-server!");
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn server_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write_vectored(&[
                IoSlice::new(b"01234567890123456789"),
                IoSlice::new(b"01234567890123456789")
            ])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    // this test will vary in behaviour depending on the default suites
    do_handshake(&mut client, &mut server);
    server.set_buffer_limit(Some(48));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345");
}

#[test]
fn client_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write_vectored(&[
                IoSlice::new(b"01234567890123456789"),
                IoSlice::new(b"01234567890123456789")
            ])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    do_handshake(&mut client, &mut server);
    client.set_buffer_limit(Some(48));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345");
}

#[test]
fn client_detects_broken_write_vectored_impl() {
    // see https://github.com/rustls/rustls/issues/2316
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let err = client
        .write_tls(&mut BrokenWriteVectored)
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(format!("{err:?}").starts_with(
        "Custom { kind: Other, error: \"illegal write_vectored return value (9999 > "
    ));

    struct BrokenWriteVectored;

    impl Write for BrokenWriteVectored {
        fn write_vectored(&mut self, _bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            Ok(9999)
        }

        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            unreachable!()
        }

        fn flush(&mut self) -> io::Result<()> {
            unreachable!()
        }
    }
}

#[test]
fn buf_read() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    do_handshake(&mut client, &mut server);

    // Write two separate messages ensuring that empty messages are not written
    assert_eq!(client.writer().write(b"").unwrap(), 0);
    assert_eq!(client.writer().write(b"hello").unwrap(), 5);
    transfer(&mut client, &mut server);
    assert_eq!(client.writer().write(b"world").unwrap(), 5);
    assert_eq!(client.writer().write(b"").unwrap(), 0);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let mut reader = server.reader();
    // fill_buf() returns each record separately (this is an implementation detail)
    assert_eq!(reader.fill_buf().unwrap(), b"hello");
    // partially consuming the buffer is OK
    reader.consume(1);
    assert_eq!(reader.fill_buf().unwrap(), b"ello");
    // Read::read is compatible with BufRead
    let mut b = [0u8; 2];
    reader.read_exact(&mut b).unwrap();
    assert_eq!(b, *b"el");
    assert_eq!(reader.fill_buf().unwrap(), b"lo");
    reader.consume(2);
    // once the first packet is consumed, the next one is available
    assert_eq!(reader.fill_buf().unwrap(), b"world");
    reader.consume(5);
    check_fill_buf_err(&mut reader, io::ErrorKind::WouldBlock);
}

#[test]
fn server_read_returns_wouldblock_when_no_data() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(server.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn client_read_returns_wouldblock_when_no_data() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(client.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn server_fill_buf_returns_wouldblock_when_no_data() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(server.reader().fill_buf(),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn client_fill_buf_returns_wouldblock_when_no_data() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(client.reader().fill_buf(),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn new_server_returns_initial_io_state() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let io_state = server.process_new_packets().unwrap();
    println!("IoState is Debug {io_state:?}");
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert_eq!(io_state.tls_bytes_to_write(), 0);
}

#[test]
fn new_client_returns_initial_io_state() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let io_state = client.process_new_packets().unwrap();
    println!("IoState is Debug {io_state:?}");
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert!(io_state.tls_bytes_to_write() > 200);
}

#[test]
fn client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = complete_io(&mut OtherSession::new(&mut server), &mut client).unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn buffered_client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) =
        complete_io(&mut OtherSession::new_buffered(&mut server), &mut client).unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let mut input = io::Cursor::new(Vec::new());

    assert!(client.is_handshaking());
    let err = complete_io(&mut input, &mut client).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = complete_io(&mut pipe, &mut client).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writev_lengths());
            assert_eq!(pipe.writev_lengths(), vec![vec![42, 42]]);
        }
        check_read(
            &mut server.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[test]
fn client_complete_io_with_nonblocking_io() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    // absolutely no progress writing ClientHello
    assert_eq!(
        complete_io(&mut TestNonBlockIo::default(), &mut client)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );

    // a little progress writing ClientHello
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                writes: vec![1],
                reads: vec![],
            },
            &mut client
        )
        .unwrap(),
        (0, 1)
    );

    // complete writing ClientHello
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                writes: vec![4096],
                reads: vec![],
            },
            &mut client
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );

    // complete writing ClientHello, partial read of ServerHello
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let (rd, wr) = dbg!(complete_io(
        &mut TestNonBlockIo {
            writes: vec![4096],
            reads: vec![vec![ContentType::Handshake.into()]],
        },
        &mut client
    ))
    .unwrap();
    assert_eq!(rd, 1);
    assert!(wr > 1);

    // data phase:
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    // read
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                reads: vec![vec![ContentType::ApplicationData.into()]],
                writes: vec![],
            },
            &mut client
        )
        .unwrap(),
        (1, 0)
    );

    // write
    client
        .writer()
        .write_all(b"hello")
        .unwrap();

    // no progress
    assert_eq!(
        complete_io(
            &mut TestNonBlockIo {
                reads: vec![],
                writes: vec![],
            },
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
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new_buffered(&mut server);
            let (rdlen, wrlen) = complete_io(&mut pipe, &mut client).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writev_lengths());
            assert_eq!(pipe.writev_lengths(), vec![vec![42, 42]]);
        }
        check_read(
            &mut server.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[test]
fn client_complete_io_for_read() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = complete_io(&mut pipe, &mut client).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut client.reader(), b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);

        assert!(server.is_handshaking());
        let (rdlen, wrlen) = complete_io(&mut OtherSession::new(&mut client), &mut server).unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert!(!server.is_handshaking());
        assert!(!server.wants_write());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    let mut input = io::Cursor::new(Vec::new());

    assert!(server.is_handshaking());
    let err = complete_io(&mut input, &mut server).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = complete_io(&mut pipe, &mut server).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.writev_lengths(), vec![vec![42, 42]]);
        }
        check_read(
            &mut client.reader(),
            b"0123456789012345678901234567890123456789",
        );
    }
}

#[test]
fn server_complete_io_for_write_eof() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        // Queue 20 bytes to write.
        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            const BYTES_BEFORE_EOF: usize = 5;
            let mut eof_writer = EofWriter::<BYTES_BEFORE_EOF>::default();

            // Only BYTES_BEFORE_EOF should be written.
            let (rdlen, wrlen) = complete_io(&mut eof_writer, &mut server).unwrap();
            assert_eq!(rdlen, 0);
            assert_eq!(wrlen, BYTES_BEFORE_EOF);

            // Now nothing should be written.
            let (rdlen, wrlen) = complete_io(&mut eof_writer, &mut server).unwrap();
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
        let (mut client, mut server) = make_pair(*kt, &provider);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = complete_io(&mut pipe, &mut server).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut server.reader(), b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake_ending_with_alert() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert!(server.is_handshaking());

    let mut pipe = OtherSession::new_fails(&mut client);
    let rc = complete_io(&mut pipe, &mut server);
    assert!(rc.is_err(), "server io failed due to handshake failure");
    assert!(!server.wants_write(), "but server did send its alert");
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
        let (mut client, mut server) = make_pair(*kt, &provider);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
        check_read(&mut server.reader(), data);
    }
}

fn test_server_stream_write(stream_kind: StreamKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
        check_read(&mut client.reader(), data);
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
        let (mut client, mut server) = make_pair(*kt, &provider);
        let data = b"world";
        server.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut server);
            transfer_eof(&mut client);

            let stream: Box<dyn BufRead> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

fn test_server_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let (mut client, mut server) = make_pair(*kt, &provider);
        let data = b"world";
        client.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut client);
            transfer_eof(&mut server);

            let stream: Box<dyn BufRead> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

#[test]
fn test_client_write_and_vectored_write_equivalence() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    const N: usize = 1000;

    let data_chunked: Vec<IoSlice<'_>> = core::iter::repeat_n(IoSlice::new(b"A"), N).collect();
    let bytes_written_chunked = client
        .writer()
        .write_vectored(&data_chunked)
        .unwrap();
    let bytes_sent_chunked = transfer(&mut client, &mut server);
    println!("write_vectored returned {bytes_written_chunked} and sent {bytes_sent_chunked}");

    let data_contiguous = &[b'A'; N];
    let bytes_written_contiguous = client
        .writer()
        .write(data_contiguous)
        .unwrap();
    let bytes_sent_contiguous = transfer(&mut client, &mut server);
    println!("write returned {bytes_written_contiguous} and sent {bytes_sent_contiguous}");

    assert_eq!(bytes_written_chunked, bytes_written_contiguous);
    assert_eq!(bytes_sent_chunked, bytes_sent_contiguous);
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
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 0,
    };
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert!(rc.is_err());
    let err = rc.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 1,
    };
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert_eq!(format!("{rc:?}"), "Ok(5)");
}

#[test]
fn client_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs(provider::DEFAULT_PROVIDER);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    {
        let mut pipe = OtherSession::new_fails(&mut server);
        let mut client_stream = Stream::new(&mut client, &mut pipe);
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
    let (client, mut server) = make_pair_for_configs(client_config, server_config);

    let pipe = OtherSession::new_fails(&mut server);
    let mut client_stream = StreamOwned::new(client, pipe);
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
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    client
        .writer()
        .write_all(b"world")
        .unwrap();

    {
        let mut pipe = OtherSession::new_fails(&mut client);
        let mut server_stream = Stream::new(&mut server, &mut pipe);
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
    let (mut client, server) = make_pair_for_configs(client_config, server_config);

    client
        .writer()
        .write_all(b"world")
        .unwrap();

    let pipe = OtherSession::new_fails(&mut client);
    let mut server_stream = StreamOwned::new(server, pipe);
    let mut bytes = [0u8; 5];
    let rc = server_stream.read(&mut bytes);
    assert!(rc.is_err());
    assert_eq!(
        format!("{rc:?}"),
        "Err(Custom { kind: InvalidData, error: PeerIncompatible(NoCipherSuitesInCommon) })"
    );
}

#[test]
fn vectored_write_for_server_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writev_lengths(), vec![vec![42, 42]]);
    }
    check_read(
        &mut client.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[test]
fn vectored_write_for_client_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writev_lengths(), vec![vec![42, 42]]);
    }
    check_read(
        &mut server.reader(),
        b"0123456789012345678901234567890123456789",
    );
}

#[test]
fn vectored_write_for_server_handshake_with_half_rtt_data() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config_with_auth(KeyType::Rsa2048, &provider),
        server_config,
    );

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"0123456789")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 2400); // its pretty big (contains cert chain)
        assert_eq!(pipe.writev_lengths().len(), 1); // only one writev
        assert_eq!(pipe.writev_lengths()[0].len(), 5); // at least a server hello/ccs/cert/serverkx/0.5rtt data
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // 2 tickets (in one flight)
        assert_eq!(wrlen, 184);
        assert_eq!(pipe.writev_lengths(), vec![vec![184]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

fn check_half_rtt_does_not_work(server_config: ServerConfig) {
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config_with_auth(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER),
        server_config,
    );

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"0123456789")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 2400); // its pretty big (contains cert chain)
        assert_eq!(pipe.writev_lengths().len(), 1); // only one writev
        assert_eq!(pipe.writev_lengths()[0].len(), 3); // at least a server hello/ccs/cert/serverkx data, in one message
    }

    // client second flight
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);

    // when client auth is enabled, we don't sent 0.5-rtt data, as we'd be sending
    // it to an unauthenticated peer. so it happens here, in the server's second
    // flight (42 and 32 are lengths of appdata sent above).
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 258);
        assert_eq!(pipe.writev_lengths(), vec![vec![184, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_for_server_handshake_no_half_rtt_with_client_auth() {
    let mut server_config = make_server_config_with_mandatory_client_auth(
        KeyType::Rsa2048,
        &provider::DEFAULT_PROVIDER,
    );
    server_config.send_half_rtt_data = true; // ask even though it will be ignored
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn vectored_write_for_server_handshake_no_half_rtt_by_default() {
    let server_config = make_server_config(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(!server_config.send_half_rtt_data);
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn vectored_write_for_client_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write_all(b"0123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 200); // just the client hello
        assert_eq!(pipe.writev_lengths().len(), 1); // only one writev
        assert!(pipe.writev_lengths()[0].len() == 1); // only a client hello
    }

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 138);
        // CCS, finished, then two application data records
        assert_eq!(pipe.writev_lengths(), vec![vec![6, 58, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut server.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_with_slow_client() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);

    client.set_buffer_limit(Some(32));

    do_handshake(&mut client, &mut server);
    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();

    {
        let mut pipe = OtherSession::new(&mut client);
        pipe.short_writes = true;
        let wrlen = server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap();
        assert_eq!(42, wrlen);
        assert_eq!(
            pipe.writev_lengths(),
            vec![vec![21], vec![10], vec![5], vec![3], vec![3]]
        );
    }
    check_read(&mut client.reader(), b"01234567890123456789");
}

#[test]
fn test_client_mtu_reduction() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_config = make_client_config(*kt, &provider);
        client_config.max_fragment_size = Some(64);
        let (mut client, mut server) = make_pair_for_configs(
            client_config,
            make_server_config(KeyType::Rsa2048, &provider),
        );

        {
            let mut pipe = OtherSession::new(&mut server);
            client.write_tls(&mut pipe).unwrap();

            assert!(
                pipe.message_lengths()
                    .iter()
                    .all(|x| *x <= 64)
            );
        }
    }
}

#[test]
fn test_server_mtu_reduction() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.max_fragment_size = Some(64);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) = make_pair_for_configs(
        make_client_config(KeyType::Rsa2048, &provider),
        server_config,
    );

    let big_data = [0u8; 2048];
    server
        .writer()
        .write_all(&big_data)
        .unwrap();

    let encryption_overhead = 20; // FIXME: see issue #991

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();

        assert!(
            pipe.message_lengths()
                .iter()
                .all(|x| *x <= 64 + encryption_overhead)
        );
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();

        assert!(
            pipe.message_lengths()
                .iter()
                .all(|x| *x <= 64 + encryption_overhead)
        );
    }

    client.process_new_packets().unwrap();
    check_read(&mut client.reader(), &big_data);
}

fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let provider = provider::DEFAULT_PROVIDER;
    let mut client_config = make_client_config(KeyType::Ed25519, &provider);
    client_config.max_fragment_size = Some(size);
    Arc::new(client_config)
        .connect(server_name("localhost"))
        .build()
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
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        for version_provider in ALL_VERSIONS {
            // no hidden significance to these numbers
            for frag_size in [37, 61, 101, 257] {
                println!("test kt={kt:?} version={version_provider:?} frag={frag_size:?}");
                let mut client_config = make_client_config(*kt, &version_provider);
                client_config.max_fragment_size = Some(frag_size);
                let mut server_config = make_server_config(*kt, &provider);
                server_config.max_fragment_size = Some(frag_size);

                let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
                do_handshake(&mut client, &mut server);

                // check server -> client data flow
                let pattern = (0x00..=0xffu8).collect::<Vec<u8>>();
                assert_eq!(pattern.len(), server.writer().write(&pattern).unwrap());
                transfer(&mut server, &mut client);
                client.process_new_packets().unwrap();
                check_read(&mut client.reader(), &pattern);

                // and client -> server
                assert_eq!(pattern.len(), client.writer().write(&pattern).unwrap());
                transfer(&mut client, &mut server);
                server.process_new_packets().unwrap();
                check_read(&mut server.reader(), &pattern);
            }
        }
    }
}

#[test]
fn test_acceptor() {
    use rustls::server::Acceptor;

    let provider = provider::DEFAULT_PROVIDER;
    let client_config = Arc::new(make_client_config(KeyType::Ed25519, &provider));
    let mut client = client_config
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();

    let server_config = Arc::new(make_server_config(KeyType::Ed25519, &provider));
    let mut acceptor = Acceptor::default();
    acceptor
        .read_tls(&mut buf.as_slice())
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let ch = accepted.client_hello();
    assert_eq!(
        ch.server_name(),
        Some(&DnsName::try_from("localhost").unwrap())
    );
    assert_eq!(
        ch.named_groups().unwrap(),
        provider::DEFAULT_PROVIDER
            .kx_groups
            .iter()
            .map(|kx| kx.name())
            .collect::<Vec<NamedGroup>>()
    );

    let server = accepted
        .into_connection(server_config)
        .unwrap();
    assert!(server.wants_write());

    // Reusing an acceptor is not allowed
    assert_eq!(
        acceptor
            .read_tls(&mut [0u8].as_ref())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Other,
    );
    assert_eq!(
        acceptor.accept().err().unwrap().0,
        ApiMisuse::AcceptorPolledAfterCompletion.into()
    );

    let mut acceptor = Acceptor::default();
    assert!(acceptor.accept().unwrap().is_none());
    acceptor
        .read_tls(&mut &buf[..3])
        .unwrap(); // incomplete message
    assert!(acceptor.accept().unwrap().is_none());

    acceptor
        .read_tls(&mut [0x80, 0x00].as_ref())
        .unwrap(); // invalid message (len = 32k bytes)
    let (err, mut alert) = acceptor.accept().unwrap_err();
    assert_eq!(err, Error::InvalidMessage(InvalidMessage::MessageTooLarge));
    let mut alert_content = Vec::new();
    let _ = alert.write(&mut alert_content);
    let expected = encoding::alert(AlertDescription::DecodeError, &[]);
    assert_eq!(alert_content, expected);

    let mut acceptor = Acceptor::default();
    // Minimal valid 1-byte application data message is not a handshake message
    acceptor
        .read_tls(
            &mut encoding::message_framing(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                vec![0x00],
            )
            .as_slice(),
        )
        .unwrap();
    let (err, mut alert) = acceptor.accept().unwrap_err();
    assert!(matches!(err, Error::InappropriateMessage { .. }));
    let mut alert_content = Vec::new();
    let _ = alert.write(&mut alert_content);
    let expected = encoding::alert(AlertDescription::UnexpectedMessage, &[]);
    assert_eq!(alert_content, expected);

    let mut acceptor = Acceptor::default();
    // Minimal 1-byte ClientHello message is not a legal handshake message
    acceptor
        .read_tls(
            &mut encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                encoding::handshake_framing(HandshakeType::ClientHello, vec![0x00]),
            )
            .as_slice(),
        )
        .unwrap();
    let (err, mut alert) = acceptor.accept().unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidMessage(InvalidMessage::MissingData(_))
    ));
    let mut alert_content = Vec::new();
    let _ = alert.write(&mut alert_content);
    let expected = encoding::alert(AlertDescription::DecodeError, &[]);
    assert_eq!(alert_content, expected);
}

#[test]
fn test_acceptor_rejected_handshake() {
    use rustls::server::Acceptor;

    let client_config =
        ClientConfig::builder(provider::DEFAULT_TLS13_PROVIDER.into()).finish(KeyType::Ed25519);
    let mut client = Arc::new(client_config)
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();

    let server_config =
        ServerConfig::builder(provider::DEFAULT_TLS12_PROVIDER.into()).finish(KeyType::Ed25519);
    let mut acceptor = Acceptor::default();
    acceptor
        .read_tls(&mut buf.as_slice())
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let ch = accepted.client_hello();
    assert_eq!(
        ch.server_name(),
        Some(&DnsName::try_from("localhost").unwrap())
    );

    let (err, mut alert) = accepted
        .into_connection(server_config.into())
        .unwrap_err();
    assert_eq!(
        err,
        Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled)
    );

    let mut alert_content = Vec::new();
    let _ = alert.write(&mut alert_content);
    let expected = encoding::alert(AlertDescription::ProtocolVersion, &[]);
    assert_eq!(alert_content, expected);
}

#[test]
fn test_received_plaintext_backpressure() {
    test_plaintext_buffer_limit(None, 16_384);
    test_plaintext_buffer_limit(Some(18_000), 18_000);
}

fn test_plaintext_buffer_limit(limit: Option<usize>, plaintext_limit: usize) {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;

    let server_config = Arc::new(
        ServerConfig::builder(
            CryptoProvider {
                tls13_cipher_suites: Cow::Owned(vec![
                    provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
                ]),
                ..provider.clone()
            }
            .into(),
        )
        .with_no_client_auth()
        .with_single_cert(kt.identity(), kt.key())
        .unwrap(),
    );

    let client_config = Arc::new(make_client_config(kt, &provider));
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);

    if let Some(limit) = limit {
        server.set_plaintext_buffer_limit(Some(limit));
    }

    do_handshake(&mut client, &mut server);

    // Fill the server's received plaintext buffer with 16k bytes
    let client_buf = vec![0; plaintext_limit];
    assert_eq!(
        client
            .writer()
            .write(&client_buf)
            .unwrap(),
        plaintext_limit
    );
    let mut network_buf = Vec::with_capacity(plaintext_limit * 2);
    let sent = dbg!(
        client
            .write_tls(&mut network_buf)
            .unwrap()
    );
    let mut read = 0;
    while read < sent {
        let new = dbg!(
            server
                .read_tls(&mut &network_buf[read..sent])
                .unwrap()
        );
        if new == 4096 {
            read += new;
        } else {
            break;
        }
    }
    server.process_new_packets().unwrap();

    // Send one more byte from client to server
    assert_eq!(
        client
            .writer()
            .write(&client_buf[..1])
            .unwrap(),
        1
    );
    let sent = dbg!(
        client
            .write_tls(&mut network_buf)
            .unwrap()
    );

    // Get an error because the received plaintext buffer is full
    assert_eq!(
        format!(
            "{:?}",
            server
                .read_tls(&mut &network_buf[..sent])
                .unwrap_err()
        ),
        "Custom { kind: Other, error: \"received plaintext buffer full\" }"
    );

    // Read out some of the plaintext
    server
        .reader()
        .read_exact(&mut [0; 1])
        .unwrap();

    // Now there's room again in the plaintext buffer
    assert_eq!(
        server
            .read_tls(&mut &network_buf[..sent])
            .unwrap(),
        sent
    );
}

#[test]
fn server_flush_does_nothing() {
    let (_, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(server.writer().flush(), Ok(())));
}

#[test]
fn client_flush_does_nothing() {
    let (mut client, _) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    assert!(matches!(client.writer().flush(), Ok(())));
}

#[test]
fn server_close_notify() {
    let provider = provider::DEFAULT_PROVIDER;
    let kt = KeyType::Rsa2048;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt, &provider));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config_with_auth(kt, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        server.send_close_notify();

        transfer(&mut server, &mut client);
        let io_state = client.process_new_packets().unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut client.reader(), b"from-server!");

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_close_notify() {
    let provider = provider::DEFAULT_PROVIDER;
    let kt = KeyType::Rsa2048;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt, &provider));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config_with_auth(kt, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        client.send_close_notify();

        transfer(&mut client, &mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut server.reader(), b"from-client!");

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[test]
fn server_closes_uncleanly() {
    let provider = provider::DEFAULT_PROVIDER;
    let kt = KeyType::Rsa2048;
    let server_config = Arc::new(make_server_config(kt, &provider));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config(kt, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        transfer(&mut server, &mut client);
        transfer_eof(&mut client);
        let io_state = client.process_new_packets().unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut client.reader(), b"from-server!");

        check_read_err(
            &mut client.reader() as &mut dyn Read,
            io::ErrorKind::UnexpectedEof,
        );

        // may still transmit pending frames
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_closes_uncleanly() {
    let provider = provider::DEFAULT_PROVIDER;
    let kt = KeyType::Rsa2048;
    let server_config = Arc::new(make_server_config(kt, &provider));

    for version_provider in ALL_VERSIONS {
        let client_config = make_client_config(kt, &version_provider);
        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        transfer(&mut client, &mut server);
        transfer_eof(&mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut server.reader(), b"from-client!");

        check_read_err(
            &mut server.reader() as &mut dyn Read,
            io::ErrorKind::UnexpectedEof,
        );

        // may still transmit pending frames
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client.reader(), b"from-server!");
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

    let mut stream = FakeStream(client_hello_followed_by_close_notify_alert);
    assert_eq!(
        complete_io(&mut stream, &mut server)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn test_complete_io_with_no_io_needed() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    client.send_close_notify();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    server
        .writer()
        .write_all(b"hello")
        .unwrap();
    server.send_close_notify();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    // neither want any IO: both directions are closed.
    assert!(!client.wants_write());
    assert!(!client.wants_read());
    assert!(!server.wants_write());
    assert!(!server.wants_read());
    assert_eq!(
        complete_io(&mut FakeStream(&[]), &mut client).unwrap(),
        (0, 0)
    );
    assert_eq!(
        complete_io(&mut FakeStream(&[]), &mut server).unwrap(),
        (0, 0)
    );
}

#[test]
fn test_junk_after_close_notify_received() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    client.send_close_notify();

    let mut client_buffer = vec![];
    client
        .write_tls(&mut io::Cursor::new(&mut client_buffer))
        .unwrap();

    // add some junk that will be dropped from the deframer buffer
    // after the close_notify
    client_buffer.extend_from_slice(&[0x17, 0x03, 0x03, 0x01]);

    server
        .read_tls(&mut io::Cursor::new(&client_buffer[..]))
        .unwrap();
    server.process_new_packets().unwrap();
    server.process_new_packets().unwrap(); // check for desync

    // can read data received prior to close_notify
    let mut received_data = [0u8; 128];
    let len = server
        .reader()
        .read(&mut received_data)
        .unwrap();
    assert_eq!(&received_data[..len], b"hello");

    // but subsequent reads just report clean EOF
    assert_eq!(
        server
            .reader()
            .read(&mut received_data)
            .unwrap(),
        0
    );
}

#[test]
fn test_data_after_close_notify_is_ignored() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    client
        .writer()
        .write_all(b"before")
        .unwrap();
    client.send_close_notify();
    client
        .writer()
        .write_all(b"after")
        .unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let mut received_data = [0u8; 128];
    let count = server
        .reader()
        .read(&mut received_data)
        .unwrap();
    assert_eq!(&received_data[..count], b"before");
    assert_eq!(
        server
            .reader()
            .read(&mut received_data)
            .unwrap(),
        0
    );
}

#[test]
fn test_close_notify_sent_prior_to_handshake_complete() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(
        KeyType::EcdsaP256,
        &provider::DEFAULT_PROVIDER,
    )))
    .unwrap();

    server
        .read_tls(
            &mut encoding::message_framing(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                encoding::basic_client_hello(vec![]),
            )
            .as_slice(),
        )
        .unwrap();
    server
        .read_tls(&mut encoding::warning_alert(AlertDescription::CloseNotify).as_slice())
        .unwrap();
    assert_eq!(
        server.process_new_packets().err(),
        Some(PeerMisbehaved::IllegalWarningAlert(AlertDescription::CloseNotify).into())
    );
}

#[test]
fn test_subsequent_close_notify_ignored() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    client.send_close_notify();
    assert!(transfer(&mut client, &mut server) > 0);

    // does nothing
    client.send_close_notify();
    assert_eq!(transfer(&mut client, &mut server), 0);
}

#[test]
fn test_second_close_notify_after_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);
    client.send_close_notify();
    assert!(transfer(&mut client, &mut server) > 0);
    server.process_new_packets().unwrap();

    // does nothing
    client.send_close_notify();
    assert_eq!(transfer(&mut client, &mut server), 0);
}

#[test]
fn test_read_tls_artificial_eof_after_close_notify() {
    let (mut client, mut server) = make_pair(KeyType::Rsa2048, &provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);
    client.send_close_notify();
    assert!(transfer(&mut client, &mut server) > 0);
    server.process_new_packets().unwrap();

    let buf = [1, 2, 3, 4];
    assert_eq!(
        server
            .read_tls(&mut io::Cursor::new(buf))
            .unwrap(),
        0
    );
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
