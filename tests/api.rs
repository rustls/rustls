// Assorted public API tests.
use std::sync::Arc;
use std::sync::atomic;
use std::fs;
use std::io::{self, Write, Read};

extern crate rustls;
use rustls::{ClientConfig, ClientSession, ResolvesClientCert};
use rustls::{ServerConfig, ServerSession, ResolvesServerCert};
use rustls::Session;
use rustls::Stream;
use rustls::{ProtocolVersion, SignatureScheme};
use rustls::TLSError;
use rustls::sign;
use rustls::{Certificate, PrivateKey};
use rustls::internal::pemfile;

fn transfer(left: &mut Session, right: &mut Session) {
    let mut buf = [0u8; 262144];

    while left.wants_write() {
        let sz = left.write_tls(&mut buf.as_mut()).unwrap();
        if sz == 0 {
            return;
        }

        let mut offs = 0;
        loop {
            offs += right.read_tls(&mut buf[offs..sz].as_ref()).unwrap();
            if sz == offs {
                break;
            }
        }
    }
}

fn get_chain() -> Vec<Certificate> {
    pemfile::certs(&mut io::BufReader::new(fs::File::open("test-ca/rsa/end.fullchain").unwrap()))
        .unwrap()
}

fn get_key() -> PrivateKey {
    pemfile::rsa_private_keys(&mut io::BufReader::new(fs::File::open("test-ca/rsa/end.rsa")
                .unwrap()))
            .unwrap()[0]
        .clone()
}

fn make_server_config() -> ServerConfig {
    let mut cfg = ServerConfig::new();
    cfg.set_single_cert(get_chain(), get_key());

    cfg
}

fn make_client_config() -> ClientConfig {
    let mut cfg = ClientConfig::new();
    let mut rootbuf = io::BufReader::new(fs::File::open("test-ca/rsa/ca.cert").unwrap());
    cfg.root_store.add_pem_file(&mut rootbuf).unwrap();

    cfg
}

fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets().unwrap();
        transfer(server, client);
        client.process_new_packets().unwrap();
    }
}

fn do_handshake_until_error(client: &mut ClientSession,
                            server: &mut ServerSession)
                            -> Result<(), TLSError> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets()?;
        transfer(server, client);
        client.process_new_packets()?;
    }

    Ok(())
}

fn alpn_test(server_protos: Vec<String>, client_protos: Vec<String>, agreed: Option<String>) {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    client_config.alpn_protocols = client_protos;
    server_config.alpn_protocols = server_protos;

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    assert_eq!(client.get_alpn_protocol(), None);
    assert_eq!(server.get_alpn_protocol(), None);
    do_handshake(&mut client, &mut server);
    assert_eq!(client.get_alpn_protocol(), agreed);
    assert_eq!(server.get_alpn_protocol(), agreed);
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec!["server-proto".to_string()], vec![], None);

    // client support
    alpn_test(vec![], vec!["client-proto".to_string()], None);

    // no overlap
    alpn_test(vec!["server-proto".to_string()],
              vec!["client-proto".to_string()],
              None);

    // server chooses preference
    alpn_test(vec!["server-proto".to_string(), "client-proto".to_string()],
              vec!["client-proto".to_string(), "server-proto".to_string()],
              Some("server-proto".to_string()));

    // case sensitive
    alpn_test(vec!["PROTO".to_string()], vec!["proto".to_string()], None);
}

fn version_test(client_versions: Vec<ProtocolVersion>,
                server_versions: Vec<ProtocolVersion>,
                result: Option<ProtocolVersion>) {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    println!("version {:?} {:?} -> {:?}",
             client_versions,
             server_versions,
             result);

    if !client_versions.is_empty() {
        client_config.versions = client_versions;
    }

    if !server_versions.is_empty() {
        server_config.versions = server_versions;
    }

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    assert_eq!(client.get_protocol_version(), None);
    assert_eq!(server.get_protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    } else {
        do_handshake(&mut client, &mut server);
        assert_eq!(client.get_protocol_version(), result);
        assert_eq!(server.get_protocol_version(), result);
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(vec![], vec![], Some(ProtocolVersion::TLSv1_3));

    // client default, server 1.2 -> 1.2
    version_test(vec![],
                 vec![ProtocolVersion::TLSv1_2],
                 Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server default -> 1.2
    version_test(vec![ProtocolVersion::TLSv1_2],
                 vec![],
                 Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server 1.3 -> fail
    version_test(vec![ProtocolVersion::TLSv1_2],
                 vec![ProtocolVersion::TLSv1_3],
                 None);

    // client 1.3, server 1.2 -> fail
    version_test(vec![ProtocolVersion::TLSv1_3],
                 vec![ProtocolVersion::TLSv1_2],
                 None);

    // client 1.3, server 1.2+1.3 -> 1.3
    version_test(vec![ProtocolVersion::TLSv1_3],
                 vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                 Some(ProtocolVersion::TLSv1_3));

    // client 1.2+1.3, server 1.2 -> 1.2
    version_test(vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
                 vec![ProtocolVersion::TLSv1_2],
                 Some(ProtocolVersion::TLSv1_2));
}

fn check_read(reader: &mut io::Read, bytes: &[u8]) {
    let mut buf = Vec::new();
    assert_eq!(bytes.len(), reader.read_to_end(&mut buf).unwrap());
    assert_eq!(bytes.to_vec(), buf);
}

#[test]
fn buffered_client_data_sent() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    assert_eq!(5, client.write(b"hello").unwrap());

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server, b"hello");
}

#[test]
fn buffered_server_data_sent() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    assert_eq!(5, server.write(b"hello").unwrap());

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client, b"hello");
}

#[test]
fn buffered_both_data_sent() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    assert_eq!(12, server.write(b"from-server!").unwrap());
    assert_eq!(12, client.write(b"from-client!").unwrap());

    do_handshake(&mut client, &mut server);

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut client, b"from-server!");
    check_read(&mut server, b"from-client!");
}

#[test]
fn client_can_get_server_cert() {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    do_handshake(&mut client, &mut server);

    let certs = client.get_peer_certificates();
    assert_eq!(certs, Some(get_chain()));
}

#[test]
fn server_can_get_client_cert() {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    server_config.set_client_auth_roots(get_chain(), true);
    client_config.set_single_client_cert(get_chain(), get_key());

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    do_handshake(&mut client, &mut server);

    let certs = server.get_peer_certificates();
    assert_eq!(certs, Some(get_chain()));
}

fn check_read_and_close(reader: &mut io::Read, expect: &[u8]) {
    let mut buf = Vec::new();
    buf.resize(expect.len(), 0u8);
    assert_eq!(expect.len(), reader.read(&mut buf).unwrap());
    assert_eq!(expect.to_vec(), buf);

    let err = reader.read(&mut buf);
    assert!(err.is_err());
    assert_eq!(err.err().unwrap().kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn server_close_notify() {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    server_config.set_client_auth_roots(get_chain(), true);
    client_config.set_single_client_cert(get_chain(), get_key());

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    do_handshake(&mut client, &mut server);

    // check that alerts don't overtake appdata
    assert_eq!(12, server.write(b"from-server!").unwrap());
    assert_eq!(12, client.write(b"from-client!").unwrap());
    server.send_close_notify();

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    check_read_and_close(&mut client, b"from-server!");

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    check_read(&mut server, b"from-client!");
}

#[test]
fn client_close_notify() {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    server_config.set_client_auth_roots(get_chain(), true);
    client_config.set_single_client_cert(get_chain(), get_key());

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    do_handshake(&mut client, &mut server);

    // check that alerts don't overtake appdata
    assert_eq!(12, server.write(b"from-server!").unwrap());
    assert_eq!(12, client.write(b"from-client!").unwrap());
    client.send_close_notify();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    check_read_and_close(&mut server, b"from-client!");

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    check_read(&mut client, b"from-server!");
}

struct ServerCheckCertResolve {
    expected: String
}

impl ServerCheckCertResolve {
    fn new(expect: &str) -> ServerCheckCertResolve {
        ServerCheckCertResolve {
            expected: expect.to_string()
        }
    }
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self,
               server_name: Option<&str>,
               sigschemes: &[SignatureScheme])
        -> Option<sign::CertChainAndSigner> {
        if let Some(got_dns_name) = server_name {
            if got_dns_name != self.expected {
                panic!("unexpected dns name (wanted '{}' got '{}')", &self.expected, got_dns_name);
            }
        } else {
            panic!("dns name not provided (wanted '{}')", &self.expected);
        }

        if sigschemes.len() == 0 {
            panic!("no signature schemes shared by client");
        }

        None
    }
}

#[test]
fn server_cert_resolve_with_sni() {
    let client_config = make_client_config();
    let mut server_config = make_server_config();

    server_config.cert_resolver = Box::new(ServerCheckCertResolve::new("the-value-from-sni"));

    let mut client = ClientSession::new(&Arc::new(client_config), "the-value-from-sni");
    let mut server = ServerSession::new(&Arc::new(server_config));

    let err = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(err.is_err(), true);
}

struct ClientCheckCertResolve {
    query_count: atomic::AtomicUsize,
    expect_queries: usize
}

impl ClientCheckCertResolve {
    fn new(expect_queries: usize) -> ClientCheckCertResolve {
        ClientCheckCertResolve {
            query_count: atomic::AtomicUsize::new(0),
            expect_queries: expect_queries
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        let count = self.query_count.load(atomic::Ordering::SeqCst);
        assert_eq!(count, self.expect_queries);
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(&self,
               acceptable_issuers: &[&[u8]],
               sigschemes: &[SignatureScheme])
        -> Option<sign::CertChainAndSigner> {
        self.query_count.fetch_add(1, atomic::Ordering::SeqCst);

        if acceptable_issuers.len() == 0 {
            panic!("no issuers offered by server");
        }

        if sigschemes.len() == 0 {
            panic!("no signature schemes shared by server");
        }

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn client_cert_resolve() {
    let mut client_config = make_client_config();
    let mut server_config = make_server_config();

    client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(1));
    server_config.set_client_auth_roots(get_chain(), true);

    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    let mut server = ServerSession::new(&Arc::new(server_config));

    let err = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(err.is_err(), true);
}

#[test]
fn client_error_is_sticky() {
    let client_config = make_client_config();
    let mut client = ClientSession::new(&Arc::new(client_config), "localhost");
    client.read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref()).unwrap();
    let mut err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_error_is_sticky() {
    let server_config = make_server_config();
    let mut server = ServerSession::new(&Arc::new(server_config));
    server.read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref()).unwrap();
    let mut err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_is_send() {
    let server_config = make_server_config();
    let server = ServerSession::new(&Arc::new(server_config));
    &server as &Send;
}

#[test]
fn client_is_send() {
    let client_config = make_client_config();
    let client = ClientSession::new(&Arc::new(client_config), "localhost");
    &client as &Send;
}

#[test]
fn server_respects_buffer_limit_pre_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    server.set_buffer_limit(32);

    assert_eq!(server.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(server.write(b"01234567890123456789").unwrap(), 12);

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client, b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_post_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    // this test will vary in behaviour depending on the default suites
    do_handshake(&mut client, &mut server);
    server.set_buffer_limit(48);

    assert_eq!(server.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(server.write(b"01234567890123456789").unwrap(), 6);

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client, b"01234567890123456789012345");
}

#[test]
fn client_respects_buffer_limit_pre_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    client.set_buffer_limit(32);

    assert_eq!(client.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(client.write(b"01234567890123456789").unwrap(), 12);

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server, b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_post_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    do_handshake(&mut client, &mut server);
    client.set_buffer_limit(48);

    assert_eq!(client.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(client.write(b"01234567890123456789").unwrap(), 6);

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server, b"01234567890123456789012345");
}

struct OtherSession<'a> {
    sess: &'a mut Session,
    pub reads: usize,
    pub writes: usize,
}

impl<'a> OtherSession<'a> {
    fn new(sess: &'a mut Session) -> OtherSession<'a> {
        OtherSession { sess, reads: 0, writes: 0 }
    }
}

impl<'a> io::Read for OtherSession<'a> {
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<'a> io::Write for OtherSession<'a> {
    fn write(&mut self, mut b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let l = self.sess.read_tls(b.by_ref())?;
        self.sess.process_new_packets().unwrap();
        Ok(l)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn client_complete_io_for_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    assert_eq!(true, client.is_handshaking());
    let (rdlen, wrlen) = client.complete_io(&mut OtherSession::new(&mut server)).unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert_eq!(false, client.is_handshaking());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, client.is_handshaking());
    let err = client.complete_io(&mut input).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    do_handshake(&mut client, &mut server);

    client.write(b"01234567890123456789").unwrap();
    client.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
        assert!(rdlen == 0 && wrlen > 0);
        assert_eq!(pipe.writes, 2);
    }
    check_read(&mut server, b"0123456789012345678901234567890123456789");
}

#[test]
fn client_complete_io_for_read() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    do_handshake(&mut client, &mut server);

    server.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
        assert!(rdlen > 0 && wrlen == 0);
        assert_eq!(pipe.reads, 1);
    }
    check_read(&mut client, b"01234567890123456789");
}

#[test]
fn server_complete_io_for_handshake() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    assert_eq!(true, server.is_handshaking());
    let (rdlen, wrlen) = server.complete_io(&mut OtherSession::new(&mut client)).unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert_eq!(false, server.is_handshaking());
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let mut server = ServerSession::new(&Arc::new(make_server_config()));
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, server.is_handshaking());
    let err = server.complete_io(&mut input).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    do_handshake(&mut client, &mut server);

    server.write(b"01234567890123456789").unwrap();
    server.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
        assert!(rdlen == 0 && wrlen > 0);
        assert_eq!(pipe.writes, 2);
    }
    check_read(&mut client, b"0123456789012345678901234567890123456789");
}

#[test]
fn server_complete_io_for_read() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    do_handshake(&mut client, &mut server);

    client.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
        assert!(rdlen > 0 && wrlen == 0);
        assert_eq!(pipe.reads, 1);
    }
    check_read(&mut server, b"01234567890123456789");
}

#[test]
fn client_stream_write() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    {
        let mut pipe = OtherSession::new(&mut server);
        let mut stream = Stream::new(&mut client, &mut pipe);
        assert_eq!(stream.write(b"hello").unwrap(), 5);
    }
    check_read(&mut server, b"hello");
}

#[test]
fn client_stream_read() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    server.write(b"world").unwrap();

    {
        let mut pipe = OtherSession::new(&mut server);
        let mut stream = Stream::new(&mut client, &mut pipe);
        check_read(&mut stream, b"world");
    }
}

#[test]
fn server_stream_write() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    {
        let mut pipe = OtherSession::new(&mut client);
        let mut stream = Stream::new(&mut server, &mut pipe);
        assert_eq!(stream.write(b"hello").unwrap(), 5);
    }
    check_read(&mut client, b"hello");
}

#[test]
fn server_stream_read() {
    let mut client = ClientSession::new(&Arc::new(make_client_config()), "localhost");
    let mut server = ServerSession::new(&Arc::new(make_server_config()));

    client.write(b"world").unwrap();

    {
        let mut pipe = OtherSession::new(&mut client);
        let mut stream = Stream::new(&mut server, &mut pipe);
        check_read(&mut stream, b"world");
    }
}
