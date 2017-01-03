// Assorted public API tests.
use std::sync::Arc;
use std::fs;
use std::io::{self, Write};

extern crate rustls;
use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::Session;
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
    assert_eq!(server.is_handshaking(), true);
    assert_eq!(client.is_handshaking(), true);
    transfer(client, server);
    server.process_new_packets().unwrap();
    assert_eq!(server.is_handshaking(), true);
    assert_eq!(client.is_handshaking(), true);
    transfer(server, client);
    client.process_new_packets().unwrap();
    assert_eq!(server.is_handshaking(), true);
    assert_eq!(client.is_handshaking(), true);
    transfer(client, server);
    server.process_new_packets().unwrap();
    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), true);
    transfer(server, client);
    client.process_new_packets().unwrap();
    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), false);
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
