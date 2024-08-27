use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::{str, thread};

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::ffdhe::{self, FfdheKxGroup};
use crate::utils::verify_openssl3_available;

#[test]
fn rustls_server_with_ffdhe_kx_tls13() {
    test_rustls_server_with_ffdhe_kx(&TLS13, 1)
}

#[test]
fn rustls_server_with_ffdhe_kx_tls12() {
    test_rustls_server_with_ffdhe_kx(&TLS12, 1)
}

fn test_rustls_server_with_ffdhe_kx(
    protocol_version: &'static SupportedProtocolVersion,
    iters: usize,
) {
    verify_openssl3_available();

    let message = "Hello from rustls!\n";

    let listener = std::net::TcpListener::bind(("localhost", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = std::thread::spawn(move || {
        let config = Arc::new(server_config_with_ffdhe_kx(protocol_version));
        for _ in 0..iters {
            let mut server = rustls::ServerConnection::new(config.clone()).unwrap();
            let (mut tcp_stream, _addr) = listener.accept().unwrap();
            server
                .writer()
                .write_all(message.as_bytes())
                .unwrap();
            server
                .complete_io(&mut tcp_stream)
                .unwrap();
            tcp_stream.flush().unwrap();
        }
    });

    let mut connector = openssl::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .set_ca_file(CA_PEM_FILE)
        .unwrap();
    connector
        .set_groups_list("ffdhe2048")
        .unwrap();

    let connector = connector.build();

    for _iter in 0..iters {
        let stream = TcpStream::connect(("localhost", port)).unwrap();
        let mut stream = connector
            .connect("testserver.com", stream)
            .unwrap();

        let mut buf = String::new();
        stream.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, message);
    }

    server_thread.join().unwrap();
}

#[test]
fn rustls_client_with_ffdhe_kx() {
    test_rustls_client_with_ffdhe_kx(1);
}

fn test_rustls_client_with_ffdhe_kx(iters: usize) {
    verify_openssl3_available();

    let message = "Hello from rustls!\n";

    println!("crate openssl version: {}", openssl::version::version());

    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_groups_list("ffdhe2048")
        .unwrap();
    acceptor
        .set_private_key_file(PRIV_KEY_FILE, SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file(CERT_CHAIN_FILE)
        .unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind(("localhost", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = std::thread::spawn(move || {
        for stream in listener.incoming().take(iters) {
            match stream {
                Ok(stream) => {
                    let acceptor = acceptor.clone();
                    thread::spawn(move || {
                        let mut stream = acceptor.accept(stream).unwrap();
                        let mut buf = String::new();
                        stream.read_to_string(&mut buf).unwrap();
                        assert_eq!(buf, message);
                    });
                }
                Err(e) => {
                    panic!("openssl connection failed: {e}");
                }
            }
        }
    });

    // client:
    for _ in 0..iters {
        let mut tcp_stream = std::net::TcpStream::connect(("localhost", port)).unwrap();
        let mut client = rustls::client::ClientConnection::new(
            client_config_with_ffdhe_kx().into(),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        client
            .writer()
            .write_all(message.as_bytes())
            .unwrap();
        client
            .complete_io(&mut tcp_stream)
            .unwrap();
        client.send_close_notify();
        client
            .write_tls(&mut tcp_stream)
            .unwrap();
        tcp_stream.flush().unwrap();
    }

    server_thread.join().unwrap();
}

fn client_config_with_ffdhe_kx() -> ClientConfig {
    ClientConfig::builder_with_provider(ffdhe_provider().into())
        // OpenSSL 3 does not support RFC 7919 with TLS 1.2: https://github.com/openssl/openssl/issues/10971
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(root_ca())
        .with_no_client_auth()
}

// TLS 1.2 requires stripping leading zeros of the shared secret,
// While TLS 1.3 requires the shared secret to be padded with zeros.
// The chance of getting a shared secret with the first byte being zero is 1 in 256,
// so we repeat the tests to have a high chance of getting a kx with this property.
#[test]
#[ignore]
fn rustls_client_with_ffdhe_kx_repeated() {
    test_rustls_client_with_ffdhe_kx(512);
}

#[test]
#[ignore]
fn rustls_server_with_ffdhe_tls13_repeated() {
    test_rustls_server_with_ffdhe_kx(&TLS13, 512)
}

#[test]
#[ignore]
fn rustls_server_with_ffdhe_tls12_repeated() {
    test_rustls_server_with_ffdhe_kx(&TLS12, 512);
}

fn root_ca() -> RootCertStore {
    let mut res = RootCertStore::empty();
    res.add_parsable_certificates([CertificateDer::from(fs::read(CA_FILE).unwrap())]);
    res
}

fn load_certs() -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(File::open(CERT_CHAIN_FILE).unwrap());
    rustls_pemfile::certs(&mut reader)
        .map(|c| c.unwrap())
        .collect()
}

fn load_private_key() -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(File::open(PRIV_KEY_FILE).unwrap());

    match rustls_pemfile::read_one(&mut reader)
        .unwrap()
        .unwrap()
    {
        Item::Pkcs1Key(key) => key.into(),
        Item::Pkcs8Key(key) => key.into(),
        Item::Sec1Key(key) => key.into(),
        _ => panic!("no key in key file {PRIV_KEY_FILE}"),
    }
}

fn ffdhe_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![
            ffdhe::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ],
        kx_groups: vec![&FfdheKxGroup(
            rustls::NamedGroup::FFDHE2048,
            rustls::ffdhe_groups::FFDHE2048,
        )],
        ..provider::default_provider()
    }
}

fn server_config_with_ffdhe_kx(protocol: &'static SupportedProtocolVersion) -> ServerConfig {
    ServerConfig::builder_with_provider(ffdhe_provider().into())
        .with_protocol_versions(&[protocol])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(load_certs(), load_private_key())
        .unwrap()
}

const CERT_CHAIN_FILE: &str = "../test-ca/rsa-2048/end.fullchain";
const PRIV_KEY_FILE: &str = "../test-ca/rsa-2048/end.key";
const CA_FILE: &str = "../test-ca/rsa-2048/ca.der";
const CA_PEM_FILE: &str = "../test-ca/rsa-2048/ca.cert";
