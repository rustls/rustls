use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::{fs, str, thread};

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rustls::crypto::{CryptoProvider, Identity, aws_lc_rs as provider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::ffdhe::{self, FFDHE2048_GROUP};
use crate::utils::verify_openssl3_available;

#[test]
fn rustls_server_with_ffdhe_kx_tls13() {
    test_rustls_server_with_ffdhe_kx(FFDHE_TLS13_PROVIDER, 1)
}

#[test]
fn rustls_server_with_ffdhe_kx_tls12() {
    test_rustls_server_with_ffdhe_kx(FFDHE_TLS12_PROVIDER, 1)
}

fn test_rustls_server_with_ffdhe_kx(provider: CryptoProvider, iters: usize) {
    verify_openssl3_available();

    let message = "Hello from rustls!\n";

    let listener = TcpListener::bind(("localhost", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let config = Arc::new(server_config_with_ffdhe_kx(provider));
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

    let server_thread = thread::spawn(move || {
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
        let mut tcp_stream = TcpStream::connect(("localhost", port)).unwrap();
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
    ClientConfig::builder(
        // OpenSSL 3 does not support RFC 7919 with TLS 1.2: https://github.com/openssl/openssl/issues/10971
        FFDHE_TLS13_PROVIDER.into(),
    )
    .with_root_certificates(root_ca())
    .with_no_client_auth()
    .unwrap()
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
    test_rustls_server_with_ffdhe_kx(FFDHE_TLS13_PROVIDER, 512)
}

#[test]
#[ignore]
fn rustls_server_with_ffdhe_tls12_repeated() {
    test_rustls_server_with_ffdhe_kx(FFDHE_TLS12_PROVIDER, 512);
}

fn root_ca() -> RootCertStore {
    let mut res = RootCertStore::with_capacity(1);
    res.add_parsable_certificates([CertificateDer::from(fs::read(CA_FILE).unwrap())]);
    res
}

fn load_certs() -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(CERT_CHAIN_FILE)
        .unwrap()
        .map(|c| c.unwrap())
        .collect()
}

fn load_private_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(PRIV_KEY_FILE).unwrap()
}

const FFDHE_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[&ffdhe::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]),
    tls13_cipher_suites: Cow::Borrowed(&[provider::cipher_suite::TLS13_AES_128_GCM_SHA256]),
    kx_groups: Cow::Borrowed(&[FFDHE2048_GROUP]),
    ..provider::DEFAULT_PROVIDER
};

const FFDHE_TLS12_PROVIDER: CryptoProvider = CryptoProvider {
    tls13_cipher_suites: Cow::Borrowed(&[]),
    ..FFDHE_PROVIDER
};

const FFDHE_TLS13_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[]),
    ..FFDHE_PROVIDER
};

fn server_config_with_ffdhe_kx(provider: CryptoProvider) -> ServerConfig {
    ServerConfig::builder(provider.into())
        .with_no_client_auth()
        .with_single_cert(
            Arc::new(Identity::from_cert_chain(load_certs()).unwrap()),
            load_private_key(),
        )
        .unwrap()
}

const CERT_CHAIN_FILE: &str = "../test-ca/rsa-2048/end.fullchain";
const PRIV_KEY_FILE: &str = "../test-ca/rsa-2048/end.key";
const CA_FILE: &str = "../test-ca/rsa-2048/ca.der";
const CA_PEM_FILE: &str = "../test-ca/rsa-2048/ca.cert";
