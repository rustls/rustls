//! This is the simplest possible client using rustls-postquantum, based on
//! `simpleclient.rs`.
//!
//! It sends a HTTP request to pq.cloudflareresearch.com and prints the response to
//! stdout.  Observe in that output: `kex=X25519MLKEM768`
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

fn main() {
    env_logger::init();
    rustls_post_quantum::provider()
        .install_default()
        .unwrap();

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "pq.cloudflareresearch.com"
        .try_into()
        .unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("pq.cloudflareresearch.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET /cdn-cgi/trace HTTP/1.0\r\n",
            "Host: pq.cloudflareresearch.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let kx_group = tls
        .conn
        .negotiated_key_exchange_group()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current key exchange group: {kx_group:?}",
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
