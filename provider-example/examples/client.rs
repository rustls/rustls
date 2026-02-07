use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, Connection, RootCertStore};
use rustls_provider_example::provider;
use rustls_util::Stream;

fn main() {
    env_logger::init();

    let root_store = RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let config = Arc::new(
        ClientConfig::builder(provider().into())
            .with_root_certificates(root_store)
            .with_no_client_auth()
            .unwrap(),
    );

    let mut conn = config
        .connect("www.rust-lang.org".try_into().unwrap())
        .build()
        .unwrap();

    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut tls = Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
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
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
