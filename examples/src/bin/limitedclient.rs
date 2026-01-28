//! limitedclient: This example demonstrates usage of ClientConfig building
//! so that unused cryptography in rustls can be discarded by the linker.  You can
//! observe using `nm` that the binary of this program does not contain any AES code.

use std::borrow::Cow;
use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls_aws_lc_rs as provider;
use rustls_util::Stream;

fn main() {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let config = rustls::ClientConfig::builder(PROVIDER.into())
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .unwrap();

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
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

const PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[]),
    tls13_cipher_suites: Cow::Borrowed(&[provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
    kx_groups: Cow::Borrowed(&[provider::kx_group::X25519]),
    ..provider::DEFAULT_PROVIDER
};
