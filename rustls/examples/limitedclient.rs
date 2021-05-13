/// limitedclient: This example demonstrates usage of ClientConfig building
/// so that unused cryptography in rustls can be discarded by the linker.  You can
/// observe using `nm` that the binary of this program does not contain any AES code.
use std::sync::Arc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;

use rustls;
use webpki;
use webpki_roots;

use rustls::Connection;

fn main() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = rustls::ConfigBuilder::with_cipher_suites(&[
        &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ])
    .with_kx_groups(&[&rustls::kx_group::X25519])
    .with_protocol_versions(&[&rustls::version::TLS13])
    .for_client()
    .unwrap()
    .with_root_certificates(root_store, &[])
    .with_no_client_auth();

    let dns_name = webpki::DnsNameRef::try_from_ascii_str("google.com").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), dns_name).unwrap();
    let mut sock = TcpStream::connect("google.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
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
        ciphersuite.suite
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
