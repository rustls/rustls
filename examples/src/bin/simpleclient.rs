//! This is the simplest possible client using rustls that does something useful:
//! it accepts the default configuration, loads some root certs, and then connects
//! to rust-lang.org and issues a basic HTTP request.  The response is printed to stdout.
//!
//! It makes use of rustls::Stream to treat the underlying TLS connection as a basic
//! bi-directional stream -- the underlying IO is performed transparently.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_util::{KeyLogFile, Stream};

fn main() {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let mut config = ClientConfig::builder(rustls_aws_lc_rs::DEFAULT_PROVIDER.into())
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .unwrap();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(KeyLogFile::new());

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
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
