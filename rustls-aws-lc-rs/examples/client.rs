//! This is the simplest possible client using post-quantum algorithms, based on
//! `simple-client.rs`.
//!
//! It sends a HTTP request to pq.cloudflareresearch.com and prints the response to
//! stdout.  Observe in that output: `kex=X25519MLKEM768`
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::VecInput;
use rustls_aws_lc_rs::DEFAULT_PROVIDER;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt::init();

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = rustls::ClientConfig::builder(Arc::new(DEFAULT_PROVIDER))
        .with_root_certificates(root_store)
        .with_no_client_auth()?;

    let server_name = "pq.cloudflareresearch.com".try_into()?;

    let mut output = Vec::new();
    let mut conn = Arc::new(config)
        .connect(server_name)
        .build(&mut output)?;
    let mut sock = TcpStream::connect("pq.cloudflareresearch.com:443").unwrap();
    let mut input = VecInput::default();
    let mut plaintext = Vec::new();

    while conn.is_handshaking() {
        sock.write_all(&output)?;
        output.clear();
        if input.read(&mut sock)? == 0 {
            return Err("server closed connection during handshake".into());
        }
        conn.read_tls(&mut input, &mut output)
            .handle_all(&mut plaintext)?;
    }

    let ciphersuite = conn.negotiated_cipher_suite().unwrap();
    eprintln!("Current ciphersuite: {:?}", ciphersuite.suite());

    let kx_group = conn
        .negotiated_key_exchange_group()
        .unwrap();
    eprintln!("Current key exchange group: {kx_group:?}",);

    conn.write(
        concat!(
            "GET /cdn-cgi/trace HTTP/1.0\r\n",
            "Host: pq.cloudflareresearch.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes()
        .into(),
        &mut output,
    )?;
    sock.write_all(&output)?;
    output.clear();

    loop {
        let read = input.read(&mut sock)?;
        let state = conn
            .read_tls(&mut input, &mut output)
            .handle_all(&mut plaintext)?;
        stdout().write_all(&plaintext)?;
        plaintext.clear();
        sock.write_all(&output)?;
        output.clear();

        if state.peer_has_closed() {
            return Ok(());
        } else if read == 0 {
            return Err("server closed connection without sending TLS close_notify".into());
        }
    }
}
