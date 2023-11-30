use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use futures::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_async::{Error, TcpConnector};

// runtime selection:
// - adjust the dependencies in `Cargo.toml`
// - adjust the imports in this file
// - uppdate the attribute on the `main` function
// - comment / uncomment the `compat_write` call in `main` if using `async_std` / `tokio`
use async_std::net::TcpStream;

// use tokio::net::TcpStream;
// use tokio_util::compat::TokioAsyncWriteCompatExt;

// remote server
const CERTFILE: Option<&str> = None;
const SERVER_NAME: &str = "example.com";
const PORT: u16 = 443;

#[async_std::main]
// #[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        // switch protocol version
        .with_protocol_versions(&[&TLS12])
        // .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(build_root_store()?)
        .with_no_client_auth();

    let config = Arc::new(config);

    let sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}")).await?;

    // tokio only
    // let sock = sock.compat_write();

    let connector = TcpConnector::from(config);
    let domain = SERVER_NAME.try_into().unwrap();
    let mut stream = connector.connect(domain, sock)?.await?;

    let request = build_http_request();
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0; 8 * 1024];
    let read = stream.read(&mut response).await?;
    println!("{}", String::from_utf8_lossy(&response[..read]));

    Ok(())
}

fn build_root_store() -> Result<RootCertStore, Error> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = CERTFILE {
        let certfile = File::open(path)?;
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?,
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }
    Ok(root_store)
}

fn build_http_request() -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").into_bytes()
}
