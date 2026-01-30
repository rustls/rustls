//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use core::error::Error as StdError;
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use rustls_aws_lc_rs::DEFAULT_PROVIDER;
use rustls_util::Stream;

fn main() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
    let config = ServerConfig::builder(Arc::new(DEFAULT_PROVIDER))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), private_key)?;

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut tcp_stream, _) = listener.accept()?;
    let mut conn = ServerConnection::new(Arc::new(config))?;
    let mut tls_stream = Stream::new(&mut conn, &mut tcp_stream);

    tls_stream.write_all(b"Hello from the server")?;
    tls_stream.flush()?;
    let mut buf = [0; 64];
    let len = tls_stream.read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}
