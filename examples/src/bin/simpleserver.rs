//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! You must either set the CERTFILE and PRIV_KEY_FILE env vars to point to a server
//! certificate and private key, or place 'localhost.pem' and 'localhost-key.pem' in
//! the directory you run this example from.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::error::Error as StdError;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const CERTFILE: &str = match option_env!("CERTFILE") {
    Some(certfile) => certfile,
    None => "localhost.pem",
};

const PRIV_KEY_FILE: &str = match option_env!("PRIV_KEY_FILE") {
    Some(priv_key_file) => priv_key_file,
    None => "localhost-key.pem",
};

fn main() -> Result<(), Box<dyn StdError>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(CERTFILE)?))
        .collect::<Result<Vec<_>, _>>()?;
    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(PRIV_KEY_FILE)?))?.unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut stream, _) = listener.accept()?;

    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;
    conn.complete_io(&mut stream)?;

    conn.writer()
        .write_all(b"Hello from the server")?;
    conn.complete_io(&mut stream)?;
    let mut buf = [0; 64];
    let len = conn.reader().read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}
