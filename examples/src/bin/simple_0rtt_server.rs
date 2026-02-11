//! This is an example server that streams 0-RTT early data from the client.
//!
//! Usage: cargo r --bin simple_0rtt_server --package rustls-examples <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! You can test interaction either with simple_0rtt_client or with OpenSSL:
//!
//! `openssl s_client -connect localhost:4443 -sess_out sess.pem`
//!
//! `openssl s_client -connect localhost:4443 -sess_in sess.pem -early_data early.txt`
//!
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use core::error::Error as StdError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::{env, io};

use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{Connection, ServerConfig, ServerConnection, TlsInputBuffer};
use rustls_aws_lc_rs::DEFAULT_PROVIDER;
use rustls_util::complete_io;

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
        .expect("cannot open certificate file")
        .map(|cert| cert.unwrap())
        .collect();
    let private_key =
        PrivateKeyDer::from_pem_file(private_key_file).expect("cannot open private key file");

    let mut config = ServerConfig::builder(Arc::new(DEFAULT_PROVIDER))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), private_key)?;
    config.max_early_data_size = 1000;

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();

    loop {
        let (mut stream, _) = listener.accept()?;

        println!("Accepting connection");

        let mut conn = ServerConnection::new(Arc::new(config.clone()))?;

        let mut input = TlsInputBuffer::default();
        let mut buf = Vec::new();
        let mut did_early_data = false;
        'handshake: while conn.is_handshaking() {
            while conn.wants_write() {
                if conn.write_tls(&mut stream)? == 0 {
                    // EOF
                    stream.flush()?;
                    break 'handshake;
                }
            }
            stream.flush()?;

            while conn.wants_read() {
                match input.read(&mut stream, true) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                    Ok(_) => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return Err(err.into()),
                };
            }

            if let Err(e) = conn.process_new_packets(&mut input) {
                let _ignored = conn.write_tls(&mut stream);
                stream.flush()?;

                return Err(io::Error::new(io::ErrorKind::InvalidData, e).into());
            };

            if let Some(mut early_data) = conn.early_data() {
                if !did_early_data {
                    println!("Receiving early data from client");
                    did_early_data = true;
                }

                let bytes_read = early_data
                    .read_to_end(&mut buf)
                    .unwrap();

                if bytes_read != 0 {
                    println!("Early data from client: {buf:?}");
                }
            }
        }

        if !did_early_data {
            println!("Did not receive early data from client");
        }

        println!("Handshake complete\n");

        conn.writer()
            .write_all(b"Hello from the server")?;
        conn.send_close_notify();
        complete_io(&mut stream, &mut input, &mut conn)?;
    }
}
