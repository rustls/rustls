//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::collections::HashMap;
use std::env;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::str;
use std::sync::Arc;

use rustls::crypto::PresharedKey;
use rustls::crypto::hash::HashAlgorithm;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::Acceptor;

fn main() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let identity = args.next().expect("missing identity");
    let secret = args.next().expect("missing secret");

    println!("secret = {:x?}", secret.as_bytes());

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;

    config.preshared_keys = Arc::new({
        let mut keys = PresharedKeys::new();
        for alg in [HashAlgorithm::SHA256, HashAlgorithm::SHA384] {
            let psk = PresharedKey::external(identity.as_bytes(), secret.as_bytes())
                .unwrap()
                .with_hash_alg(alg);
            keys.insert(psk);
        }
        keys
    });

    let config = Arc::new(config);

    let listener = TcpListener::bind("localhost:4443")?;

    'incoming: for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();

            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write_all(&mut stream).unwrap();
                    println!("error accepting connection: {e}");
                    continue 'incoming;
                }
            }
        };
        let mut conn = match accepted.into_connection(config.clone()) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                alert.write_all(&mut stream).unwrap();
                println!("error completing accepting connection: {e}");
                continue;
            }
        };

        let (nr, nw) = conn.complete_io(&mut stream)?;
        println!("complete_io: ({nr}, {nw})");

        conn.read_tls(&mut stream)?;

        let state = conn.process_new_packets()?;
        println!("state = {state:?}");

        let mut buf = vec![0; state.plaintext_bytes_to_read()];
        retry(|| conn.reader().read_exact(&mut buf))?;
        println!(
            "received {} bytes from client: {}",
            buf.len(),
            str::from_utf8(&buf).unwrap()
        );

        retry(|| {
            let msg = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Connection: Closed\r\n",
                "Content-Type: text/html\r\n",
                "\r\n",
                "<h1>Hello World!</h1>\r\n"
            );
            conn.writer()
                .write_all(msg.as_bytes())?;
            conn.complete_io(&mut stream)
        })?;
        println!("wrote response");

        conn.send_close_notify();
        conn.write_tls(&mut stream).unwrap();
        conn.complete_io(&mut stream).unwrap();
    }

    Ok(())
}

fn retry<F, T>(mut f: F) -> std::io::Result<T>
where
    F: FnMut() -> std::io::Result<T>,
{
    for _ in 0..10 {
        match f() {
            Ok(v) => return Ok(v),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                println!("continue");
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "too many loops",
    ))
}

#[derive(Debug)]
struct PresharedKeys {
    keys: HashMap<Vec<u8>, Arc<PresharedKey>>,
}

impl PresharedKeys {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn insert(&mut self, psk: PresharedKey) {
        let identity = psk.identity().to_vec();
        self.keys
            .insert(identity, Arc::new(psk));
    }
}

impl rustls::server::SelectsPresharedKeys for PresharedKeys {
    fn load_psk(&self, identity: &[u8]) -> Option<Arc<PresharedKey>> {
        self.keys.get(identity).cloned()
    }
}
