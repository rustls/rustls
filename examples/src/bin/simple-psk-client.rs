use std::collections::HashMap;
use std::env;
use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::crypto::PresharedKey;
use rustls::crypto::hash::HashAlgorithm;

use rustls::pki_types::ServerName;

fn main() {
    env_logger::init();

    let mut args = env::args();
    args.next();
    let identity = args.next().expect("missing identity");
    let secret = args.next().expect("missing secret");

    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let server_name = "localhost";

    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
    config.preshared_keys = Arc::new({
        let mut keys = PresharedKeys::new();
        for alg in [HashAlgorithm::SHA256, HashAlgorithm::SHA384] {
            let psk = PresharedKey::external(identity.as_bytes(), secret.as_bytes())
                .unwrap()
                .with_hash_alg(alg);
            keys.insert(server_name.try_into().unwrap(), psk);
        }
        keys
    });

    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name.try_into().unwrap()).unwrap();
    let mut sock = TcpStream::connect(format!("{server_name}:4443")).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
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

#[derive(Debug)]
struct PresharedKeys {
    keys: HashMap<ServerName<'static>, Vec<Arc<PresharedKey>>>,
}

impl PresharedKeys {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn insert(&mut self, server_name: ServerName<'_>, psk: PresharedKey) {
        let psk = Arc::new(psk);
        self.keys
            .entry(server_name.to_owned())
            .and_modify(|e| e.push(psk.clone()))
            .or_insert_with(|| vec![psk.clone()]);
    }
}

impl rustls::client::PresharedKeyStore for PresharedKeys {
    fn psks(&self, server_name: &ServerName<'_>) -> Vec<Arc<PresharedKey>> {
        self.keys.get(server_name).cloned()
    }
}
