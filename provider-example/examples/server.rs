use std::io::Write;
use std::sync::Arc;

use rustls::crypto::Identity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::{Connection, ServerConfig};
use rustls_util::{KeyLogFile, complete_io};

fn main() {
    env_logger::init();

    let pki = TestPki::new();
    let server_config = pki.server_config();

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                // Note: do not use `unwrap()` on IO in real programs!
                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                complete_io(&mut stream, &mut conn).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                complete_io(&mut stream, &mut conn).unwrap();
            }
            Err((err, _)) => {
                eprintln!("{err}");
            }
        }
    }
}

struct TestPki {
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca = rcgen::Issuer::new(ca_params, ca_key);

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();

        let server_cert = server_ee_params
            .signed_by(&server_key, &ca)
            .unwrap();
        Self {
            server_cert_der: server_cert.into(),
            // TODO(XXX): update below once https://github.com/rustls/rcgen/issues/260 is resolved.
            server_key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls_provider_example::provider());
        let mut server_config = ServerConfig::builder(provider.clone())
            .with_no_client_auth()
            .with_single_cert(
                Arc::new(Identity::from_cert_chain(vec![self.server_cert_der]).unwrap()),
                self.server_key_der,
            )
            .unwrap();

        server_config.key_log = Arc::new(KeyLogFile::new());
        server_config.ticketer = provider
            .ticketer_factory
            .ticketer()
            .ok();

        Arc::new(server_config)
    }
}
