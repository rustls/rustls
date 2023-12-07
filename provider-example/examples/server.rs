use std::io::Write;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::Acceptor;
use rustls::ServerConfig;

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
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(e) => {
                eprintln!("{}", e);
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
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
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
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = CertificateDer::from(
            server_cert
                .serialize_der_with_signer(&ca_cert)
                .unwrap(),
        );
        let server_key_der =
            PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der()).into();
        Self {
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        let mut server_config =
            ServerConfig::builder_with_provider(rustls_provider_example::provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.server_cert_der], self.server_key_der)
                .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}
