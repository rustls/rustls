use pki_types::CertificateDer;
use pki_types::PrivateKeyDer;
use rustls::crypto::CryptoProvider;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_provider_example::sign::ecdsa::EcdsaSigningKeyP256;
use rustls_provider_example::Provider;
use std::io::Write;
use std::sync::Arc;

struct ExampleResolvesServerCert(Arc<CertifiedKey>);

impl ExampleResolvesServerCert {
    pub fn new(cert_chain: Vec<CertificateDer<'static>>, key_der: PrivateKeyDer<'_>) -> Self {
        let key: EcdsaSigningKeyP256 = key_der.try_into().unwrap();

        Self(Arc::new(CertifiedKey::new(cert_chain, Arc::new(key))))
    }
}

impl ResolvesServerCert for ExampleResolvesServerCert {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = server_cert
            .serialize_der_with_signer(&ca_cert)
            .unwrap();
        let server_key_der = server_cert.serialize_private_key_der();
        Self {
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config<C: CryptoProvider>(&self) -> Arc<ServerConfig<C>> {
        let mut server_config: ServerConfig<C> = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ExampleResolvesServerCert::new(
                vec![self.server_cert_der.clone().into()],
                PrivateKeyDer::Pkcs8(self.server_key_der.clone().into()),
            )));

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}

fn main() {
    env_logger::init();

    let pki = TestPki::new();
    let server_config = pki.server_config::<Provider>();

    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", 4443)).unwrap();
    'accept: for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            if let Ok(_) = acceptor.read_tls(&mut stream) {
                if let Ok(Some(accepted)) = acceptor.accept() {
                    break accepted;
                }
            }

            eprintln!("unexpected connection");
            continue 'accept;
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

                let _ = conn.writer().write(msg);
                let _ = conn.write_tls(&mut stream);
                _ = conn.complete_io(&mut stream);

                conn.send_close_notify();
                let _ = conn.write_tls(&mut stream);
                _ = conn.complete_io(&mut stream);
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}
