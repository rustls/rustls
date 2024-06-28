use log::trace;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::{
    aws_lc_rs as provider, verify_tls12_signature_with_spki, verify_tls13_signature_with_spki,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::version::TLS12;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, ServerConfig,
    ServerConnection, SignatureScheme, Stream,
};
use std::time::Duration;
use std::{
    env,
    fs::File,
    io::{BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    result::Result,
    sync::Arc,
};
use std::{io, thread};

fn load_rpk(path_to_rpk: &str) -> Result<SubjectPublicKeyInfoDer<'static>, io::Error> {
    let file = File::open(path_to_rpk)?;
    let mut reader = BufReader::new(file);
    let cert = rustls_pemfile::public_key(&mut reader)
        .map_err(|_| io::Error::new(std::io::ErrorKind::InvalidData, "Invalid public key data"))?;
    Ok(cert.unwrap())
}

fn load_private_key(path_to_private_key: &str) -> Result<PrivateKeyDer<'static>, io::Error> {
    let file = File::open(path_to_private_key)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| std::io::Error::new(io::ErrorKind::InvalidData, "Invalid private key data"))?;

    Ok(key.unwrap())
}

fn create_rpk_client_config(
    client_spki_cert: SubjectPublicKeyInfoDer<'static>,
    client_private_key: PrivateKeyDer<'static>,
    server_spki_certs: Vec<SubjectPublicKeyInfoDer<'static>>,
) -> ClientConfig {
    let server_cert_verifier = Arc::new(SimpleRpkServerCertVerifier::new(server_spki_certs));
    ClientConfig::builder_with_protocol_versions(&[&TLS12])
        .dangerous()
        .with_custom_certificate_verifier(server_cert_verifier)
        .with_client_auth_rpk(client_spki_cert, client_private_key)
        .unwrap()
}

fn create_rpk_server_config(
    server_spki_cert: SubjectPublicKeyInfoDer<'static>,
    server_private_key: PrivateKeyDer<'static>,
    client_spki_certs: Vec<SubjectPublicKeyInfoDer<'static>>,
) -> ServerConfig {
    let client_cert_verifier = Arc::new(SimpleRpkClientCertVerifier::new(client_spki_certs));
    ServerConfig::builder_with_protocol_versions(&[&TLS12])
        .with_client_cert_verifier(client_cert_verifier)
        .with_rpk(server_spki_cert, server_private_key)
        .unwrap()
}

fn run_client(config: ClientConfig) -> Result<(), io::Error> {
    let server_name = "0.0.0.0".try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("[::]:{}", 4443)).unwrap();
    let mut tls = Stream::new(&mut conn, &mut sock);

    let mut buf = vec![0; 128];
    let len = tls.read(&mut buf).unwrap();
    println!("Received message from server: {:?}", &buf[..len]);

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();

    let bytes_written = tls
        .write(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: www.rust-lang.org\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

    println!("Wrote {} bytes", bytes_written);
    Ok(())
}

fn run_server(config: ServerConfig) -> Result<(), io::Error> {
    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut stream, _) = listener.accept()?;

    let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
    conn.complete_io(&mut stream)?;
    trace!("Server accepted connection from client");

    conn.writer()
        .write_all(b"Hello from the server")?;
    conn.complete_io(&mut stream)?;
    trace!("Server sent message to client");

    let mut buf = [0; 64];
    conn.complete_io(&mut stream)?;
    match conn.reader().read(&mut buf) {
        Ok(len) => {
            trace!("Received message from client: {:?}", &buf[..len]);
        }
        Err(err) => {
            return Err(err);
        }
    }

    Ok(())
}

#[derive(Debug)]
struct SimpleRpkClientCertVerifier {
    trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl SimpleRpkClientCertVerifier {
    pub fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
        let provider = Arc::new(provider::default_provider());
        Self {
            trusted_spki,
            supported_algs: provider
                .clone()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for SimpleRpkClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        match self
            .trusted_spki
            .contains(&end_entity_as_spki)
        {
            false => {
                trace!("Server certificate not trusted");
                Err(rustls::Error::NoCertificatesPresented)
            }
            true => {
                trace!("Server certificate trusted");
                Ok(ClientCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        trace!("Verifying TLS 1.2 server signature");
        verify_tls12_signature_with_spki(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        trace!("Verifying TLS 1.3 server signature");
        verify_tls13_signature_with_spki(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        trace!(
            "Supported schemes: {:?}",
            self.supported_algs.supported_schemes()
        );
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct SimpleRpkServerCertVerifier {
    trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl SimpleRpkServerCertVerifier {
    fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
        let provider = Arc::new(provider::default_provider());
        SimpleRpkServerCertVerifier {
            trusted_spki,
            supported_algs: provider
                .clone()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for SimpleRpkServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        match self
            .trusted_spki
            .contains(&end_entity_as_spki)
        {
            false => {
                trace!("Server certificate not trusted");
                Err(rustls::Error::NoCertificatesPresented)
            }
            true => {
                trace!("Server certificate trusted");
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        trace!("Verifying TLS 1.2 client signature");
        verify_tls12_signature_with_spki(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        trace!("Verifying TLS 1.3 client signature");
        verify_tls13_signature_with_spki(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        trace!(
            "Supported schemes: {:?}",
            self.supported_algs.supported_schemes()
        );
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn main() -> Result<(), io::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .init();
    provider::default_provider()
        .install_default()
        .unwrap();

    let mut args = env::args();
    args.next(); // Skip the first argument which is the program name

    let role = args.next().unwrap_or_else(|| {
        eprintln!("Usage: <server|client|both> <cert.pem> <key.pem> <peer-key.pem> [client_cert.pem client_key.pem]");
        std::process::exit(1);
    });

    let server_spki_file = args
        .next()
        .unwrap_or_else(|| String::from(SERVER_PUB_KEY_FILE));
    let server_private_key_file = args
        .next()
        .unwrap_or_else(|| String::from(SERVER_PRIV_KEY_FILE));
    let client_spki_file = args
        .next()
        .unwrap_or_else(|| String::from(CLIENT_PUB_KEY_FILE));
    let client_private_key_file = args
        .next()
        .unwrap_or_else(|| String::from(CLIENT_PRIV_KEY_FILE));

    let server_spki_certs = load_rpk(&server_spki_file).unwrap();
    let server_private_key = load_private_key(&server_private_key_file).unwrap();
    let client_spki_certs = load_rpk(&client_spki_file).unwrap();
    let client_private_key = load_private_key(&client_private_key_file).unwrap();

    match role.as_str() {
        "server" => {
            let server_config = create_rpk_server_config(
                server_spki_certs,
                server_private_key,
                vec![client_spki_certs],
            );
            run_server(server_config)
        }
        "client" => {
            let client_config = create_rpk_client_config(
                client_spki_certs,
                client_private_key,
                vec![server_spki_certs],
            );
            run_client(client_config)
        }
        "both" => {
            let server_config = create_rpk_server_config(
                server_spki_certs.clone(),
                server_private_key,
                vec![client_spki_certs.clone()],
            );
            let client_config = create_rpk_client_config(
                client_spki_certs,
                client_private_key,
                vec![server_spki_certs],
            );

            // Start the server in a separate thread
            let server_thread = thread::spawn(move || {
                run_server(server_config).expect("Server failed");
            });

            // Give the server a moment to start
            thread::sleep(Duration::from_secs(1));

            // Start the client
            let client_thread = thread::spawn(move || {
                run_client(client_config).expect("Client failed");
            });

            // Wait for both threads to complete
            server_thread.join().unwrap();
            client_thread.join().unwrap();

            Ok(())
        }
        _ => {
            eprintln!("Invalid role: {}", role);
            Ok(())
        }
    }
}

const SERVER_PRIV_KEY_FILE: &str = "./test-ca/rsa-2048/end.key";
const SERVER_PUB_KEY_FILE: &str = "./test-ca/rsa-2048/end.spki.pem";
const CLIENT_PUB_KEY_FILE: &str = "./test-ca/rsa-2048/client.spki.pem";
const CLIENT_PRIV_KEY_FILE: &str = "./test-ca/rsa-2048/client.key";
