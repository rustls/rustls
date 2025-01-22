//! This module provides tests for the interoperability of raw public keys with OpenSSL, and also
//! demonstrates how to set up a client-server architecture that utilizes raw public keys.
//!
//! The module also includes example implementations of the `ServerCertVerifier` and `ClientCertVerifier` traits, using
//! pre-configured raw public keys for the verification of the peer.

mod client {
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::AlwaysResolvesClientRawPublicKeys;
    use rustls::crypto::{
        aws_lc_rs as provider, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms,
    };
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
    };
    use rustls::sign::CertifiedKey;
    use rustls::version::TLS13;
    use rustls::{
        CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error,
        InconsistentKeys, PeerIncompatible, SignatureScheme, Stream,
    };

    /// Build a `ClientConfig` with the given client private key and a server public key to trust.
    pub(super) fn make_config(client_private_key: &str, server_pub_key: &str) -> ClientConfig {
        let client_private_key = Arc::new(provider::default_provider())
            .key_provider
            .load_private_key(
                PrivateKeyDer::from_pem_file(client_private_key)
                    .expect("cannot open private key file"),
            )
            .expect("cannot load signing key");
        let client_public_key = client_private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))
            .expect("cannot load public key");
        let client_public_key_as_cert = CertificateDer::from(client_public_key.to_vec());

        let server_raw_key = SubjectPublicKeyInfoDer::from_pem_file(server_pub_key)
            .expect("cannot open pub key file");

        let certified_key = Arc::new(CertifiedKey::new(
            vec![client_public_key_as_cert],
            client_private_key,
        ));

        ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SimpleRpkServerCertVerifier::new(vec![
                server_raw_key,
            ])))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                certified_key,
            )))
    }

    /// Run the client and connect to the server at the specified port.
    ///
    /// This client reads a message and then writes 'Hello from the client' to the server.
    pub(super) fn run_client(config: ClientConfig, port: u16) -> Result<String, io::Error> {
        let server_name = "0.0.0.0".try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect(format!("[::]:{}", port)).unwrap();
        let mut tls = Stream::new(&mut conn, &mut sock);

        let mut buf = vec![0; 128];
        let len = tls.read(&mut buf).unwrap();
        let received_message = String::from_utf8_lossy(&buf[..len]).to_string();

        let bytes_written = tls
            .write("Hello from the client".as_bytes())
            .unwrap_or("".len());
        assert!(bytes_written > 0);
        Ok(received_message)
    }

    /// Verifies the tls handshake signature of the server,
    /// and that the server's raw public key is in the list of trusted keys.
    ///
    /// Note: when the verifier is used for Raw Public Keys the `CertificateDer` argument to the functions contains the SPKI instead of a X509 Certificate
    #[derive(Debug)]
    struct SimpleRpkServerCertVerifier {
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        supported_algs: WebPkiSupportedAlgorithms,
    }

    impl SimpleRpkServerCertVerifier {
        fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
            SimpleRpkServerCertVerifier {
                trusted_spki,
                supported_algs: Arc::new(provider::default_provider())
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
                false => Err(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
                true => Ok(ServerCertVerified::assertion()),
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::PeerIncompatible(
                PeerIncompatible::Tls12NotOffered,
            ))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.supported_algs,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_algs.supported_schemes()
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
}

mod server {
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{
        aws_lc_rs as provider, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms,
    };
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::server::AlwaysResolvesServerRawPublicKeys;
    use rustls::sign::CertifiedKey;
    use rustls::version::TLS13;
    use rustls::{
        CertificateError, DigitallySignedStruct, DistinguishedName, Error, InconsistentKeys,
        PeerIncompatible, ServerConfig, ServerConnection, SignatureScheme,
    };

    /// Build a `ServerConfig` with the given server private key and a client public key to trust.
    pub(super) fn make_config(server_private_key: &str, client_pub_key: &str) -> ServerConfig {
        let client_raw_key = SubjectPublicKeyInfoDer::from_pem_file(client_pub_key)
            .expect("cannot open pub key file");

        let server_private_key = provider::default_provider()
            .key_provider
            .load_private_key(
                PrivateKeyDer::from_pem_file(server_private_key)
                    .expect("cannot open private key file"),
            )
            .expect("cannot load signing key");
        let server_public_key = server_private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))
            .expect("cannot load public key");
        let server_public_key_as_cert = CertificateDer::from(server_public_key.to_vec());

        let certified_key = Arc::new(CertifiedKey::new(
            vec![server_public_key_as_cert],
            server_private_key,
        ));

        let client_cert_verifier = Arc::new(SimpleRpkClientCertVerifier::new(vec![client_raw_key]));
        let server_cert_resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));

        ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_cert_resolver(server_cert_resolver)
    }

    /// Run the server at the specified port and accept a connection from the client.
    ///
    /// After the handshake is complete, the server writes 'Hello from the server' to the client.
    /// The server then waits until reads it receives a message from the client and closes the connection.
    pub(super) fn run_server(
        config: ServerConfig,
        listener: TcpListener,
    ) -> Result<String, io::Error> {
        let (mut stream, _) = listener.accept()?;

        let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
        conn.complete_io(&mut stream)?;

        conn.writer()
            .write_all(b"Hello from the server")?;
        conn.complete_io(&mut stream)?;

        let mut buf = [0; 128];

        loop {
            match conn.reader().read(&mut buf) {
                Ok(len) => {
                    conn.send_close_notify();
                    conn.complete_io(&mut stream)?;
                    return Ok(String::from_utf8_lossy(&buf[..len]).to_string());
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    conn.read_tls(&mut stream)?;
                    conn.process_new_packets().unwrap();
                }
                Err(err) => {
                    return Err(err);
                }
            };
        }
    }

    /// Verifies the tls handshake signature of the client,
    /// and that the client's raw public key is in the list of trusted keys.
    ///
    /// Note: when the verifier is used for Raw Public Keys the `CertificateDer` argument to the functions contains the SPKI instead of a X509 Certificate
    #[derive(Debug)]
    struct SimpleRpkClientCertVerifier {
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        supported_algs: WebPkiSupportedAlgorithms,
    }

    impl SimpleRpkClientCertVerifier {
        pub fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
            Self {
                trusted_spki,
                supported_algs: Arc::new(provider::default_provider())
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
                false => Err(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
                true => Ok(ClientCertVerified::assertion()),
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::PeerIncompatible(
                PeerIncompatible::Tls12NotOffered,
            ))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.supported_algs,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_algs.supported_schemes()
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
}

mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::process::{Command, Stdio};
    use std::sync::mpsc::channel;
    use std::thread;

    use super::{client, server};
    use crate::utils::verify_openssl3_available;

    const SERVER_PRIV_KEY_FILE: &str = "../test-ca/ecdsa-p256/end.key";
    const SERVER_PUB_KEY_FILE: &str = "../test-ca/ecdsa-p256/end.spki.pem";
    const SERVER_CERT_KEY_FILE: &str = "../test-ca/ecdsa-p256/end.cert";
    const CLIENT_PUB_KEY_FILE: &str = "../test-ca/ecdsa-p256/client.spki.pem";
    const CLIENT_PRIV_KEY_FILE: &str = "../test-ca/ecdsa-p256/client.key";
    const CLIENT_CERT_KEY_FILE: &str = "../test-ca/ecdsa-p256/client.cert";

    fn tcp_listener() -> TcpListener {
        TcpListener::bind("[::]:0").expect("Could not bind to random port")
    }

    #[test]
    fn test_rust_server_and_rust_client() {
        let listener = tcp_listener();
        let port = listener.local_addr().unwrap().port();

        let (sender, receiver) = channel();
        let server_thread = thread::spawn(move || {
            sender
                .send(server::run_server(
                    server::make_config(SERVER_PRIV_KEY_FILE, CLIENT_PUB_KEY_FILE),
                    listener,
                ))
                .unwrap();
        });

        // Start the Rust client
        let client_config = client::make_config(CLIENT_PRIV_KEY_FILE, SERVER_PUB_KEY_FILE);
        match client::run_client(client_config, port) {
            Ok(server_message) => {
                assert_eq!(server_message, "Hello from the server");
            }
            Err(e) => {
                panic!("Client failed to communicate with the server: {:?}", e);
            }
        }

        // Wait for the server to finish and clean up the thread
        let server_result = receiver.recv().unwrap();
        server_thread
            .join()
            .expect("Failed to join server thread");

        match server_result {
            Ok(client_message) => {
                assert_eq!(client_message, "Hello from the client");
            }
            Err(e) => {
                panic!("Server failed to communicate with the client: {:?}", e);
            }
        }
    }

    #[test]
    fn test_rust_server_with_openssl_client() {
        verify_openssl3_available();

        let listener = tcp_listener();
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            server::run_server(
                server::make_config(SERVER_PRIV_KEY_FILE, CLIENT_PUB_KEY_FILE),
                listener,
            )
            .expect("failed to run server to completion")
        });

        // Start the OpenSSL client
        let mut openssl_client = Command::new("openssl")
            .arg("s_client")
            .arg("-connect")
            .arg(format!("[::]:{:?}", port))
            .arg("-enable_server_rpk")
            .arg("-enable_client_rpk")
            .arg("-key")
            .arg(CLIENT_PRIV_KEY_FILE)
            .arg("-cert")
            .arg(CLIENT_CERT_KEY_FILE)
            .arg("-tls1_3")
            .arg("-debug")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to execute OpenSSL client");

        let mut stdin = openssl_client.stdin.take().unwrap();
        let mut stdout = openssl_client.stdout.take().unwrap();
        let mut stdout_buf = [0; 1024];
        let mut openssl_stdout = String::new();
        let mut received_server_msg = false;
        loop {
            match stdout.read(&mut stdout_buf) {
                Ok(0) => break,
                Ok(len) => {
                    let read = &stdout_buf[..len];

                    std::io::stdout()
                        .write_all(read)
                        .unwrap();
                    openssl_stdout.push_str(&String::from_utf8_lossy(read));
                    if openssl_stdout.contains("Hello from the server") {
                        received_server_msg = true;
                        stdin
                            .write_all(b"Hello, from openssl client!")
                            .expect("Failed to write to stdin");
                        break;
                    }
                }
                Err(e) => panic!("Error reading from OpenSSL stdin: {e:?}"),
            }
        }

        assert!(received_server_msg);
        assert_eq!(server_thread.join().unwrap(), "Hello, from openssl client!");
        openssl_client.wait().unwrap();
    }

    #[test]
    fn test_rust_client_with_openssl_server() {
        verify_openssl3_available();

        let listener = tcp_listener();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // Start OpenSSL server
        let mut server_process = Command::new("openssl")
            .arg("s_server")
            .arg("-port")
            .arg(port.to_string())
            .arg("-cert")
            .arg(SERVER_CERT_KEY_FILE)
            .arg("-key")
            .arg(SERVER_PRIV_KEY_FILE)
            .arg("-verify")
            .arg("1")
            .arg("-enable_server_rpk")
            .arg("-enable_client_rpk")
            .arg("-tls1_3")
            .arg("-debug")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .expect("Failed to start OpenSSL server");

        // Read from the OpenSSL server's stdout and wait for "ACCEPT"
        if let Some(stdout) = server_process.stdout.take() {
            let stdout_reader = BufReader::new(stdout);
            for line in stdout_reader.lines() {
                match line {
                    Ok(l) => {
                        if l.contains("ACCEPT") {
                            break;
                        }
                    }
                    Err(e) => {
                        panic!("Error reading from OpenSSL stdout: {:?}", e);
                    }
                }
            }
        }

        // Write a message to the OpenSSL server's stdin
        if let Some(mut stdin) = server_process.stdin.take() {
            stdin
                .write_all(b"Hello, from openssl server!")
                .expect("Failed to write to stdin");
        }

        // Create the Rust client config and run the client
        let client_config = client::make_config(CLIENT_PRIV_KEY_FILE, SERVER_PUB_KEY_FILE);
        match client::run_client(client_config, port) {
            Ok(server_message) => {
                assert_eq!(server_message, "Hello, from openssl server!");
            }
            Err(_) => {
                unreachable!("Client failed to communicate with the server");
            }
        }

        // Ensure the OpenSSL server process is terminated
        server_process
            .kill()
            .expect("Failed to kill OpenSSL server process");
        server_process
            .wait()
            .expect("Failed to wait on OpenSSL server process");
    }
}
