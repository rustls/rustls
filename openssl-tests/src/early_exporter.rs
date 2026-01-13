use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::{str, thread};

use openssl::ssl::{SslConnector, SslMethod, SslSession, SslStream};
use rustls::ServerConfig;
use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_aws_lc_rs as provider;

use crate::utils::verify_openssl3_available;

#[test]
fn test_early_exporter() {
    verify_openssl3_available();

    // full handshake + one resumption
    const ITERS: usize = 2;

    let listener = TcpListener::bind(("localhost", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_thread = thread::spawn(move || {
        let mut config = ServerConfig::builder(provider::DEFAULT_PROVIDER.into())
            .with_no_client_auth()
            .with_single_cert(
                Arc::new(Identity::from_cert_chain(load_certs()).unwrap()),
                load_private_key(),
            )
            .unwrap();
        config.max_early_data_size = 8192;
        let config = Arc::new(config);

        for _ in 0..ITERS {
            let mut server = rustls::ServerConnection::new(config.clone()).unwrap();
            let (mut tcp_stream, _addr) = listener.accept().unwrap();

            // read clienthello and then inspect early_data status
            server
                .read_tls(&mut tcp_stream)
                .unwrap();
            server.process_new_packets().unwrap();

            let message = if let Some(mut early) = server.early_data() {
                let secret = early
                    .exporter()
                    .unwrap()
                    .derive(b"label", Some(b"context"), [0u8; 64])
                    .unwrap();

                let mut buf = b"early data: ".to_vec();
                early.read_to_end(&mut buf).unwrap();
                buf.push(b'\n');

                buf.extend_from_slice(b"exported: ");
                buf.extend_from_slice(format!("{:02x?}", secret).as_bytes());
                buf.push(b'\n');
                buf
            } else {
                b"no early data\n".to_vec()
            };

            server
                .writer()
                .write_all(&message)
                .unwrap();

            server
                .complete_io(&mut tcp_stream)
                .unwrap();

            tcp_stream.flush().unwrap();
        }
    });

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .set_ca_file(CA_PEM_FILE)
        .unwrap();

    let connector = connector.build();

    let mut session: Option<SslSession> = None;
    let mut saw_early_data_at_least_once = false;

    for _iter in 0..ITERS {
        let stream = TcpStream::connect(("localhost", port)).unwrap();

        let mut config = connector.configure().unwrap();
        config.set_connect_state();

        if let Some(sess) = &session {
            unsafe { config.set_session(sess).unwrap() };
        }

        let mut stream = SslStream::new(
            config
                .into_ssl("testserver.com")
                .unwrap(),
            stream,
        )
        .unwrap();
        let _ = stream.write_early_data(b"early hello");

        stream.connect().unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        let message = String::from_utf8(buf).unwrap();

        let mut secret = [0u8; 64];
        let expected_message = match stream
            .ssl()
            .export_keying_material_early(&mut secret, "label", b"context")
        {
            Ok(_) => {
                saw_early_data_at_least_once = true;
                format!("early data: early hello\nexported: {:02x?}\n", secret)
            }
            Err(_) => "no early data\n".to_string(),
        };

        assert_eq!(expected_message, message);

        let _ = stream.shutdown();

        session = stream
            .ssl()
            .session()
            .map(|sess| sess.to_owned());
    }

    assert!(saw_early_data_at_least_once);
    server_thread.join().unwrap();
}

fn load_certs() -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(CERT_CHAIN_FILE)
        .unwrap()
        .map(|c| c.unwrap())
        .collect()
}

fn load_private_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(PRIV_KEY_FILE).unwrap()
}

const CERT_CHAIN_FILE: &str = "../test-ca/rsa-2048/end.fullchain";
const PRIV_KEY_FILE: &str = "../test-ca/rsa-2048/end.key";
const CA_PEM_FILE: &str = "../test-ca/rsa-2048/ca.cert";
