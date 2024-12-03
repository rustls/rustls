use std::io::Write;

use rustls::version::{TLS12, TLS13};
use rustls::{
    ClientConfig, ClientConnection, ServerConfig, ServerConnection, SupportedProtocolVersion,
};

// These tests exercise rustls_fuzzing_provider and makes sure it can
// handshake with itself without errors.

#[test]
fn pairwise_tls12() {
    test_version(&TLS12);
}

#[test]
fn pairwise_tls13() {
    test_version(&TLS13);
}

fn test_version(version: &'static SupportedProtocolVersion) -> Transcript {
    let _ = env_logger::try_init();

    let server_config =
        ServerConfig::builder_with_provider(rustls_fuzzing_provider::provider().into())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(rustls_fuzzing_provider::server_cert_resolver());
    let mut server = ServerConnection::new(server_config.into()).unwrap();

    let client_config =
        ClientConfig::builder_with_provider(rustls_fuzzing_provider::provider().into())
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(rustls_fuzzing_provider::server_verifier())
            .with_no_client_auth();
    let hostname = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(client_config.into(), hostname).unwrap();
    server
        .writer()
        .write_all(b"hello from server")
        .unwrap();
    client
        .writer()
        .write_all(b"hello from client")
        .unwrap();

    let mut transcript = Transcript::default();

    while client.is_handshaking() || server.is_handshaking() {
        let mut buffer = vec![];
        client
            .write_tls(&mut &mut buffer)
            .unwrap();
        transcript
            .client_wrote
            .extend_from_slice(&buffer);
        server
            .read_tls(&mut &buffer[..])
            .unwrap();
        server.process_new_packets().unwrap();

        let mut buffer = vec![];
        server
            .write_tls(&mut &mut buffer)
            .unwrap();
        transcript
            .server_wrote
            .extend_from_slice(&buffer);
        client
            .read_tls(&mut &buffer[..])
            .unwrap();
        client.process_new_packets().unwrap();
    }

    transcript
}

#[derive(Default)]
struct Transcript {
    client_wrote: Vec<u8>,
    server_wrote: Vec<u8>,
}
