use std::fs;
use std::io::Write;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ServerConfig, ServerConnection};

// These tests exercise rustls_fuzzing_provider and makes sure it can
// handshake with itself without errors.
//
// Transcripts are written into the fuzzing corpus.

#[test]
fn pairwise_tls12() {
    let transcript = test_version(rustls_fuzzing_provider::PROVIDER_TLS12);

    fs::write(
        "../fuzz/corpus/unbuffered/tls12-server.bin",
        [&[0u8], &transcript.server_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/unbuffered/tls12-client.bin",
        [&[1u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/server/buffered-tls12-client.bin",
        [&[0u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/server/accepter-tls12-client.bin",
        [&[1u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/client/tls12-server.bin",
        &transcript.server_wrote,
    )
    .unwrap();
}

#[test]
fn pairwise_tls13() {
    let transcript = test_version(rustls_fuzzing_provider::PROVIDER_TLS13);

    fs::write(
        "../fuzz/corpus/unbuffered/tls13-server.bin",
        [&[0u8], &transcript.server_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/unbuffered/tls13-client.bin",
        [&[1u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/server/buffered-tls13-client.bin",
        [&[0u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/server/accepter-tls13-client.bin",
        [&[1u8], &transcript.client_wrote[..]].concat(),
    )
    .unwrap();
    fs::write(
        "../fuzz/corpus/client/tls13-server.bin",
        &transcript.server_wrote,
    )
    .unwrap();
}

fn test_version(provider: CryptoProvider) -> Transcript {
    let _ = env_logger::try_init();

    let server_config = ServerConfig::builder(provider.clone().into())
        .with_no_client_auth()
        .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
        .unwrap();
    let mut server = ServerConnection::new(server_config.into()).unwrap();

    let client_config = Arc::new(
        ClientConfig::builder(provider.into())
            .dangerous()
            .with_custom_certificate_verifier(rustls_fuzzing_provider::server_verifier())
            .with_no_client_auth()
            .unwrap(),
    );
    let hostname = "localhost".try_into().unwrap();
    let mut client = client_config
        .connect(hostname)
        .build()
        .unwrap();
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
