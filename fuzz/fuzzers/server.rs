#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::server::{Accepted, ServerHandshake};
use rustls::{Connection, Error, ServerConfig, ServerConnection, VecInput};

fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((0x00, rest)) => fuzz_buffered_api(rest),
        Some((0x01, rest)) => fuzz_handshake_api(rest),
        Some((_, _)) | None => {}
    }
});

fn fuzz_buffered_api(data: &[u8]) {
    let config = Arc::new(
        ServerConfig::builder(rustls_fuzzing_provider::PROVIDER.into())
            .with_no_client_auth()
            .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
            .unwrap(),
    );
    let mut stream = io::Cursor::new(data);
    let mut server = ServerConnection::new(config).unwrap();

    service_connection(&mut stream, &mut VecInput::default(), &mut server);
}

fn fuzz_handshake_api(data: &[u8]) {
    let mut server = ServerHandshake::start();
    let mut stream = io::Cursor::new(data);
    let mut input = VecInput::default();
    let mut output = vec![];

    loop {
        let rd = input.read(&mut stream).unwrap_or(0);

        let next = match server.process(&mut input, &mut output) {
            Ok(ServerHandshake::Accepted(accepted)) => choose_config(accepted, &mut output),
            other => other,
        };

        server = match next {
            Ok(ServerHandshake::NeedsInput(next)) => next,
            // the handshake completed, failed, or reached a state this
            // configuration cannot produce: nothing more to feed it.
            Ok(_) | Err(_) => break,
        };

        if rd == 0 {
            break;
        }
    }
}

fn choose_config(accepted: Accepted, output: &mut Vec<u8>) -> Result<ServerHandshake, Error> {
    accepted.choose_config(
        Arc::new(
            ServerConfig::builder(rustls_fuzzing_provider::PROVIDER.into())
                .with_no_client_auth()
                .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
                .unwrap(),
        ),
        output,
    )
}

fn service_connection(
    stream: &mut dyn io::Read,
    input: &mut VecInput,
    server: &mut ServerConnection,
) {
    loop {
        let rd = input.read(stream);
        if server
            .process_new_packets(input, &mut Vec::new())
            .handle_all(&mut Vec::new())
            .is_err()
        {
            break;
        }

        if matches!(rd, Ok(0) | Err(_)) {
            break;
        }
    }
}
