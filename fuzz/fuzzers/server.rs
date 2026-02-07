#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::server::{Accepted, Acceptor};
use rustls::{Connection, ServerConfig, ServerConnection};

fuzz_target!(|data: &[u8]| {
    let _ = env_logger::try_init();
    match data.split_first() {
        Some((0x00, rest)) => fuzz_buffered_api(rest),
        Some((0x01, rest)) => fuzz_acceptor_api(rest),
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

    service_connection(&mut stream, &mut server);
}

fn fuzz_acceptor_api(data: &[u8]) {
    let mut server = Acceptor::default();
    let mut stream = io::Cursor::new(data);

    loop {
        let rd = server
            .read_tls(&mut stream)
            .unwrap_or(0);

        match server.accept() {
            Ok(Some(accepted)) => {
                fuzz_accepted(&mut stream, accepted);
                break;
            }
            Err(_) => {
                break;
            }
            Ok(None) => {}
        }
        if rd == 0 {
            break;
        }
    }
}

fn fuzz_accepted(stream: &mut dyn io::Read, accepted: Accepted) {
    let mut maybe_server = accepted.into_connection(Arc::new(
        ServerConfig::builder(rustls_fuzzing_provider::PROVIDER.into())
            .with_no_client_auth()
            .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
            .unwrap(),
    ));

    if let Ok(conn) = &mut maybe_server {
        service_connection(stream, conn);
    }
}

fn service_connection(stream: &mut dyn io::Read, server: &mut ServerConnection) {
    loop {
        let rd = server.read_tls(stream);
        if server.process_new_packets().is_err() {
            break;
        }

        if matches!(rd, Ok(0) | Err(_)) {
            break;
        }

        // gather and discard written data
        let mut wr = vec![];
        server.write_tls(&mut &mut wr).unwrap();
    }
}
