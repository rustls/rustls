#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};

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
        ServerConfig::builder_with_provider(rustls_fuzzing_provider::provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(rustls_fuzzing_provider::server_cert_resolver()),
    );
    let mut stream = io::Cursor::new(data);
    let mut server = ServerConnection::new(config).unwrap();

    loop {
        let rd = server.read_tls(&mut stream);
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

fn fuzz_acceptor_api(data: &[u8]) {
    let mut server = Acceptor::default();
    let mut stream = io::Cursor::new(data);

    loop {
        let rd = server.read_tls(&mut stream).unwrap();
        match server.accept() {
            Ok(Some(_)) | Err(_) => {
                break;
            }
            Ok(None) => {}
        }
        if rd == 0 {
            break;
        }
    }
}
