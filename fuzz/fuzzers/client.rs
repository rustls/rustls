#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection};

fuzz_target!(|data: &[u8]| {
    let _ = env_logger::try_init();
    let config = Arc::new(
        ClientConfig::builder_with_provider(rustls_fuzzing_provider::provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(rustls_fuzzing_provider::server_verifier())
            .with_no_client_auth(),
    );
    let hostname = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(config, hostname).unwrap();

    let mut stream = io::Cursor::new(data);
    loop {
        let rd = client.read_tls(&mut stream);
        if client.process_new_packets().is_err() {
            break;
        }

        if matches!(rd, Ok(0) | Err(_)) {
            break;
        }

        // gather and discard written data
        let mut wr = vec![];
        client.write_tls(&mut &mut wr).unwrap();
    }
});
