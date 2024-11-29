#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, RootCertStore};

fuzz_target!(|data: &[u8]| {
    let root_store = RootCertStore::empty();
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let example_com = "example.com".try_into().unwrap();
    let mut client = ClientConnection::new(config, example_com).unwrap();
    let mut stream = io::Cursor::new(data);

    loop {
        let rd = client.read_tls(&mut stream).unwrap();
        if client.process_new_packets().is_err() {
            break;
        }
        if rd == 0 {
            break;
        }
    }
});
