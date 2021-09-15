#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;
extern crate webpki;

use rustls::{
    ClientConfig,
    ClientConnection,
    Connection,
    RootCertStore
};
use std::convert::TryInto;
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let root_store = RootCertStore::empty();
    let config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .without_certificate_transparency_logs()
            .with_no_client_auth(),
    );
    let example_com = "example.com".try_into().unwrap();
    let mut client = ClientConnection::new(config, example_com).unwrap();
    let _ = client.read_tls(&mut io::Cursor::new(data));
});
