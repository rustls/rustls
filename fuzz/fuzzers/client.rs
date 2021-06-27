#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;
extern crate webpki;

use rustls::{
    client_config_builder_with_safe_defaults,
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
        client_config_builder_with_safe_defaults()
            .with_root_certificates(root_store, &[])
            .with_no_client_auth(),
    );
    let example_com = "example.com".try_into().unwrap();
    let mut client = ClientConnection::new(config, example_com).unwrap();
    let _ = client.read_tls(&mut io::Cursor::new(data));
});
