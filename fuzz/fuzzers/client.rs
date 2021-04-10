#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;
extern crate webpki;

use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, DEFAULT_CIPHERSUITES};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let root_store = RootCertStore::empty();
    let config = Arc::new(ClientConfig::new(root_store, &[], DEFAULT_CIPHERSUITES));
    let example_com = webpki::DnsNameRef::try_from_ascii_str("example.com").unwrap();
    let mut client = ClientConnection::new(&config, example_com).unwrap();
    let _ = client.read_tls(&mut io::Cursor::new(data));
});
