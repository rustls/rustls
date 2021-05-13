#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;
extern crate webpki;

use rustls::{ConfigBuilder, ClientConnection, Connection, RootCertStore};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let root_store = RootCertStore::empty();
    let config = Arc::new(ConfigBuilder::with_safe_defaults()
        .for_client()
        .unwrap()
        .with_root_certificates(root_store, &[])
        .with_no_client_auth());
    let example_com = webpki::DnsNameRef::try_from_ascii_str("example.com").unwrap();
    let mut client = ClientConnection::new(config, example_com).unwrap();
    let _ = client.read_tls(&mut io::Cursor::new(data));
});
