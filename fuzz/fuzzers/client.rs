#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;
extern crate webpki;

use rustls::{ClientConfig, ClientSession, Session};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(ClientConfig::new());
    let example_com = webpki::DNSNameRef::try_from_ascii_str("example.com").unwrap();
    let mut client = ClientSession::new(&config, example_com);
    let _ = client.read_tls(&mut io::Cursor::new(data));
});
