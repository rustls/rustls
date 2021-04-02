#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::{ServerConfig, ServerConnection, Connection, NoClientAuth};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(ServerConfig::new(NoClientAuth::new()));
    let mut server= ServerConnection::new(&config);
    let _ = server.read_tls(&mut io::Cursor::new(data));
});
