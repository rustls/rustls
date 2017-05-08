#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::{ServerConfig, ServerSession, Session};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(ServerConfig::new());
    let mut server= ServerSession::new(&config);
    let _ = server.read_tls(&mut io::Cursor::new(data));
});
