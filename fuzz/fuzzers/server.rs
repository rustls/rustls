#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use std::io;
use std::sync::Arc;

use rustls::server::{Acceptor, ResolvesServerCert};
use rustls::{ServerConfig, ServerConnection};

fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((0x00, rest)) => fuzz_buffered_api(rest),
        Some((0x01, rest)) => fuzz_acceptor_api(rest),
        Some((_, _)) | None => {}
    }
});

fn fuzz_buffered_api(data: &[u8]) {
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fail)),
    );
    let mut stream = io::Cursor::new(data);
    let mut server = ServerConnection::new(config).unwrap();
    let _ = server.read_tls(&mut stream);
    let _ = server.process_new_packets();
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

#[derive(Debug)]
struct Fail;

impl ResolvesServerCert for Fail {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}
