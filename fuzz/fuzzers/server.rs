#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::{ServerConfigBuilder, ServerConnection, Connection, ResolvesServerCert};
use std::io;
use std::sync::Arc;

struct Fail;

impl ResolvesServerCert for Fail {
    fn resolve(&self, _client_hello: rustls::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(ServerConfigBuilder::with_safe_default_crypto()
                          .with_no_client_auth()
                          .with_cert_resolver(Arc::new(Fail)));
    let mut server= ServerConnection::new(&config);
    let _ = server.read_tls(&mut io::Cursor::new(data));
});
