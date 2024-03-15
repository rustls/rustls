#![cfg(feature = "ring")]

use bencher::{benchmark_group, benchmark_main, Bencher};
use rustls::crypto::ring as provider;

#[path = "../tests/common/mod.rs"]
mod test_utils;
use std::io;
use std::sync::Arc;

use rustls::ServerConnection;
use test_utils::*;

fn bench_ewouldblock(c: &mut Bencher) {
    let server_config = make_server_config(KeyType::Rsa2048);
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut read_ewouldblock = FailsReads::new(io::ErrorKind::WouldBlock);
    c.iter(|| server.read_tls(&mut read_ewouldblock));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
