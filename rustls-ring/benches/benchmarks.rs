use std::sync::Arc;

use bencher::{Bencher, benchmark_group, benchmark_main};
use rustls::{Connection, ServerConnection};
use rustls_test::{KeyType, TestNonBlockIo, make_server_config};

fn bench_ewouldblock(c: &mut Bencher) {
    let server_config = make_server_config(KeyType::Rsa2048, &rustls_ring::DEFAULT_PROVIDER);
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    c.iter(|| server.read_tls(&mut TestNonBlockIo::default()));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
