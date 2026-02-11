use std::sync::Arc;

use bencher::{Bencher, benchmark_group, benchmark_main};
use rustls::{Connection, ServerConnection, TlsInputBuffer};
use rustls_test::{KeyType, TestNonBlockIo, make_server_config};

fn bench_ewouldblock(c: &mut Bencher) {
    let server_config = make_server_config(KeyType::Rsa2048, &rustls_ring::DEFAULT_PROVIDER);
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut buf = TlsInputBuffer::default();
    c.iter(|| buf.read(&mut TestNonBlockIo::default(), server.is_handshaking()));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
