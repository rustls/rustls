use bencher::{Bencher, benchmark_group, benchmark_main};
use rustls::VecBuffer;
use rustls_test::TestNonBlockIo;

fn bench_ewouldblock(c: &mut Bencher) {
    let mut buf = VecBuffer::default();
    c.iter(|| buf.read(&mut TestNonBlockIo::default()));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
