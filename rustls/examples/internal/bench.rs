#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
mod bench_impl;

fn main() {
    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    bench_impl::main();

    #[cfg(not(any(feature = "ring", feature = "aws_lc_rs")))]
    panic!("no provider to test");
}
