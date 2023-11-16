#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
mod bogo_shim_impl;

fn main() {
    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    bogo_shim_impl::main();

    #[cfg(not(any(feature = "ring", feature = "aws_lc_rs")))]
    panic!("requires ring or aws_lc_rs feature");
}
