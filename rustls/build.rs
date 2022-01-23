/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// See the comment in lib.rs to understand why we need this.

#[rustversion::not(nightly)]
fn main() {}

#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=read_buf");
}
