/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// See the comment in lib.rs to understand why we need this.

#[cfg_attr(feature = "read_buf", rustversion::not(nightly))]
fn main() {
    println!("cargo:rustc-check-cfg=cfg(bench)");
    println!("cargo:rustc-check-cfg=cfg(read_buf)");
}

#[cfg(feature = "read_buf")]
#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-check-cfg=cfg(bench)");
    println!("cargo:rustc-check-cfg=cfg(read_buf)");
    println!("cargo:rustc-cfg=read_buf");
}
