/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// We cannot use `rustversion` to avoid this build script because
/// `rustversion` doesn't provide a mechanism for conditionally enabling
/// language features like `read_buf`.
///
/// TODO: When the `read_buf` language feature becomes stable in our MSRV, then
/// remove this.

fn main() {
    #[cfg(feature = "read_buf")]
    if let Ok(rustc_version::Channel::Nightly) = rustc_version::version_meta().map(|x| x.channel) {
        println!("cargo:rustc-cfg=read_buf");
    }
}
