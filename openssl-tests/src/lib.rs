#![cfg(test)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::manual_let_else,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    elided_lifetimes_in_paths,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

mod early_exporter;
mod ffdhe;
mod ffdhe_kx_with_openssl;
mod raw_key_openssl_interop;
mod utils;
mod validate_ffdhe_params;
