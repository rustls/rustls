//! This crate is obsolete, as post-quantum key exchange support
//! was incorporated into the rustls crate in version 0.23.21.

pub use rustls::crypto::aws_lc_rs::default_provider as provider;
pub use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};
