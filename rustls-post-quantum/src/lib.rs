//! The functionality of this crate became part of the core rustls
//! crate from the 0.23.22 release. When using that version of the crate,
//! use the `prefer-post-quantum` Cargo feature to control whether to prefer
//! using post-quantum algorithms instead of using this crate.

pub use rustls::crypto::aws_lc_rs::default_provider as provider;
pub use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, MLKEM1024, X25519MLKEM768};
