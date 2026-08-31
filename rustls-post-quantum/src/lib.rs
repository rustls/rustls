//! This crate provides a [`CryptoProvider`] built on the default aws-lc-rs provider,
//! with added support for three variants of the ML-DSA signature algorithm.
//!
//! Before rustls 0.23.22, this crate additionally provided support for the ML-KEM key exchange
//! (both "pure" and hybrid variants), but these have been moved to the rustls crate itself.
//! In rustls 0.23.22 and later, you can use rustls' `prefer-post-quantum` feature to determine
//! whether the ML-KEM key exchange is preferred over non-post-quantum key exchanges.

use rustls::crypto::CryptoProvider;

/// The default `CryptoProvider` backed by aws-lc-rs.
pub const DEFAULT_PROVIDER: CryptoProvider = rustls_aws_lc_rs::DEFAULT_PROVIDER;
