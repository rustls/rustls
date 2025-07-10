<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.
</p>

# rustls-post-quantum

This crate provide a `CryptoProvider` built on the default aws-lc-rs default provider.

Features:

- `aws-lc-rs-unstable`: adds support for three variants of the experimental ML-DSA signature
  algorithm.

Before rustls 0.23.22, this crate additionally provided support for the ML-KEM key exchange
(both "pure" and hybrid variants), but these have been moved to the rustls crate itself.
In rustls 0.23.22 and later, you can use rustls' `prefer-post-quantum` feature to determine
whether the ML-KEM key exchange is preferred over non-post-quantum key exchanges.

This crate is release under the same licenses as the [main rustls crate][rustls].

[rustls]: https://crates.io/crates/rustls
