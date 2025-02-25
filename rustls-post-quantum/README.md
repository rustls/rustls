<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.
</p>

# rustls-post-quantum

The functionality of this crate became part of the core rustls
crate from the 0.23.22 release. When using that version of the crate,
use the `prefer-post-quantum` Cargo feature to control whether to prefer
using post-quantum algorithms instead of using this crate.

This crate is release under the same licenses as the [main rustls crate][rustls].

[rustls]: https://crates.io/crates/rustls
