# `no-std-libc-demo`

rustls demo applications that does not depend on libstd but instead uses direct FFI bindings to use OS resources like sockets (AKA a libc API).

This demo uses a custom compilation target as an OS-agnostic version of `x86_64-unknown-linux-gnu` [^1] and due to that a nightly toolchain is required to build the demo.

The OS bindings have been written to run this demo on Linux.
Other OSes have not been tested and may require modification to the bindings in `packages/ministd/src/libc.rs`

As a way to check the FFI bindings, one can run the examples in the `ministd` packages -- there no regular `#[test]`s because the `test` crate is not available in no-std context.

[^1]: using the built-in `x86_64-unknown-none` target was also attempted but that target has many instruction sets disabled in its codegen settings which makes it impossible to use with cryptography crates like `curve25519-dalek` and `poly1305` (see [dalek-cryptography/curve25519-dalek#601], [RustCrypto/universal-hashes#189] and [rust-lang/rust#117938]),

[dalek-cryptography/curve25519-dalek#601]: https://github.com/dalek-cryptography/curve25519-dalek/issues/601
[RustCrypto/universal-hashes#189]: https://github.com/RustCrypto/universal-hashes/issues/189
[rust-lang/rust#117938]: https://github.com/rust-lang/rust/issues/117938
