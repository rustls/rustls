# Third-party Cryptography Providers

In addition to the providers listed [in the README][README] there are a number
of third-party cryptography providers available for Rustls.

[README]: https://github.com/rustls/rustls#cryptography-providers

These projects have not been evaluated by the Rustls maintainers, and no claim
is made to their production worthiness or overall quality.

| Repository | Description |
| -- | -- |
| [`rustls-graviola`] | a provider that uses [`graviola`] for cryptography. |
| [`rustls-symcrypt`] | a provider that uses Microsoft's [SymCrypt] library. |
| [`rustls-openssl`] | a provider that uses [OpenSSL] for cryptography. |
| [`boring-rustls-provider`] | a work-in-progress provider that uses [`boringssl`] for cryptography. |
| [`rustls-ccm`] | adds AES-CCM cipher suites (TLS 1.2 and 1.3) using [`RustCrypto`], for IoT/constrained-device protocols (IEEE 2030.5, Matter, RFC 7925). |
| [`rustls-mbedtls-provider`] | a provider that uses [`mbedtls`] for cryptography. |
| [`rustls-pure`] | a pure-Rust provider (no C or assembly) using [`RustCrypto`] primitives: TLS 1.3 only, ECDSA and Ed25519 certificates, tested against Wycheproof vectors. |
| [`rustls-rustcrypto`] | an experimental provider that uses the crypto primitives from [`RustCrypto`] for cryptography. |
| [`rustls-wolfcrypt-provider`] | a work-in-progress provider that uses [`wolfCrypt`] for cryptography. |

[`rustls-graviola`]: https://crates.io/crates/rustls-graviola
[`graviola`]: https://github.com/ctz/graviola
[`rustls-symcrypt`]: https://github.com/microsoft/rustls-symcrypt
[SymCrypt]: https://github.com/microsoft/SymCrypt
[`rustls-openssl`]: https://github.com/tofay/rustls-openssl
[OpenSSL]: https://openssl-library.org/
[`rustls-ccm`]: https://github.com/jsulmont/rustls-ccm
[`rustls-mbedtls-provider`]: https://github.com/fortanix/rustls-mbedtls-provider
[`mbedtls`]: https://github.com/Mbed-TLS/mbedtls
[`boring-rustls-provider`]: https://github.com/janrueth/boring-rustls-provider
[`boringssl`]: https://github.com/google/boringssl
[`rustls-pure`]: https://crates.io/crates/rustls-pure
[`rustls-rustcrypto`]: https://github.com/RustCrypto/rustls-rustcrypto
[`RustCrypto`]: https://github.com/RustCrypto
[`rustls-wolfcrypt-provider`]: https://github.com/wolfSSL/rustls-wolfcrypt-provider
[`wolfCrypt`]: https://www.wolfssl.com/products/wolfcrypt

See the [Making a custom CryptoProvider] section of the documentation for more information
on this topic.

[Making a custom CryptoProvider]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#making-a-custom-cryptoprovider

