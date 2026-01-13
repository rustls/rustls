/*! # Using rustls with FIPS-approved cryptography

To use FIPS-approved cryptography with rustls, you should use a FIPS-approved `CryptoProvider`.
The easiest way to do this is to use the the `rustls-aws-lc` crate with the `fips` feature enabled.

## 1. Enable the `fips` crate feature for rustls-aws-lc:

Use:

```toml
rustls = { version = "0.24" }
rustls-aws-lc-rs = { version = "0.1", features = ["fips"] }
```

## 2. Use the FIPS `CryptoProvider`

Instantiate your `ClientConfig` or `ServerConfig` using the FIPS `CryptoProvider`.

## 3. Validate the FIPS status of your `ClientConfig`/`ServerConfig` at run-time

See [`ClientConfig::fips()`] or [`ServerConfig::fips()`].

You could, for example:

```rust,ignore
# let client_config = unreachable!();
assert!(client_config.fips());
```

But maybe your application has an error handling or health-check strategy better than panicking.

# aws-lc-rs FIPS approval status

This is covered by [FIPS 140-3 certificate #4816][cert-4816].
See [the security policy][policy-4816] for precisely which
environments and functions this certificate covers.

Later releases of aws-lc-rs may be covered by later certificates,
or be pending certification.

For the most up-to-date details see the latest documentation
for the [`aws-lc-fips-sys`] crate.

[`aws-lc-fips-sys`]: https://crates.io/crates/aws-lc-fips-sys
[`CryptoProvider`]: crate::crypto::CryptoProvider
[`ClientConfig::fips()`]: crate::client::ClientConfig::fips
[`ServerConfig::fips()`]: crate::server::ServerConfig::fips
[cert-4816]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816
[policy-4816]: https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4816.pdf
*/
