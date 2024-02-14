/*! # Using rustls with FIPS-approved cryptography

To use FIPS-approved cryptography with rustls, you should take
these actions:

## 1. Enable the `fips` crate feature for rustls.

Use:

```toml
rustls = { version = "0.23", features = [ "fips" ] }
```

## 2. Use the FIPS `CryptoProvider`

This is [`default_fips_provider()`]:

```rust,ignore
rustls::crypto::default_fips_provider()
    .install_default()
    .expect("default provider already set elsewhere");
```

This snippet makes use of the process-default provider,
and that assumes all your uses of rustls use that.
See [`CryptoProvider`] documentation for other ways to
specify which `CryptoProvider` to use.

## 3. Validate the FIPS status of your `ClientConfig`/`ServerConfig` at run-time

See [`ClientConfig::fips()`] or [`ServerConfig::fips()`].

You could, for example:

```rust,ignore
# let client_config = unreachable!();
assert!(client_config.fips());
```

But maybe your application has an error handling
or health-check strategy better than panicking.

# aws-lc-rs FIPS approval status

At the time of writing, this is pending approval on Linux
for two architectures (ARM aarch64 and Intel x86-64).

For the most up-to-date details see the latest documentation
for the [`aws-lc-fips-sys`] crate.

[`aws-lc-fips-sys`]: https://crates.io/crates/aws-lc-fips-sys
[`default_fips_provider()`]: crate::crypto::default_fips_provider
[`CryptoProvider`]: crate::crypto::CryptoProvider
[`ClientConfig::fips()`]: crate::client::ClientConfig::fips
[`ServerConfig::fips()`]: crate::server::ServerConfig::fips
*/
