# RFC001: Alternative crypto backends

Issue: rustls/rustls#521

## Why

There are a bunch of reasons someone might want use crypto implementations
other than those from *ring*.  The issue contains a thorough discussion,
but to summarise:

- runtime platform support: especially platforms like wasm who have their own
  cryptography APIs.
- CPU architecture support: we should have a support route for all architectures
  that rustc can target.
- upstream packaging requirements: RHEL has a hard policy that all cryptography
  must come from a limited set of packages.
- hardware support: including HSMs and cryptographic acceleration IP on microcontrollers.
- assorted "pure rust TLS stack" reasons: including build system, memory safety, portability, etc.

## Study

First, let's look at where we use crypto and for what.  This includes
uses which _already support_ alternative crypto backends via existing
extension points.

| Purpose | Current status | Example algorithm | Example code location |
| --- | --- | --- | --- |
| Random material generation | Statically uses *ring* | System-provided RNG | `src/rand.rs` |
| Bulk encryption/decryption | Statically uses *ring* | AES-128-GCM | `src/cipher.rs` |
| Certificate and signature verification | Pluggable extension point, behind `dangerous_configuration`. Default uses webpki which statically uses *ring*. | ECDSA-P256 | `src/verify.rs` |
| Authentication key loading and signature generation | Pluggable extension point.  Default uses *ring*. | ECDSA-P256 | `src/sign.rs` |
| Key exchange | Statically uses *ring* | X25519 | `src/kx.rs` |
| TLS1.2 PRF | Statically uses *ring* | HMAC-SHA256 | `src/tls12/kdf.rs` |
| TLS1.3 key schedule | Statically uses *ring* | HKDF-HMAC-SHA256 | `src/tls13/key_schedule.rs` |
| Server ticket production | Pluggable extension point. Default does not support ticket generation. Provided optional implementation uses *ring*. | CHACHA20-POLY1305 | `src/ticketer.rs` |

For the items here that statically depend on *ring*, how do we determine what
individual algorithm to use?

- Random material generation: currently fixed.
- Bulk encryption/decryption: from cipher suite (`SupportedCipherSuite`)
- Key exchange: from key exchange group (`SupportedKxGroup`)
- TLS1.2 PRF: from cipher suite (`SupportedCipherSuite::Tls12`)
- TLS1.3 key schedule: from cipher suite (`SupportedCipherSuite::Tls13`)

The principal observation here is: the same mechanism which means that AES does not appear
present in an application binary which only mentioned `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
should be the same one that lets an application avoid a *ring* dependency.

This gives us five remaining issues to deal with:

### Random generation

This is needed early on, so we cannot hook it to anything else (like the cipher suite, say, but
that would be odd anyway.)

We should make this configurable in the `ServerConfig`/`ClientConfig` types.

### Bulk encryption/decryption

We have suitable traits for this already, rooted in `SupportedCipherSuite::Tls12`.
The same would need doing for `SupportedCipherSuite::Tls13`.

### Key exchange
`SupportedKxGroup` should contain a functor which returns a trait implementation that
replaces the *ring*-oriented functions in the `KeyExchange` struct.

### TLS1.2 PRF and TLS1.3 key schedule
We should define a trait for incremental HMAC computation.

In `SupportedCipherSuite` we should have a function that returns an implementation of that trait.

This can be used by the TLS1.2 PRF and TLS1.3 key schedule.  The latter should wrap HMAC to maintain
type safety of the HKDF uses.

# Proposal

## Crate organisation

1. Move most of the crate to a `rustls-core` crate.  This should not depend on webpki, *ring* or sct.
   But, alone, it is not useful: it does not contain any `SupportedCipherSuite`s, `SupportedKxGroup`s, etc.
   However, it does contain all the traits and types for implementing these.
2. `rustls` reexports most of the public parts of `rustls-core`, plus provides the default
   `SupportedCipherSuite`s, `SupportedKxGroup`s, webpki-backed certificate verifier, loading and using
   signing keys, early steps of config builders (as these know the default cipher suites), etc.

   Most importantly: everything that `rustls` does can equally be done by a downstream crate against
   different dependencies.
3. To prove any of this works, we should likely demonstrate that with at least one other crate,
   say `rustls-openssl` or `rustls-rustcrypto`, and naturally these should not take a dependency
   on webpki, *ring*, or sct.  Clearly, we should expect these to have different application-visible
   behaviours and APIs for configuring root certificates, loading signing keys, etc.

## APIs

1. Make `SupportedCipherSuite` generic to *ring* in `rustls-core` and make it public.
2. Make `SupportedKxGroup` generic to *ring* in `rustls-core` and make it public.
3. (lots more than this... TODO)


