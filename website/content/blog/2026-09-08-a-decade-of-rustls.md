+++
title = "A Decade of Rustls"
date = 2026-09-08
authors = ["Joe Birr-Pixton"]

[taxonomies]
tags = ["blog"]
+++

This year marks ten years of Rustls. In this post, we reflect on a decade of the project: where it started, how it has grown, and where it's heading next. This post is based on our presentation at RustConf 2026.

## The early days

Rustls began with [a first commit](https://github.com/rustls/rustls/commit/4460bbe15b4df1f6e6efea4f9f06fbd0fb278077) on May 2, 2016. Progress was quick: a month later, on June 5, it could interoperate with most sites on the web. The first release, 0.1.0, followed on August 27, 2016 – less than four months after the first commit.

Early on, there were significant external contributions from [@briansmith](https://github.com/briansmith) and [@djc](http://github.com/djc).

In 2018 [@djc](http://github.com/djc) and [@Ralith](https://github.com/ralith) contributed QUIC support to rustls during the development of [Quinn](https://github.com/quinn-rs/quinn); this was the first outside contribution of a significant feature. In 2021 [@djc](http://github.com/djc) became the first co-maintainer, and was joined by [@cpu](http://github.com/cpu) in 2023.

Between 2018 and 2020 @djc worked towards arranging a [third-party audit](https://jbp.io/2020/06/14/rustls-audit/) which was funded by CNCF at the request of [Buoyant.io](https://buoyant.io) and completed by Cure53. In 2021 the project had its first paid contributions, where @djc was under contract with ISRG via their [Prossimo](https://www.memorysafety.org/initiative/rustls/) initiative to work on robustness. Later on, Prossimo funded myself, @cpu, @djc and others to dramatically improve the pace and depth of development.
That funding helped us deliver significant features -- pluggable cryptography providers, `no_std` support, FIPS certification, post-quantum key exchange and Encrypted ClientHello -- as well as sibling projects like [rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier) and the [OpenSSL compatibility layer](https://github.com/rustls/rustls-openssl-compat).

## Releases up to 0.23

From the 0.1.0 release, the project moved through a long series of releases over the following eight years, building out functionality, hardening and refining the API. That sequence of release lines culminated in 0.23, released on February 29, 2024.

![diagram of rustls major versions and 0.23 minor versions, on a timeline](/blog/release-lines-0.23.svg)

## The 0.23 line: stability and features

The 0.23 release line has been a stable one: in the time since, it has seen 43 non-breaking releases. That stability didn't come with stagnation. The 0.23 line delivered a wide range of important features, including a FIPS-certified cryptography option, certificate compression, Encrypted ClientHello, post-quantum cryptography, and performance improvements.

## The present: 0.24

The next breaking release is 0.24. It brings many improvements, amongst them:

* External buffering, improving bulk data performance
* Some support for async-friendly usage
* "Split mode"
* New arrangements for choosing a `CryptoProvider`

### External buffering and bulk data performance

In earlier releases, all data passed through `std::io` traits. This had a number of drawbacks: extra copies, awkward error handling, no `no-std` support, no half-close, and poor control over buffer sizes.

In 0.24, buffering moves outside Rustls. All TLS input arrives through a new trait, `TlsInputBuffer`, and all TLS output is appended to a user-provided `&mut Vec<u8>`. Incoming plaintext is decrypted in place and returned as a borrow into the input buffer, avoiding copies. Two implementations of `TlsInputBuffer` are provided: `SliceInput` and `VecInput`. `VecInput` can read from an `io::Read`, as before, giving a route to easy porting.

### Async-friendly usage

For some time, we've been waiting on Rust language developments — async dyn traits and "async keyword generics" — before addressing async usage directly. Rather than wait longer, 0.24 introduces a system of session types that model the steps of the handshake process. Servers move through `NeedsInput` → `Accepted` → `VerifyClientIdentity` → `Complete`; clients move through `NeedsInput` → `VerifyServerIdentity` → `Complete`.

Each step can be driven in async, blocking, or completion-based style. More steps can be added in the future in non-breaking changes. This replaces, and builds on, the `Acceptor` API seen in 0.23.

### Split mode

Previously, a single `Connection` object was responsible for both sending and receiving data. In 0.24, post-handshake sending and receiving are handled by separate objects: `SendTraffic` and `ReceiveTraffic`. Both are `Send`, so they can be used on different threads. This means full-duplex workloads can now double their throughput. The two objects communicate through an internal back-channel with very low contention.

![block diagram of split-mode components. on the left the receive-side is shown, with a simple state machine. on the right the send-side is shown.](/blog/split-mode.svg)

This is a feature first requested in 2019, and one we think is unique in TLS libraries. It will be exciting to see applications make use of this to take their TLS performance to the next level.

### Choosing a `CryptoProvider`

All cryptography used by Rustls comes via a `CryptoProvider`. In 0.23, two providers were built-in and could be chosen by crate features. In 0.24, providers are separate crates, such as `rustls-aws-lc-rs` and `rustls-ring`, and the main `rustls` crate no longer has crate features for selecting a provider. Choosing a global provider at the top of `main()` now happens elsewhere. As a result, there are no more panics related to feature unification.

## The future

After 0.24 is released, it will be baked for a little while to shake out any issues and give the ecosystem time to adapt. Then 1.0 will follow, and we want this to be a stable API that we can maintain long-term.
