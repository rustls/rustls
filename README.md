# rustls-pki-types

[![Build Status](https://github.com/rustls/pki-types/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rustls/pki-types/actions/workflows/ci.yml?query=branch%3Amain)
[![Documentation](https://docs.rs/rustls-pki-types/badge.svg)](https://docs.rs/rustls-pki-types/)
[![Chat](https://img.shields.io/discord/976380008299917365?logo=discord)](https://discord.gg/MCSB76RU96)

This crate provides types for representing X.509 certificates, keys and other types as commonly
used in the rustls ecosystem. It is intended to be used by crates that need to work with such X.509
types, such as [rustls](https://crates.io/crates/rustls),
[rustls-webpki](https://crates.io/crates/rustls-webpki),
[rustls-pemfile](https://crates.io/crates/rustls-pemfile), and others.

Some of these crates used to define their own trivial wrappers around DER-encoded bytes.
However, in order to avoid inconvenient dependency edges, these were all disconnected. By
using a common low-level crate of types with long-term stable API, we hope to avoid the
downsides of unnecessary dependency edges while providing interoperability between crates.

## Features

- Interoperability between different crates in the rustls ecosystem
- Long-term stable API
- No dependencies
- Support for `no_std` contexts, with optional support for `alloc`

## DER and PEM

Many of the types defined in this crate represent DER-encoded data. DER is a binary encoding of
the ASN.1 format commonly used in web PKI specifications. It is a binary encoding, so it is
relatively compact when stored in memory. However, as a binary format, it is not very easy to
work with for humans and in contexts where binary data is inconvenient. For this reason,
many tools and protocols use a ASCII-based encoding of DER, called PEM. In addition to the
base64-encoded DER, PEM objects are delimited by header and footer lines which indicate the type
of object contained in the PEM blob.

The [rustls-pemfile](https://docs.rs/rustls-pemfile) crate can be used to parse PEM files.

## Creating new certificates and keys

This crate does not provide any functionality for creating new certificates or keys. However,
the [rcgen](https://docs.rs/rcgen) crate can be used to create new certificates and keys.
