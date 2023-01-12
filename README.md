<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.  It uses <a href = "https://github.com/briansmith/ring"><em>ring</em></a> for cryptography and <a href = "https://github.com/briansmith/webpki">webpki</a> for certificate
verification.
</p>

# Status
Rustls is ready for use.  There are no major breaking interface changes
envisioned after the set included in the 0.20 release.

If you'd like to help out, please see [CONTRIBUTING.md](CONTRIBUTING.md).

[![Build Status](https://github.com/rustls/rustls/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/rustls/actions/workflows/build.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/rustls/rustls/branch/main/graph/badge.svg)](https://codecov.io/gh/rustls/rustls/)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/rustls/)
[![Chat](https://img.shields.io/discord/976380008299917365?logo=discord)](https://discord.gg/MCSB76RU96)

## Release history

* Next release
  - Planned: removal of unused signature verification schemes at link-time.
* 0.20.8 (2023-01-12)
  - Yield an error from `ConnectionCommon::read_tls()` if buffers are full.
    Both a full deframer buffer and a full incoming plaintext buffer will
    now cause an error to be returned. Callers should call `process_new_packets()`
    and read out the plaintext data from `reader()` after each successful call to `read_tls()`.
  - The minimum supported Rust version is now 1.57.0 due to some dependencies
    requiring it.
* 0.20.7 (2022-10-18)
  - Expose secret extraction API under the `secret_extraction` cargo feature.
    This is designed to enable switching from rustls to kTLS (kernel TLS
    offload) after a successful TLS 1.2/1.3 handshake, for example.
  - Move filtering of signature schemes after config selection, avoiding the need
    for linking in encryption/decryption code for all cipher suites at the cost of
    exposing more signature schemes in the `ClientHello` emitted by the `Acceptor`.
  - Expose AlertDescription, ContentType, and HandshakeType,
    SignatureAlgorithm, and NamedGroup as part of the stable API. Previously they
    were part of the unstable internals API, but were referenced by parts of the
    stable API.
  - We now have a [Discord channel](https://discord.gg/MCSB76RU96) for community
    discussions.
  - The minimum supported Rust version is now 1.56.0 due to several dependencies
    requiring it.
* 0.20.6 (2022-05-18)
  - 0.20.5 included a change to track more context for the `Error::CorruptMessage`
    which made API-incompatible changes to the `Error` type. We yanked 0.20.5
    and have reverted that change as part of 0.20.6.
* 0.20.5 (2022-05-14)
  - Correct compatbility with servers which return no TLS extensions and take
    advantage of a special case encoding.
  - Remove spurious warn-level logging introduced in 0.20.3.
  - Expose cipher suites in `ClientHello` type.
  - Allow verification of IP addresses with `dangerous_config` enabled.
  - Retry I/O operations in `ConnectionCommon::complete_io()` when interrupted.
  - Fix server::ResolvesServerCertUsingSni case sensitivity.
* 0.20.4 (2022-02-19)
  - Correct regression in QUIC 0-RTT support.
* 0.20.3 (2022-02-13)
  - Support loading ECDSA keys in SEC1 format.
  - Support receipt of 0-RTT "early data" in TLS1.3 servers.  It is not enabled
    by default; opt in by setting `ServerConfig::max_early_data_size` to a non-zero
    value.
  - Support sending of data with the first server flight.  This is also not
    enabled by default either: opt in by setting `ServerConfig::send_half_rtt_data`.
  - Support `read_buf` interface when compiled with nightly. This means
    data can be safely read out of a rustls connection into a buffer without
    the buffer requiring initialisation first.  Set the `read_buf` feature to
    use this.
  - Improve efficiency when writing vectors of TLS types.
  - Reduce copying and improve efficiency in TLS1.2 handshake.
* 0.20.2 (2021-11-21)
  - Fix `CipherSuite::as_str()` value (as introduced in 0.20.1).
* 0.20.1 (2021-11-14)
  - Allow cipher suite enum items to be stringified.
  - Improve documentation of configuration builder types.
  - Ensure unused cipher suites can be removed at link-time.
  - Ensure single-use error types implement `std::error::Error`, and are public.

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for further change history.

# Documentation
Lives here: https://docs.rs/rustls/

# Approach
Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography.

## Current features

* TLS1.2 and TLS1.3.
* ECDSA, Ed25519 or RSA server authentication by clients.
* ECDSA, Ed25519 or RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* ChaCha20-Poly1305 bulk encryption ([RFC7905](https://tools.ietf.org/html/rfc7905)).
* ALPN support.
* SNI support.
* Tunable fragment size to make TLS messages match size of underlying transport.
* Optional use of vectored IO to minimise system calls.
* TLS1.2 session resumption.
* TLS1.2 resumption via tickets ([RFC5077](https://tools.ietf.org/html/rfc5077)).
* TLS1.3 resumption via tickets or session storage.
* TLS1.3 0-RTT data for clients.
* TLS1.3 0-RTT data for servers.
* Client authentication by clients.
* Client authentication by servers.
* Extended master secret support ([RFC7627](https://tools.ietf.org/html/rfc7627)).
* Exporters ([RFC5705](https://tools.ietf.org/html/rfc5705)).
* OCSP stapling by servers.
* SCT stapling by servers.
* SCT verification by clients.

## Possible future features

* PSK support.
* OCSP verification by clients.
* Certificate pinning.

## Non-features

For reasons [explained in the manual](https://docs.rs/rustls/latest/rustls/manual/_02_tls_vulnerabilities/index.html),
rustls does not and will not support:

* SSL1, SSL2, SSL3, TLS1 or TLS1.1.
* RC4.
* DES or triple DES.
* EXPORT ciphersuites.
* MAC-then-encrypt ciphersuites.
* Ciphersuites without forward secrecy.
* Renegotiation.
* Kerberos.
* Compression.
* Discrete-log Diffie-Hellman.
* Automatic protocol version downgrade.

There are plenty of other libraries that provide these features should you
need them.

### Platform support

Rustls uses [`ring`](https://crates.io/crates/ring) for implementing the
cryptography in TLS. As a result, rustls only runs on platforms
[supported by `ring`](https://github.com/briansmith/ring#online-automated-testing).
At the time of writing this means x86, x86-64, armv7, and aarch64.

Rustls requires Rust 1.56 or later.

# Example code
There are two example programs which use
[mio](https://github.com/carllerche/mio) to do asynchronous IO.

## Client example program
The client example program is named `tlsclient-mio`.  The interface looks like:

```tlsclient-mio
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient-mio [options] [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] <hostname>
  tlsclient-mio (--version | -v)
  tlsclient-mio (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --max-frag-size M   Limit outgoing messages to M bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
```

Some sample runs:

```
$ cargo run --bin tlsclient-mio -- --http mozilla-modern.badssl.com
HTTP/1.1 200 OK
Server: nginx/1.6.2 (Ubuntu)
Date: Wed, 01 Jun 2016 18:44:00 GMT
Content-Type: text/html
Content-Length: 644
(...)
```

or

```
$ cargo run --bin tlsclient-mio -- --http expired.badssl.com
TLS error: WebPkiError(CertExpired, ValidateServerCert)
Connection closed
```

## Server example program
The server example program is named `tlsserver-mio`.  The interface looks like:

```tlsserver-mio
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] [options] echo
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] [options] http
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] [options] forward <fport>
  tlsserver-mio (--version | -v)
  tlsserver-mio (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
```

Here's a sample run; we start a TLS echo server, then connect to it with
`openssl` and `tlsclient-mio`:

```
$ cargo run --bin tlsserver-mio -- --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443 echo &
$ echo hello world | openssl s_client -ign_eof -quiet -connect localhost:8443
depth=2 CN = ponytown RSA CA
verify error:num=19:self signed certificate in certificate chain
hello world
^C
$ echo hello world | cargo run --bin tlsclient-mio -- --cafile test-ca/rsa/ca.cert -p 8443 localhost
hello world
^C
```

# License

Rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

# Code of conduct

This project adopts the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please email rustls-mod@googlegroups.com to report any instance of misconduct, or if you
have any comments or questions on the Code of Conduct.
