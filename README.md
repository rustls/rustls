# Rustls
Rustls is a new, modern TLS library written in Rust.  It's pronounced 'rustles'.
It uses [*ring*](https://github.com/briansmith/ring) for cryptography
and [libwebpki](https://github.com/briansmith/webpki) for certificate
verification.

# Status
Rustls is currently in development and hence unstable.  [Here's what I'm working on now](https://github.com/ctz/rustls/projects/1).

[![Build Status](https://travis-ci.org/ctz/rustls.svg?branch=master)](https://travis-ci.org/ctz/rustls)
[![Coverage Status](https://coveralls.io/repos/github/ctz/rustls/badge.svg?branch=master)](https://coveralls.io/github/ctz/rustls?branch=master)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/rustls/)

## Release history:

* 0.9.0 (2017-06-16):
  - Update dependencies.
  - Add IO helper function (`complete_io`) to `rustls::Session`.
  - Add blocking stream type -- `rustls::Stream` -- to ease use on top
    of blocking sockets.
* 0.8.0 (2017-05-14):
  - Add `dangerous_configuration` feature for unsafe features.
* 0.7.0 (2017-05-08):
  - Update dependencies.
* 0.6.0 (2017-05-06):
  - Update dependencies.
  - Expose ring's new support for PKCS#8-format private keys.
  - New API for applying limitation to internal buffer sizes.
* 0.5.8 (2017-03-16):
  - Fix build on later rustc.
* 0.5.7 (2017-02-27):
  - No changes from 0.5.6; republished with nightly cargo for category support.
* 0.5.6 (2017-02-19):
  - RFC7627 extended master secret support
  - Assorted documentation improvements
* 0.5.5 (2017-02-03):
  - Crate categories.
  - Protocol errors now permanent for given session.
  - Exposed `ResolvesServerCert` trait for customising certification
    selection.
  - Exposed `SignatureScheme` enum.
* 0.5.4 (2017-01-26):
  - First release with TLS1.3-draft-18 support.
  - More performance improvements (now ~15Gbps per core).
  - New API to learn version of negotiated connection.
* 0.5.0 (2016-09-27):
  - Tickets.
  - Coverage testing.
  - Benchmarking.
  - Massive performance improvements (from ~1Gbps to ~6Gbps per core).
  - OSX support.
  - Minor API corrections and additional testing.

# Documentation
Lives here: https://docs.rs/rustls/

# Approach
Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography.

## Current features

* TLS1.2 and TLS1.3 (draft 18) only.
* ECDSA or RSA server authentication by clients.
* RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* Chacha20Poly1305 bulk encryption.
* ALPN support.
* SNI support.
* Tunable MTU to make TLS messages match size of underlying transport.
* TLS1.2 session resumption.
* TLS1.2 resumption via tickets (RFC5077).
* TLS1.3 resumption via tickets.
* Client authentication by clients.
* Client authentication by servers.
* Extended master secret support (RFC7627).

## Possible future features

* ECDSA server authentication by servers.
* PSK support.
* OCSP stapling.
* SCT stapling.
* Certificate pinning.

## Non-features

The following things are broken, obsolete, badly designed, underspecified,
dangerous and/or insane. Rustls does not support:

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
* AES-GCM with unsafe nonces.

There are plenty of other libraries that provide these features should you
need them.

# Example code
There are two example programs which use 
[mio](https://github.com/carllerche/mio) to do asynchronous IO.

## Client example program
The client example program is named `tlsclient`.  The interface looks like:

```tlsclient
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient [options] [--suite SUITE ...] [--proto PROTO ...] <hostname>
  tlsclient (--version | -v)
  tlsclient (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer serveral protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --verbose           Emit log output.
    --mtu MTU           Limit outgoing messages to MTU bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
```

Some sample runs:

```
$ ./tlsclient --http mozilla-modern.badssl.com
HTTP/1.1 200 OK
Server: nginx/1.6.2 (Ubuntu)
Date: Wed, 01 Jun 2016 18:44:00 GMT
Content-Type: text/html
Content-Length: 644
(...)
```

or

```
$ ./target/debug/examples/tlsclient --http expired.badssl.com
TLS error: WebPKIError(CertExpired)
Connection closed
```

## Server example program
The server example program is named `tlsserver`.  The interface looks like:

```tlsserver
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the RSA private
key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] echo
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] http
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] [--proto PROTO ...] [options] forward <fport>
  tlsserver (--version | -v)
  tlsserver (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key, in PEM format.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
```

Here's a sample run; we start a TLS echo server, then connect to it with
openssl and tlsclient:

```
$ ./tlsserver --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443 echo &
$ echo hello world | openssl s_client -ign_eof -quiet -connect localhost:8443
depth=2 CN = ponytown RSA CA
verify error:num=19:self signed certificate in certificate chain
hello world
^C
$ echo hello world | ./tlsclient --cafile test-ca/rsa/ca.cert -p 8443 localhost
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

