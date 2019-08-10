![Logo](https://raw.githubusercontent.com/ctz/rustls/master/admin/rustls-logo-web.png)

Rustls is a modern TLS library written in Rust.  It's pronounced 'rustles'.
It uses [*ring*](https://github.com/briansmith/ring) for cryptography
and [libwebpki](https://github.com/briansmith/webpki) for certificate
verification.

# Status
Rustls is ready for use.  There are no major breaking interface changes
expected.  [Here's what I'm working on now](https://github.com/ctz/rustls/projects/1).

If you'd like to help out, please see [CONTRIBUTING.md](CONTRIBUTING.md).

[![Build Status](https://travis-ci.org/ctz/rustls.svg?branch=master)](https://travis-ci.org/ctz/rustls)
[![Build Status](https://dev.azure.com/ctz99/ctz/_apis/build/status/ctz.rustls?branchName=master)](https://dev.azure.com/ctz99/ctz/_build/latest?definitionId=3&branchName=master)
[![Coverage Status (coveralls)](https://coveralls.io/repos/github/ctz/rustls/badge.svg?branch=master)](https://coveralls.io/github/ctz/rustls?branch=master)
[![Coverage Status (codecov.io)](https://codecov.io/gh/ctz/rustls/branch/master/graph/badge.svg)](https://codecov.io/gh/ctz/rustls/)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/rustls/)

## Release history:

* 0.16.0 (2019-08-10):
  - Optimisation of read path for polled non-blocking IO.
  - Correct an omission in TLS1.3 middlebox compatibility mode, causing
    handshake failures with servers behind buggy middleboxes.
  - Move to *ring* 0.16.
  - Assorted refactoring to reduce memory usage during and after
    handshake.
  - Update other dependencies.
* 0.15.2 (2019-04-02):
  - Moved example code around for benefit of Fuchsia.
  - Example code fixes for Windows -- Windows is now a tested platform.
  - QUIC-specific bug fixes.
  - Update dependencies.
* 0.15.1 (2019-01-29):
  - Fix incorrect offering of SHA1.
* 0.15.0 (2019-01-20):
  - Update dependencies.
  - *Breaking API change*: ALPN protocols are now encoded as a `Vec<u8>`, not
    a `String`.  This alters the type of:
    - `ClientConfig::alpn_protocols`
    - `ClientConfig::set_protocols`
    - `ServerConfig::alpn_protocols`
    - `ServerConfig::set_protocols`
    - `Session::get_alpn_protocol`
  - Emit a warning when receiving an invalid SNI extension, such as one
    including an IP address.
  - Extended QUIC support for later QUIC drafts.
  - Correct bug where we'd send more than one fatal alert for
    handshake failure cases.
  - Discontinue support for SHA1 signatures.
  - Move to Rust 2018 edition.
* 0.14.0 (2018-09-30):
  - Introduce client-side support for 0-RTT data in TLS1.3.
  - Fix a bug in rustls::Stream for non-blocking transports.
  - Move TLS1.3 support from draft 23 to final RFC8446 version.
  - Don't offer (eg) TLS1.3 if no TLS1.3 suites are configured.
  - Support stateful resumption in TLS1.3.  Stateless resumption
    was previously supported, but is not the default configuration.
  - *Breaking API change*: `generate()` removed from `StoresServerSessions` trait.
  - *Breaking API change*: `take()` added to `StoresServerSessions` trait.
* 0.13.1 (2018-08-17):
  - Fix a bug in rustls::Stream for non-blocking transports
    (backport).
* 0.13.0 (2018-07-15):
  - Move TLS1.3 support from draft 22 to 23.
  - Add support for `SSLKEYLOGFILE`; not enabled by default.
  - Add support for basic usage in QUIC.
  - `ServerConfig::set_single_cert` and company now report errors.
  - Add support for vectored IO: `writev_tls` can now be used to
    optimise system call usage.
  - Support ECDSA signing for server and client authentication.
  - Add type like `rustls::Stream` which owns its underlying TCP stream
    and rustls session.

See [OLDCHANGES.md](OLDCHANGES.md) for further change history.

# Documentation
Lives here: https://docs.rs/rustls/

# Approach
Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography.

## Current features

* TLS1.2 and TLS1.3.
* ECDSA or RSA server authentication by clients.
* ECDSA or RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* Chacha20Poly1305 bulk encryption.
* ALPN support.
* SNI support.
* Tunable MTU to make TLS messages match size of underlying transport.
* Optional use of vectored IO to minimise system calls.
* TLS1.2 session resumption.
* TLS1.2 resumption via tickets (RFC5077).
* TLS1.3 resumption via tickets or session storage.
* TLS1.3 0-RTT data for clients.
* Client authentication by clients.
* Client authentication by servers.
* Extended master secret support (RFC7627).
* Exporters (RFC5705).
* OCSP stapling by servers.
* SCT stapling by servers.
* SCT verification by clients.

## Possible future features

* PSK support.
* OCSP verification by clients.
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

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

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

