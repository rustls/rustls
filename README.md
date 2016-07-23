# Rustls
Rustls is a new, modern TLS library written in Rust.  It's pronounced 'rustles'.
It uses [*ring*](https://github.com/briansmith/ring) for cryptography
and [libwebpki](https://github.com/briansmith/webpki) for certificate
verification.

# Status
Rustls is currently in development and hence unstable.

[![Build Status](https://travis-ci.org/ctz/rustls.svg?branch=master)](https://travis-ci.org/ctz/rustls)

# Documentation
Lives here: https://jbp.io/rustls/rustls/

# Approach
Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography.

## Current features

* TLS1.2 only.
* ECDSA or RSA server authentication by clients.
* RSA server authentication by servers.
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces.
* Chacha20Poly1305 bulk encryption.
* ALPN support.
* SNI support.
* Tunable MTU to make TLS messages match size of underlying transport.
* Resumption by clients.

## Possible future features

* Resumption by servers.
* Client authentication by clients.
* Client authentication by servers.
* ECDSA server authentication by servers.
* PSK support.
* TLS1.3.
* Resumption via tickets.
* OCSP stapling.
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
There are two example programs which use mio to do asynchronous IO.

## Client example program
The client example program is named `tlsclient`.  The interface looks like:

```
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, CA certificates are read from
`/etc/ssl/certs/ca-certificates.crt'.

Usage:
  tlsclient [--verbose] [-p PORT] [--http] [--mtu MTU] [--cache CACHE]
    [--cafile CAFILE] [--suite SUITE...] [--proto PROTOCOL...] <hostname>
  tlsclient --version
  tlsclient --help

Options:
    -p, --port PORT     Connect to PORT. Default is 443.
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
    --cache CACHE       Save session cache to file CACHE.
    --verbose           Emit log output.
    --mtu MTU           Limit outgoing messages to MTU bytes.
    --version           Show tool version.
    --help              Show this screen.

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

```
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the RSA private
key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] echo
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] http
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] forward <fport>
  tlsserver --version
  tlsserver --help

Options:
    -p, --port PORT     Listen on PORT. Default is 443.
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA private key,
                        in PEM format.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
    --verbose           Emit log output.
    --version           Show tool version.
    --help              Show this screen.
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

# TODO list
(in no particular order)

- [x] Choose a license.
- [x] Improve testing.
- [ ] Improve testing some more.
- [x] ALPN.
- [ ] Tickets.
- [x] Resumption by client.
- [x] chacha20poly1305 bulk encryption support.
- [x] Signing support in *ring* to unblock server work. (done upstream, thanks!)
- [x] Server support.
- [x] Write some more sample programs.
- [x] Stabilise and document public API.
- [ ] Benchmarks.
- [ ] Optimise internals to reduce copies.
- [ ] Resumption by server.
- [ ] Client authentication by client.
- [ ] Client authentication by server.
- [ ] Promote mio integration to a first-class feature.
