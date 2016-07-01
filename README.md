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
Rustls is built to a few rules:

- Modern, strong cryptography only:
  - No RC4, no DES.
  - No discrete-log DH or DSA.
- No discredited, little-used or legacy SSL/TLS features:
  - No CBC-mode mac-then-encrypt ciphersuites.
  - No unneccessary 'national pride' block ciphers like Camellia or ARIA.
  - No renegotiation.
  - No client authentication.
  - No discrete-log DH.  It's misdesigned in TLS.
- TLS1.2 or later only.

# Currently implemented
Client connections work to assorted internet servers.  The
following ciphersuites are supported:

- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

For ECDHE, the `nistp256` and `nistp384` curves are supported,
as well as `curve25519`.

The client test program is named `tlsclient`.  It expects to
find root certificates in `/etc/ssl/certs/ca-certificates.crt`
and be given a hostname as its single argument.  It connects
to that host and issues a basic HTTP request, eg:

```
$ ./target/debug/examples/tlsclient --http mozilla-modern.badssl.com
HTTP/1.1 200 OK
Server: nginx/1.6.2 (Ubuntu)
Date: Wed, 01 Jun 2016 18:44:00 GMT
Content-Type: text/html
Content-Length: 644
Last-Modified: Tue, 12 Apr 2016 01:21:49 GMT
Connection: close
ETag: "570c4dad-284"
Strict-Transport-Security: max-age=15768000
Cache-Control: no-store
Accept-Ranges: bytes

<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="shortcut icon" href="/icons/favicon-green.ico"/>
  <link rel="apple-touch-icon" href="/icons/icon-green.png"/>
  <title>mozilla-modern.badssl.com</title>
  <link rel="stylesheet" href="/style.css">
  <style>body { background: green; }</style>
</head>
<body>
<div id="content">
  <h1>
    mozilla-modern.<br>badssl.com
  </h1>
</div>

<div id="footer">
  This site uses the Mozilla &ldquo;<a href="https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility">Modern</a>&rdquo; TLS configuration.
</div>

</body>
</html>
Plaintext read error: Error { repr: Custom(Custom { kind: ConnectionAborted, error: StringError("CloseNotify alert received") }) }
Connection closed
```

or

```
$ ./target/debug/examples/tlsclient --http expired.badssl.com
TLS error: WebPKIError(CertExpired)
Connection closed
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
- [x] Choose a license.
- [x] Improve testing.
- [ ] Improve testing some more.
- [x] ALPN.
- [ ] Tickets.
- [x] Resumption.
- [x] chacha20poly1305 bulk encryption support.
- [x] Signing support in *ring* to unblock server work. (done upstream, thanks!)
- [x] Server support.
- [ ] Write some more sample programs.
- [ ] Stabilise and document public API.
