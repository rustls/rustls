/*!

The below list reflects the support provided with the default crate features.
Items marked with an asterisk `*` can be extended or altered via public
APIs ([`CryptoProvider`] for example).

[`CryptoProvider`]: crate::crypto::CryptoProvider

## Current features

* TLS1.2 and TLS1.3
* ECDSA, Ed25519 or RSA server authentication by clients `*`
* ECDSA, Ed25519 or RSA server authentication by servers `*`
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves `*`
* AES128-GCM and AES256-GCM bulk encryption, with safe nonces `*`
* ChaCha20-Poly1305 bulk encryption ([RFC7905](https://tools.ietf.org/html/rfc7905)) `*`
* ALPN support
* SNI support
* Tunable fragment size to make TLS messages match size of underlying transport
* Optional use of vectored IO to minimise system calls
* TLS1.2 session resumption
* TLS1.2 resumption via tickets ([RFC5077](https://tools.ietf.org/html/rfc5077))
* TLS1.3 resumption via tickets or session storage
* TLS1.3 0-RTT data
* Server and optional client authentication
* Extended master secret support ([RFC7627](https://tools.ietf.org/html/rfc7627))
* Exporters ([RFC5705](https://tools.ietf.org/html/rfc5705))
* OCSP stapling by servers

## Non-features

For reasons explained in the other sections of this manual, rustls does not
and will not support:

* SSL1, SSL2, SSL3, TLS1 or TLS1.1
* RC4
* DES or triple DES
* EXPORT ciphersuites
* MAC-then-encrypt ciphersuites
* Ciphersuites without forward secrecy
* Renegotiation
* Kerberos
* TLS 1.2 protocol compression
* Discrete-log Diffie-Hellman `*`
* Automatic protocol version downgrade
* Using CA certificates directly to authenticate a server/client (often called "self-signed
  certificates"). _Rustls' default certificate verifier does not support using a trust anchor as
  both a CA certificate and an end-entity certificate in order to limit complexity and risk in
  path building. While dangerous, all authentication can be turned off if required --
  see the [example code](https://github.com/rustls/rustls/blob/992e2364a006b2e84a8cf6a7c3eaf0bdb773c9de/examples/src/bin/tlsclient-mio.rs#L318)_ `*`

*/
