/*! # Customising private key usage

By default rustls supports PKCS#8-format[^1] RSA or ECDSA keys, plus PKCS#1-format RSA keys.

However, if your private key resides in a HSM, or in another process, or perhaps
another machine, rustls has some extension points to support this:

The main trait you must implement is [`sign::SigningKey`][signing_key]. The primary method here
is [`choose_scheme`][choose_scheme] where you are given a set of [`SignatureScheme`s][sig_scheme] the client says
it supports: you must choose one (or return `None` -- this aborts the handshake). Having
done that, you return an implementation of the [`sign::Signer`][signer] trait.
The [`sign()`][sign_method] performs the signature and returns it.

(Unfortunately this is currently designed for keys with low latency access, like in a
PKCS#11 provider, Microsoft CryptoAPI, etc. so is blocking rather than asynchronous.
It's a TODO to make these and other extension points async.)

Once you have these two pieces, configuring a server to use them involves, briefly:

- packaging your [`sign::SigningKey`][signing_key] with the matching certificate chain into a [`sign::CertifiedKey`][certified_key]
- making a [`ResolvesServerCertUsingSni`][cert_using_sni] and feeding in your [`sign::CertifiedKey`][certified_key] for all SNI hostnames you want to use it for,
- setting that as your `ServerConfig`'s [`cert_resolver`][cert_resolver]

For a complete example of implementing a custom [`sign::SigningKey`][signing_key]
and [`sign::Signer`][signer] see the [rustls-cng] crate.

[signing_key]: crate::crypto::signer::SigningKey
[choose_scheme]: crate::crypto::signer::SigningKey.choose_scheme()
[sig_scheme]: crate::SignatureScheme
[signer]: crate::crypto::signer::Signer
[sign_method]: crate::crypto::Signer.sign()
[certified_key]: crate::crypto::signer::CertifiedKey
[cert_using_sni]: crate::server::ResolvesServerCertUsingSni
[cert_resolver]: crate::ServerConfig::cert_resolver
[rustls-cng]: https://github.com/rustls/rustls-cng/blob/dev/src/signer.rs

[^1]: For PKCS#8 it does not support password encryption -- there's not a meaningful threat
      model addressed by this, and the encryption supported is typically extremely poor.

# Unexpected EOF

TLS has a `close_notify` mechanism to prevent truncation attacks[^2].
According to the TLS RFCs, each party is required to send a `close_notify` message before
closing the write side of the connection. However, some implementations don't send it.
So long as the application layer protocol (for instance HTTP/2) has message length framing
and can reject truncated messages, this is not a security problem.

Rustls treats an EOF without `close_notify` as an error of type `std::io::Error` with
`ErrorKind::UnexpectedEof`. In some situations it's appropriate for the application to handle
this error the same way it would handle a normal EOF (a read returning `Ok(0)`). In particular
if `UnexpectedEof` occurs on an idle connection it is appropriate to treat it the same way as a
clean shutdown. And if an application always uses messages with length framing (in other words,
messages are never delimited by the close of the TCP connection), it can unconditionally
ignore `UnexpectedEof` errors from rustls.

[^2]: <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
*/
