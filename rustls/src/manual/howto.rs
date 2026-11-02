/*! # Customising private key usage

By default, rustls loads private keys using the [`KeyProvider`][] of the configured
[`CryptoProvider`][]. This takes a [`PrivateKeyDer`] and allows use of an in-memory
private key in a variety of encodings and key types.

However, if your private key resides in a HSM, or in another process, or perhaps
another machine, rustls has some extension points to support this:

The main trait you must implement is [`SigningKey`][]. The primary method here
is [`choose_scheme()`][], where you are given the [`SignatureScheme`][]s
the peer says it supports (on the server, rustls first removes any that are unusable with the
negotiated protocol version and cipher suites). You must choose one and return an implementation
of the [`Signer`][] trait, or return `None` if none are acceptable. The other method,
[`public_key()`][], returns the key's SubjectPublicKeyInfo if it is available; this
is used to check that the key matches its certificate.

A [`Signer`][] is used once: [`scheme()`][] reports the chosen scheme,
and [`sign()`][] consumes the signer, performs the signature, and returns it.
The message given to `sign()` is not pre-hashed; hashing it according to the chosen
scheme is up to the implementation.

(Unfortunately this is currently designed for keys with low latency access, like in a
PKCS#11 provider, Microsoft CryptoAPI, etc. so is blocking rather than asynchronous.
It's a TODO to make these and other extension points async.)

Once you have these two pieces, configuring a server to use them involves, briefly:

- packaging your [`SigningKey`][] with the matching identity (typically a certificate
  chain) into a [`Credentials`][] using [`Credentials::new()`][].
  This fails if `public_key()` returns `None` or the keys don't match; use
  [`Credentials::new_unchecked()`][] to skip that check.
- wrapping the [`Credentials`][] in a [`ServerCredentialResolver`][]:
  - for a single identity, use [`SingleCredential`][];
  - to select by SNI hostname, make a [`ServerNameResolver`][] and
    [`add()`][] your [`Credentials`][] for each hostname;
  - or implement [`ServerCredentialResolver`][] yourself, calling
    [`Credentials::signer()`][] to obtain the [`SelectedCredential`][].
- passing that resolver to [`ConfigBuilder::with_server_credential_resolver()`][]
  (which sets [`ServerConfig::cert_resolver`][]).

[`KeyProvider`]: crate::crypto::KeyProvider
[`CryptoProvider`]: crate::crypto::CryptoProvider
[`SigningKey`]: crate::crypto::SigningKey
[`choose_scheme()`]: crate::crypto::SigningKey::choose_scheme
[`SignatureScheme`]: crate::crypto::SignatureScheme
[`Signer`]: crate::crypto::Signer
[`public_key()`]: crate::crypto::SigningKey::public_key
[`scheme()`]: crate::crypto::Signer::scheme
[`sign()`]: crate::crypto::Signer::sign
[`Credentials`]: crate::crypto::Credentials
[`Credentials::new()`]: crate::crypto::Credentials::new
[`Credentials::new_unchecked()`]: crate::crypto::Credentials::new_unchecked
[`ServerCredentialResolver`]: crate::server::ServerCredentialResolver
[`SingleCredential`]: crate::crypto::SingleCredential
[`ServerNameResolver`]: crate::server::ServerNameResolver
[`add()`]: crate::server::ServerNameResolver::add
[`Credentials::signer()`]: crate::crypto::Credentials::signer
[`SelectedCredential`]: crate::crypto::SelectedCredential
[`ConfigBuilder::with_server_credential_resolver()`]: crate::ConfigBuilder::with_server_credential_resolver
[`ServerConfig::cert_resolver`]: crate::ServerConfig::cert_resolver
[`PeerIncompatible::NoSignatureSchemesInCommon`]: crate::error::PeerIncompatible::NoSignatureSchemesInCommon
[`ClientCredentialResolver`]: crate::client::ClientCredentialResolver
[`ConfigBuilder::with_client_credential_resolver()`]: crate::ConfigBuilder::with_client_credential_resolver
[`PrivateKeyDer`]: pki_types::PrivateKeyDer
[`ConfigBuilder::with_single_cert()`]: crate::ConfigBuilder::with_single_cert

# Unexpected EOF

TLS has a `close_notify` mechanism to prevent truncation attacks[^2].
According to the TLS RFCs, each party is required to send a `close_notify` message before
closing the write side of the connection. However, some implementations don't send it.
So long as the application layer protocol (for instance HTTP/2) has message length framing
and can reject truncated messages, this is not a security problem.

When an EOF is received from the network using `TlsInputBuffer::read()`, rustls sets an
`has_seen_eof()` flag on that input buffer. If the `MessageHandler::state()` does not have
`peer_has_closed()` yielding `true` and the read side of the connection has seen an EOF, an
`UnexpectedEof` error should be raised unless the application layer protocol knows for sure
that no message is in flight. This could be the case if the connection has been idle or
if application messages are framed with their length.

[^2]: <https://datatracker.ietf.org/doc/html/rfc9846#section-6.1>

# Debugging

If you encounter a bug with Rustls it can be helpful to collect up as much diagnostic
information as possible.

## Collecting logs

If your bug reproduces with one of the [Rustls examples] you can use the
[`RUST_LOG`] environment variable to increase the log verbosity. If you're using
your own application, you may need to configure it with a tracing backend
such as those available from [`tracing-subscriber`].

Consider reproducing your bug with `RUST_LOG=rustls=trace` and sharing the result
in a [GitHub gist].

[Rustls examples]: https://github.com/rustls/rustls/tree/main/examples
[`RUST_LOG`]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
[`tracing-subscriber`]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/
[GitHub gist]: https://docs.github.com/en/get-started/writing-on-github/editing-and-sharing-content-with-gists/creating-gists

## Taking a packet capture

When logs aren't enough taking a packet capture ("pcap") is another helpful tool.
The details of how to accomplish this vary by operating system/context.

### tcpdump

As one example, on Linux using [`tcpdump`] is often easiest.

If you know the IP address of the remote server your bug demonstrates with you
could take a short packet capture with this command (after replacing
`XX.XX.XX.XX` with the correct IP address):

```bash
sudo tcpdump -i any tcp and dst host XX.XX.XX.XX -C5 -w rustls.pcap
```

The `-i any` captures on any network interface. The `tcp and dst host XX.XX.XX.XX`
portion target the capture to TCP traffic to the specified IP address. The `-C5`
argument limits the capture to at most 5MB. Lastly the `-w` argument writes the
capture to `rustls.pcap`.

Another approach is to use `tcp and port XXXX` instead of `tcp and dst host XX.XX.XX.XX`
to capture all traffic to a specific port instead of a specific host server.

[`tcpdump`]: https://web.archive.org/web/www.redhat.com/en/blog/introduction-using-tcpdump-linux-command-line

### SSLKEYLOGFILE

If the bug you are reporting happens after data is encrypted you may also wish to
share the secret keys required to decrypt the post-handshake traffic.

If you're using one of the [Rustls examples] you can set the `SSLKEYLOGFILE` environment
variable to a path where secrets will be written. E.g. `SSLKEYLOGFILE=rustls.pcap.keys`.

If you're using your own application you may need to customize the Rustls `ClientConfig`
or `ServerConfig`'s `key_log` setting like the example applications do.

With the file from `SSLKEYLOGFILE` it is possible to use [Wireshark] or another tool to
decrypt the post-handshake messages, following [these instructions][curl-sslkeylogfile].

Remember this allows plaintext decryption and should only be done in testing contexts
where no sensitive data (API keys, etc) are being shared.

[Wireshark]: https://www.wireshark.org/download.html
[curl-sslkeylogfile]: https://everything.curl.dev/usingcurl/tls/sslkeylogfile.html
*/
