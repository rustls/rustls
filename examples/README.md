# Rustls Examples

This directory contains a number of examples that use Rustls.

We recommend new users start by looking at `simpleclient.rs` and `simpleserver.rs`. Once those are understood, `tlsclient-mio.rs` and `tlsserver-mio.rs` provide more advanced examples.

## Running the examples

Run examples from the workspace root with `--package rustls-examples`:

```sh
cargo run --package rustls-examples --bin simpleclient
cargo run --package rustls-examples --bin tlsclient-mio -- --http www.rust-lang.org
```

Server examples require a certificate chain and private key in PEM format. For
local testing, [`mkcert`](https://github.com/FiloSottile/mkcert) can generate a
certificate trusted by your local browsers and tools:

```sh
mkcert localhost 127.0.0.1 ::1
cargo run --package rustls-examples --bin simpleserver -- localhost+2.pem localhost+2-key.pem
```

If you only need a quick self-signed certificate, OpenSSL can generate one:

```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt -subj "/CN=localhost"
cargo run --package rustls-examples --bin simpleserver -- server.crt server.key
```

The `server_acceptor.rs` example generates its own CA, server certificate,
client certificate, client key, and CRL. By default it writes `ca-cert.pem`,
`client-cert.pem`, `client-key.pem`, and `crl.der` into the current directory.

## Client examples

* `simpleclient.rs` - shows a simple client configuration that uses sensible defaults. It demonstrates using the `Stream` helper to treat a Rustls connection as you would a bi-directional TCP stream.
* `tlsclient-mio.rs` - shows a more complete client example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `limitedclient.rs` - shows how to configure Rustls so that unused cryptography is discarded by the linker. This client only supports TLS 1.3 and a single cipher suite.
* `simple_0rtt_client.rs` - shows how to make a TLS 1.3 client connection that sends early 0RTT data.
* `ech-client.rs` - shows how to configure Rustls to use encrypted client hello (ECH), including fetching an ECH config list with DNS-over-HTTPS.

## Server examples

* `simpleserver.rs` - shows a very minimal server example that accepts a single TLS connection. See `tlsserver-mio.rs` or `server_acceptor.rs` for a more realistic example.
* `tlsserver-mio.rs` - shows a more complete server example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `simple_0rtt_server.rs` - shows how to make a TLS 1.3 server that accepts multiple connections and prints early 0RTT data.
* `server_acceptor.rs` - shows how to use the `Acceptor` API to create a server that generates a unique `ServerConfig` for each client. This example also shows how to use client authentication, CRL revocation checking, and uses `rcgen` to generate its own certificates.

## Client-Server examples

* A client-server example using Raw Public Keys (RFC 7250) can be found in [`raw_key_openssl_interop`](../openssl-tests/src/raw_key_openssl_interop.rs).
