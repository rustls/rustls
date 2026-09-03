# Rustls Examples

This directory contains a number of examples that use Rustls.

We recommend new users start by looking at `simple-client.rs` and `simple-server.rs`. Once those are understood, `tls-client-mio.rs` and `tls-server-mio.rs` provide more advanced examples.

## Client examples

* `simple-client.rs` - shows a simple client configuration that uses sensible defaults. It demonstrates using the `Stream` helper to treat a Rustls connection as you would a bi-directional TCP stream.
* `tls-client-mio.rs` - shows a more complete client example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `limited-client.rs` - shows how to configure Rustls so that unused cryptography is discarded by the linker. This client only supports TLS 1.3 and a single cipher suite.
* `simple-0rtt-client.rs` - shows how to make a TLS 1.3 client connection that sends early 0RTT data.
* `ech-client.rs` - shows how to configure Rustls to use encrypted client hello (ECH), including fetching an ECH config list with DNS-over-HTTPS.

## Server examples

* `simple-server.rs` - shows a very minimal server example that accepts a single TLS connection. See `tls-server-mio.rs` or `server-acceptor.rs` for a more realistic example.
* `tls-server-mio.rs` - shows a more complete server example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `simple-0rtt-server.rs` - shows how to make a TLS1.3 server that accepts multiple connections and prints early 0RTT data.
* `server-acceptor.rs` - shows how to use the `Acceptor` API to create a server that generates a unique `ServerConfig` for each client. This example also shows how to use client authentication, CRL revocation checking, and uses `rcgen` to generate its own certificates.

## Client-Server examples

* A client-server example using Raw Public Keys (RFC 7250) can be found in [`raw_key_openssl_interop`](../openssl-tests/src/raw_key_openssl_interop.rs).
