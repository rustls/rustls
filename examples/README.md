# Rustls Examples

This directory contains a number of examples that use Rustls.

We recommend new users start by looking at `simpleclient.rs` and `simpleserver.rs`. Once those are understood, `tlsclient-mio.rs` and `tlsserver-mio.rs` provide more advanced examples.

## Client examples

* `simpleclient.rs` - shows a simple client configuration that uses sensible defaults. It demonstrates using the `Stream` helper to treat a Rustls connection as you would a bi-directional TCP stream.
* `tlsclient-mio.rs` - shows a more complete client example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `limitedclient.rs` - shows how to configure Rustls so that unused cryptography is discarded by the linker. This client only supports TLS 1.3 and a single cipher suite.
* `simple_0rtt_client.rs` - shows how to make a TLS 1.3 client connection that sends early 0RTT data.
* `unbuffered-client.rs` - shows an advanced example of using Rustls lower-level APIs to implement a client that does not buffer any data inside Rustls.
* `unbuffered-async-client.rs` - shows an advanced example of using Rustls lower-level APIs to implement a client that does not buffer any data inside Rustls, and that processes TLS events asynchronously.
* `ech-client.rs` - shows how to configure Rustls to use encrypted client hello (ECH), including fetching an ECH config list with DNS-over-HTTPS.

## Server examples

* `simpleserver.rs` - shows a very minimal server example that accepts a single TLS connection. See `tlsserver-mio.rs` or `server_acceptor.rs` for a more realistic example.
* `tlsserver-mio.rs` - shows a more complete server example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `simple_0rtt_server.rs` - shows how to make a TLS1.3 that accepts multiple connections and prints early 0RTT data.
* `server_acceptor.rs` - shows how to use the `Acceptor` API to create a server that generates a unique `ServerConfig` for each client. This example also shows how to use client authentication, CRL revocation checking, and uses `rcgen` to generate its own certificates.
* `unbuffered-server.rs` - shows an advanced example of using Rustls lower-level APIs to implement a server that does not buffer any data inside Rustls.
