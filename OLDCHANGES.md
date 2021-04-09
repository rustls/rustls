## Release history

* 0.17.0 (2020-02-22):
  - *Breaking API change*: ALPN protocols offered by the client are passed
    to the server certificate resolution trait (`ResolvesServerCert`).
  - *Breaking API change*: The server certificate resolution trait now
    takes a struct containing its arguments, so new data can be passed
    to these functions without further breaking changes.
  - Signature schemes offered by the client are now filtered to those
    compatible with the client-offered ciphersuites.  Prior to this change
    it was likely that server key type switching would not work for clients
    that offer signature schemes mismatched with their ciphersuites.
  - Add manual with goal-oriented documentation, and rationale for design
    decisions.
  - *Breaking API change*: `AlwaysResolvesClientCert::new` is now fallible,
    as is `ClientConfig::set_single_client_cert`.
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
  - Don't offer (e.g.) TLS1.3 if no TLS1.3 suites are configured.
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
* 0.12.0 (2018-01-06):
  - New API for learning negotiated cipher suite.
  - Move TLS1.3 support from draft 18 to 22.
  - Allow server-side MTU configuration.
  - Tested against latest BoringSSL test suite.
  - Support RFC5705 exporters.
  - Provide `ResolvesServerCertUsingSNI` for doing SNI-based
    certificate switching.
  - Allow disabling SNI extension on clients, for use with
    custom server certificate verifiers where the hostname
    may not make sense.
  - DNS names are now typesafe, using `webpki::DNSName`.
  - Update dependencies.
* 0.11.0 (2017-08-28):
  - New server API for learning requested SNI name.
  - Server now checks selected certificate for validity.
  - Remove time crate dependency.
  - Follow webpki interface changes.
  - Update dependencies.
* 0.10.0 (2017-08-12):
  - Request and verify SCTs using sct crate.  This doesn't happen
    unless you pass in some certificate transparency logs -- example code
    does this.
  - Request OCSP stapled response and pass to cert verifier.
    Note that OCSP verification is not implemented, but this is the public
    API public change required to support this.
  - Allow OCSP and SCT stapling for servers.
  - Refactor handshake state machines.
  - Bind verifications to final state -- note API change for custom cert
    verification.
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
