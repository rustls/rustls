## Release history

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
