# Rustls development roadmap

## Future priorities

Specific features, in rough order of priority:

* **Address asynchronous handshake interruption**.
  Allow completion of user-provided operations to be deferred.
  rustls/rustls#850

* **Support Encrypted Client Hello (ECH) (Server Side)**.
  Encrypted Client Hello is an upcoming standard from the TLS WG providing better
  protection for some of the data sent by a client in the initial Client Hello
  message. Rustls already supports client side ECH, we will add server side support.
  rustls/rustls#1980

General priorities:

* **Additional Performance Optimization**.
  Additional performance optimization including CPU usage, latency, and memory
  usage. The goal is to outperform OpenSSL across the board if we are not already.

* **Improve OpenSSL Compatibility**.
  Continue to improve the OpenSSL compatibility layer.

* **Rustls API Refinements**.
  Continue to improve the Rustls API. Aim for ease of use, clarity.

## Past priorities

Delivered in 0.23.11:

* **Enforce Confidentiality / Integrity Limits**.
  The QUIC use of TLS mandates limited usage of AEAD keys. While TLS 1.3 and 1.2
  do not require this, the same kinds of issues can apply here, and we should
  consider implementing limits for TLS over TCP as well.
  rustls/rustls#755

Delivered in 0.23.10:

* **Support Encrypted Client Hello (Client Side)**.
  Encrypted Client Hello is an upcoming standard from the TLS WG providing better
  protection for some of the data sent by a client in the initial Client Hello
  message.
  rustls/rustls#1718

Delivered in 0.23.9:

* **Support RFC 8879 Certificate Compression**.
  Support for a TLS extension that substantially shrinks certificates (one of the
  largest parts of the TLS handshake), improving handshake latency by decreasing
  bandwidth used.
  rustls/rustls#534

Delivered in [rustls-openssl-compat](https://github.com/rustls/rustls-openssl-compat) 0.1.0:

* **OpenSSL API Compatibility Layer**.
  Add an OpenSSL C API compatibility layer for adoption purposes.

Delivered in 0.23.2:

* **Support Post-Quantum Hybrid Key Exchange**.
  Experimental, optional support for the `X25519Kyber768Draft00` key exchange.
  This should track [the draft](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/).
  rustls/rustls#1687

Delivered in 0.23:

* **FIPS Certification for Default Cryptographic Library**.
  Change the default cryptographic library to something with FIPS certification.
  rustls/rustls#1540

* **Add No-Allocation / Write-Through API**.
  Would make handshakes faster and give the caller more control over allocations.
  RFC: rustls/rustls#1420

* **Support no_std**.
  Enables use of rustls in more memory-constrained environments.
  RFC: rustls/rustls#1399

Delivered in [rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier) 0.1.0:

* **Improve OS Trust Verifier Support**.
  While we currently have a way to trust certificates stored in the platform trust
  store, platform trust stores can have other ways of restricting how/when roots
  that they expose are trusted. In order to rely on these (on Windows, Android,
  and Apple platforms) we should rely on the platform verifier directly.

Delivered in 0.22:

* **Enable Pluggable Cryptographic Back-ends**.
  Allow plugging in different cryptographic back-ends.
  rustls/rustls#1184

* **Comprehensive Performance Benchmarking**.
  Performance should be a headline feature of Rustls. We need to develop a more
  comprehensive benchmarking system so that we can assess and improve performance
  from multiple angles, including CPU usage, latency, and memory usage.

Delivered in 0.21:

* **Support IP Address Certificates**.
  There are some popular use cases where applications want TLS certificates for
  services that don’t have their own host name, relying on the IP address directly
  instead. This is common in Kubernetes deployments and service meshes.
  rustls/rustls#184

* **Implement RFC 8446 Appendix C.4 in session cache**.
  TLS clients should use session tickets at most once for resumption. Without this,
  TLS clients may be tracked across connections through reuse of session tickets.
  Requires changes of the internal APIs to the session caching infrastructure.
  rustls/rustls#466

* **Improve Client Certificate Authentication Support**.
  Rustls and webpki currently do not provide access to client information supplied
  as part of the certificate, and there’s no infrastructure to deal with revocation
  checks.
  rustls/rustls-ffi#87

Delivered in 0.20:

* **Add/extend support for TLS 1.3 Early Data**.
  Early data allows clients to submit data before the TLS handshake is complete
  in some cases (idempotent requests, data where replay is not a risk), improving
  latency in the cases of, for example, HTTP requests by submitting the request
  in parallel with the TLS handshake.
