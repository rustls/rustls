# Security Policy

## Supported Versions

Security fixes will be backported only to the rustls versions for which the
original semver-compatible release was published less than 2 years ago.

For example, as of 2025-05-09 the latest release is 0.23.27.

* 0.23.0 was released in February of 2024
* 0.22.0 was released in December of 2023
* 0.21.0 was released in March of 2023
* 0.20.0 was released in September of 2021
* 0.19.0 was released in November of 2020

Therefore 0.23.x and 0.22.x will be updated, while 0.21.x, 0.20.x and 0.19.x
will not be.

> [!NOTE]
> We use the date of `crates.io` publication when evaluating the security
> policy. For example, while the Rustls 0.20.0 GitHub release note was created
> Jul, 2023 the actual release in `crates.io` was published in Sept. 2021.

### Minimum Supported Rust Version

From time to time we will update our minimum supported Rust version (MSRV)
in the course of normal development, subject to these constraints:

- Our MSRV will be no more recent than 9 versions old, or approximately 12 months.

> [!TIP]
> At the time of writing, the most recent Rust release is 1.90.  That means
> our MSRV could be as recent as 1.81. As it happens, it is 1.83.

- Our MSRV policy only covers the core library crate: it does not cover tests
  or example code, and is not binding on our dependencies.

- We do not consider MSRV changes to be breaking for the purposes of semver.

- Once we reach 1.0.0, we will not make MSRV changes in patch releases.
  (Prior to reaching 1.0.0, cargo does not support patch releases.)

- We will not make MSRV changes to security maintenance branches.

> [!NOTE]
> For the avoidance of doubt: security maintenance branches exist for each
> release line _that is not the latest_: so (at the time of writing) 0.22
> and 0.21 have maintenance branches, but 0.23 does not and is released from
> the `main` branch.

#### MSRV of new dependencies

We may take _non-default_ optional new dependencies on a crate with a later
MSRV than this policy.

> [!NOTE]
> This is currently the case for our optional dependency on `zlib-rs`, which
> has a current MSRV of 1.75.

## Reporting a Vulnerability

Before reporting a security bug, make sure to:

- Consider the threat model below. Misconfiguration that is unlikely to happen accidentally is
  unlikely to be a security bug.
- If applicable, compare the behavior to other TLS implementations. If the behavior is consistent
  with other implementations, it is less likely to be a security bug.

Please report security bugs [via github](https://github.com/rustls/rustls/security/advisories/new).
Make sure to disclose any use of AI assistance upfront.

We'll then:

- Prepare a fix and regression tests.
- Backport the fix and make a patch release for most recent release.
- Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db).
- Refer to the advisory on the main README.md and release notes.

If you're *looking* for security bugs, this crate is set up for
`cargo fuzz` but would benefit from more runtime, targets and corpora.

## Threat model

### Scope and assumptions

This library typically sits between raw network I/O and application code.  The network side
is fully attacker-controlled; the application-side is relatively trusted but still aims to be
misuse-resistant.

By "fully attacker-controlled", we specifically include:

- on-path attackers (manipulating traffic to a real, honest peer)
- malicious peers (whether pre- or post-authentication)
- honest but broken peers (again, pre- or post-authentication)

The core `rustls` library is a TLS protocol implementation, and requires additional items to
become useful.  These items are therefore in scope:

- the default certificate verifiers based on `rustls-webpki`.
- the cryptography providers published from the rustls repository (currently `rustls-ring` and `rustls-aws-lc-rs`;
  but not the underlying libraries).

These items are out of scope (security reports for them will be treated as normal bug reports):

- examples, benchmarking and test code,
- code in the `rustls-util` crate
- our public website https://rustls.dev/

### Boundary: network-originated input

Everything arriving from the wire is treated as adversarially crafted. This is the primary attack surface.

Specific threats (non-exhaustive):

- Integer overflow or underflow in length fields,
- Buffer over-read during fragment reassembly,
- Infinite loops, 
- Reachable loops with inappropriate and attacker-controlled complexity, with significant amplification,
- Reachable panics,
- Authentication bypass,
- Protocol downgrade,
- Memory exhaustion or excessive memory consumption, with a significant amplification compared to attacker-controlled input.

Mitigations:

- The entire crate which processes items on this trust boundary is `forbid(unsafe_code)`.  This means all
  code within is the memory safe-subset of Rust.  This ameliorates impact of items like integer overflows (generally
  reducing their impact to denial-of-service), but has little impact on other threats.
- We fuzz this interface, looking for reachable panics.  The project is registered with OSS-Fuzz which provides
  compute for this effort.  Fuzzing is performed with a mock provider of cryptography, which is intended to make
  both pre-auth and post-auth code paths reachable to the fuzzer (at the cost of fuzzing not covering the actual
  cryptography implementations).
- We have [studied and explained](https://rustls.dev/docs/manual/_01_impl_vulnerabilities/index.html#a-review-of-tls-implementation-vulnerabilities)
  issues encountered in other TLS implementations and discuss further mitigations there.
- We implement the TLS 1.3 downgrade sentinel (a [standard and required protocol feature](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3)
  which limits downgrade from TLS 1.3).

### Boundary: cryptography provider

All items under the `CryptoProvider` and associated interfaces are external to the core `rustls`
library, but overall secure operation is contingent on their correct implementation. Specific 
responsibilities are delegated through this interface (non-exhaustive):

- random material generation
- cryptography operations (encryption, decryption, hashing, key agreement, key derivation, signing, verification)
- zeroization of long-term, ephemeral and intermediate secret key material
- side-channel safety of cryptographic operations
- correct error reporting (especially for cases such as signature verification and input validation)

The core `rustls` crate cannot perform securely if these items are faulty, and it is not
a security finding that (for example) rustls does not detect random material generation which produces
the number 4 repeatedly.

In addition, the core `rustls` crate itself:

- performs zeroization of key material values it holds,
- compares secret and public values in constant time,
- correctly propagates and handles errors,
- avoids `Debug` impls on any type that contains secret key material,
- eschews support for problematic protocol features such as RSA encryption, and CBC-mode ciphersuites.

### Boundary: public API

The public API is the interface between the core `rustls` library and application code.
This is a semi-trusted boundary: callers are not treated as adversaries, but the API
aims to be misuse-resistant so that common mistakes do not lead to security failures.

However, application code is not treated as adversarial.  Callers who deliberately work
to undermine their own security (for example, by implementing a custom certificate verifier
that accepts all certificates) are outside the threat model.  Security reports that
require the caller to actively opt in to insecure behavior — through custom configuration
that is unlikely to arise by accident — will be treated as normal bug reports.

Specific threats (non-exhaustive):

- Accidental or inadvertent disabling of essential security controls such as 
  hostname verification or certificate chain validation.
- Accidental or inadvertent exposure of secret key material outside the library.
- Reachable panics from normal sequences of API calls.

Mitigations:

- We make it specifically unfriendly to configure a custom certificate verifier,
  to guide people away from this route of problem solving deployment issues.
- Support for [`SSLKEYLOGFILE`](https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/)
  requires explicit action on the part of the application.
- Avoiding `Debug` impls on any type that contains secret key material.
- In the public API error type, we have items for unreachable conditions, and
  conditions that indicate misuse of the public API.  These are returned instead of panics.
