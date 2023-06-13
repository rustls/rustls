# Security Policy

## Supported Versions

Security fixes will be backported only to the rustls versions for which the
original semver-compatible release was published less than 2 years ago.

For example, as of 2023-06-13 the latest release is 0.21.1.

* 0.21.0 was released in March of 2023
* 0.20.0 was released in September of 2021
* 0.19.0 was released in November of 2020

Therefore 0.20.x and 0.21.x will be updated, while 0.19.x will not be.

## Reporting a Vulnerability

Please report security bugs by email to rustls-security@googlegroups.com.
We'll then:

- Prepare a fix and regression tests.
- Backport the fix and make a patch release for most recent release.
- Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db).
- Refer to the advisory on the main README.md and release notes.

If you're *looking* for security bugs, this crate is set up for
`cargo fuzz` but would benefit from more runtime, targets and corpora.
