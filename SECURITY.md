# Security Policy

## Supported Versions

Security fixes will be backported to the most recent three minor version lines.

## Reporting a Vulnerability

Please report security bugs by email to rustls-security@googlegroups.com.
We'll then:

- Prepare a fix and regression tests.
- Backport the fix and make a patch release for most recent release.
- Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db).
- Refer to the advisory on the main README.md and release notes.

If you're *looking* for security bugs, this crate is set up for
`cargo fuzz` but would benefit from more runtime, targets and corpora.
