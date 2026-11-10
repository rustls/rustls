# Wycheproof HPKE test vectors

The JSON files in this directory are unmodified copies of the HPKE test vectors
from the [Wycheproof] project's `testvectors_v1/` directory, taken at commit
`d5f724a21e449bbf8f142e032a6bf86884f2851c`. The upstream `doc/hpke.md`
describes how each file applies to an implementation.

Only the DHKEM(X25519, HKDF-SHA256) vectors are vendored. The upstream ML-KEM
vectors cover KEMs that no rustls HPKE implementation supports. The vectors
are exercised by the `rustls-aws-lc-rs` HPKE unit tests.

[Wycheproof]: https://github.com/C2SP/wycheproof
