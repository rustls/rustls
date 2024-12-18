//! This module provides a hybrid[^1], post-quantum-secure[^2] key exchange
//! algorithm -- specifically [X25519MLKEM768], as well as a non-hybrid
//! post-quantum-secure key exchange algorithm.
//!
//! X25519MLKEM768 is pre-standardization, but is now widely deployed,
//! for example, by [Chrome] and [Cloudflare].
//!
//! You may see unexpected connection failures (such as [tldr.fail])
//! -- [please report these to us][interop-bug].
//!
//! The two components of this key exchange are well regarded:
//! X25519 alone is already used by default by rustls, and tends to have
//! higher quality implementations than other elliptic curves.
//! ML-KEM-768 was standardized by NIST in [FIPS203].
//!
//! [^1]: meaning: a construction that runs a classical and post-quantum
//!       key exchange, and uses the output of both together.  This is a hedge
//!       against the post-quantum half being broken.
//!
//! [^2]: a "post-quantum-secure" algorithm is one posited to be invulnerable
//!       to attack using a cryptographically-relevant quantum computer.  In contrast,
//!       classical algorithms would be broken by such a computer.  Note that such computers
//!       do not currently exist, and may never exist, but current traffic could be captured
//!       now and attacked later.
//!
//! [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
//! [FIPS203]: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>
//! [Chrome]: <https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html>
//! [Cloudflare]: <https://blog.cloudflare.com/pq-2024/#ml-kem-768-and-x25519>
//! [interop-bug]: <https://github.com/rustls/rustls/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=>
//! [tldr.fail]: <https://tldr.fail/>

use crate::crypto::aws_lc_rs::kx_group;
use crate::crypto::SupportedKxGroup;
use crate::{Error, NamedGroup, PeerMisbehaved};

mod hybrid;
mod mlkem;

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: kx_group::X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub static MLKEM768: &dyn SupportedKxGroup = &mlkem::MlKem768;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;
