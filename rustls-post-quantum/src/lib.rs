//! This crate provides a [`rustls::crypto::CryptoProvider`] that includes
//! a hybrid[^1], post-quantum-secure[^2] key exchange algorithm --
//! specifically [X25519MLKEM768], as well as a non-hybrid
//! post-quantum-secure key exchange algorithm.
//!
//! X25519MLKEM768 is pre-standardization, so you should treat
//! this as experimental.  You may see unexpected connection failures (such as [tldr.fail])
//! -- [please report these to us][interop-bug].  X25519MLKEM768 is becoming widely
//! deployed, eg, by [Chrome] and [Cloudflare].
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
//!
//!
//! # How to use this crate
//!
//! There are a few options:
//!
//! **To use this as the rustls default provider**: include this code early in your program:
//!
//! ```rust
//! rustls_post_quantum::provider().install_default().unwrap();
//! ```
//!
//! **To incorporate just the key exchange algorithm(s) in a custom [`rustls::crypto::CryptoProvider`]**:
//!
//! ```rust
//! use rustls::crypto::{aws_lc_rs, CryptoProvider};
//! let parent = aws_lc_rs::default_provider();
//! let my_provider = CryptoProvider {
//!     kx_groups: vec![
//!         rustls_post_quantum::X25519MLKEM768,
//!         aws_lc_rs::kx_group::X25519,
//!         rustls_post_quantum::MLKEM768,
//!     ],
//!     ..parent
//! };
//! ```
//!

use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

mod hybrid;
mod mlkem;

/// A `CryptoProvider` which includes `X25519MLKEM768` and `MLKEM768`
/// key exchanges.
pub fn provider() -> CryptoProvider {
    let mut parent = default_provider();

    parent
        .kx_groups
        .splice(0..0, [X25519MLKEM768, MLKEM768]);

    parent
}

/// XXX
pub fn provider_no_optimization() -> CryptoProvider {
    let mut parent = default_provider();

    parent
        .kx_groups
        .splice(0..0, [UNOPTIMIZED_X25519_MLKEM768, MLKEM768]);

    parent
}

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

static UNOPTIMIZED_X25519_MLKEM768: &dyn SupportedKxGroup = &Unoptimized;

#[derive(Debug)]
struct Unoptimized;

impl SupportedKxGroup for Unoptimized {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, Error> {
        Ok(Box::new(UnoptimizedActive {
            hybrid: X25519MLKEM768.start()?,
            separate: kx_group::X25519.start()?,
        }))
    }

    fn start_and_complete(
        &self,
        client_share: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
        X25519MLKEM768.start_and_complete(client_share)
    }

    fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
        version == rustls::ProtocolVersion::TLSv1_3
    }

    fn name(&self) -> NamedGroup {
        X25519MLKEM768.name()
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        X25519MLKEM768.ffdhe_group()
    }
}

struct UnoptimizedActive {
    hybrid: Box<dyn rustls::crypto::ActiveKeyExchange>,
    separate: Box<dyn rustls::crypto::ActiveKeyExchange>,
}

impl rustls::crypto::ActiveKeyExchange for UnoptimizedActive {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<rustls::crypto::SharedSecret, Error> {
        self.hybrid.complete(peer)
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, Error> {
        self.separate.complete(peer)
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.separate.group(), self.separate.pub_key()))
    }

    fn group(&self) -> NamedGroup {
        self.hybrid.group()
    }

    fn pub_key(&self) -> &[u8] {
        self.hybrid.pub_key()
    }
}

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;
