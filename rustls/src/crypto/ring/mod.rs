use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::rand::GetRandomFailed;
use crate::suites::SupportedCipherSuite;

pub(crate) use ring as ring_like;
use ring_like::rand::{SecureRandom, SystemRandom};

/// Using software keys for authentication.
pub mod sign;

pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
#[cfg(feature = "quic")]
pub(crate) mod quic;
pub(crate) mod ticketer;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;

/// A `CryptoProvider` backed by the [*ring*] crate.
///
/// [*ring*]: https://github.com/briansmith/ring
pub static RING: &dyn CryptoProvider = &Ring;

/// Default crypto provider.
#[derive(Debug)]
struct Ring;

impl CryptoProvider for Ring {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        DEFAULT_CIPHER_SUITES
    }

    /// Return all supported key exchange groups.
    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        ALL_KX_GROUPS
    }
}

/// The cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// A list of all the cipher suites supported by the rustls *ring* provider.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// All defined cipher suites supported by *ring* appear in this module.
pub mod cipher_suite {
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// All defined key exchange groups supported by *ring* appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
pub mod kx_group {
    pub use super::kx::SECP256R1;
    pub use super::kx::SECP384R1;
    pub use super::kx::X25519;
}

pub use kx::ALL_KX_GROUPS;
pub use ticketer::Ticketer;
