//! A `CryptoProvider` implementation backed by *ring*.

#![no_std]
#![warn(clippy::exhaustive_enums, clippy::exhaustive_structs, missing_docs)]
#![cfg_attr(bench, feature(test))]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

// Import `test` sysroot crate for `Bencher` definitions.
#[cfg(bench)]
#[expect(unused_extern_crates)]
extern crate test;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::time::Duration;

use pki_types::PrivateKeyDer;
use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SignatureScheme, SigningKey,
    TicketProducer, TicketerFactory, WebPkiSupportedAlgorithms,
};
use rustls::error::Error;
#[cfg(feature = "std")]
use rustls::ticketer::TicketRotator;
use rustls::{Tls12CipherSuite, Tls13CipherSuite};
use webpki::ring as webpki_algs;

/// Using software keys for authentication.
pub mod sign;
use sign::{EcdsaSigner, Ed25519Signer, RsaSigningKey};

pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
pub(crate) mod quic;
pub(crate) mod ticketer;
#[cfg(feature = "std")]
use ticketer::AeadTicketer;
pub(crate) mod tls12;
pub(crate) mod tls13;

/// The default `CryptoProvider` backed by [*ring*].
///
/// [*ring*]: https://github.com/briansmith/ring
pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(DEFAULT_TLS12_CIPHER_SUITES),
    tls13_cipher_suites: Cow::Borrowed(DEFAULT_TLS13_CIPHER_SUITES),
    kx_groups: Cow::Borrowed(DEFAULT_KX_GROUPS),
    signature_verification_algorithms: SUPPORTED_SIG_ALGS,
    secure_random: &Ring,
    key_provider: &Ring,
    ticketer_factory: &Ring,
};

/// The default `CryptoProvider` backed by *ring* that only supports TLS1.3.
pub const DEFAULT_TLS13_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// The default `CryptoProvider` backed by *ring* that only supports TLS1.2.
///
/// Use of TLS1.3 is **strongly** recommended.
pub const DEFAULT_TLS12_PROVIDER: CryptoProvider = CryptoProvider {
    tls13_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// Default crypto provider.
#[derive(Debug)]
struct Ring;

impl SecureRandom for Ring {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Ring {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        if let Ok(rsa) = RsaSigningKey::try_from(&key_der) {
            return Ok(Box::new(rsa));
        }

        if let Ok(ecdsa) = EcdsaSigner::try_from(&key_der) {
            return Ok(Box::new(ecdsa));
        }

        if let PrivateKeyDer::Pkcs8(pkcs8) = key_der {
            if let Ok(eddsa) = Ed25519Signer::try_from(&pkcs8) {
                return Ok(Box::new(eddsa));
            }
        }

        Err(Error::General(
            "failed to parse private key as RSA, ECDSA, or EdDSA".into(),
        ))
    }
}

impl TicketerFactory for Ring {
    /// Make the recommended `Ticketer`.
    ///
    /// This produces tickets:
    ///
    /// - where each lasts for at least 6 hours,
    /// - with randomly generated keys, and
    /// - where keys are rotated every 6 hours.
    ///
    /// The encryption mechanism used is Chacha20Poly1305.
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        #[cfg(feature = "std")]
        {
            Ok(Arc::new(TicketRotator::new(SIX_HOURS, AeadTicketer::new)?))
        }
        #[cfg(not(feature = "std"))]
        {
            Err(Error::General(
                "Ring::ticketer() relies on std-only RwLock via TicketRotator".into(),
            ))
        }
    }

    fn fips(&self) -> bool {
        fips()
    }
}

/// The TLS1.2 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS12_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = ALL_TLS12_CIPHER_SUITES;

/// A list of all the TLS1.2 cipher suites supported by the rustls *ring* provider.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.3 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS13_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = ALL_TLS13_CIPHER_SUITES;

/// A list of all the TLS1.3 cipher suites supported by the rustls *ring* provider.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
];

/// All defined cipher suites supported by *ring* appear in this module.
pub mod cipher_suite {
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against *ring*.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

/// All defined key exchange groups supported by *ring* appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
/// [`DEFAULT_KX_GROUPS`] is provided as an array of this provider's defaults.
pub mod kx_group {
    pub use super::kx::{SECP256R1, SECP384R1, X25519};
}

/// A list of the default key exchange groups supported by this provider.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = ALL_KX_GROUPS;

/// A list of all the key exchange groups supported by this provider.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];

/// Compatibility shims between ring 0.16.x and 0.17.x API
mod ring_shim {
    use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
    use rustls::crypto::kx::SharedSecret;

    pub(super) fn agree_ephemeral(
        priv_key: EphemeralPrivateKey,
        peer_key: &UnparsedPublicKey<&[u8]>,
    ) -> Result<SharedSecret, ()> {
        agreement::agree_ephemeral(priv_key, peer_key, |secret| SharedSecret::from(secret))
            .map_err(|_| ())
    }
}

/// Return `true` if this is backed by a FIPS-approved implementation.
pub fn fips() -> bool {
    false
}

const SIX_HOURS: Duration = Duration::from_secs(6 * 60 * 60);
