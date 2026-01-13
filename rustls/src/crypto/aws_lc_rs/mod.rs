use alloc::borrow::Cow;
use alloc::boxed::Box;

use pki_types::PrivateKeyDer;
use webpki::aws_lc_rs as webpki_algs;

use super::signer::SigningKey;
use crate::crypto::{
    CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SignatureScheme, SupportedKxGroup,
    TicketProducer, TicketerFactory,
};
use crate::error::{Error, OtherError};
use crate::sync::Arc;
#[cfg(feature = "std")]
use crate::ticketer::TicketRotator;
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
use crate::webpki::WebPkiSupportedAlgorithms;

/// Hybrid public key encryption (HPKE).
pub mod hpke;
/// Using software keys for authentication.
pub mod sign;
use sign::{EcdsaSigner, Ed25519Signer, RsaSigningKey};

pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
pub(crate) mod quic;
#[cfg(feature = "std")]
pub(crate) mod ticketer;
#[cfg(feature = "std")]
use ticketer::Rfc5077Ticketer;
pub(crate) mod tls12;
pub(crate) mod tls13;

/// The default `CryptoProvider` backed by aws-lc-rs.
pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(DEFAULT_TLS12_CIPHER_SUITES),
    tls13_cipher_suites: Cow::Borrowed(DEFAULT_TLS13_CIPHER_SUITES),
    kx_groups: Cow::Borrowed(DEFAULT_KX_GROUPS),
    signature_verification_algorithms: SUPPORTED_SIG_ALGS,
    secure_random: &AwsLcRs,
    key_provider: &AwsLcRs,
    ticketer_factory: &AwsLcRs,
};

/// The default `CryptoProvider` backed by aws-lc-rs that only supports TLS1.3.
pub const DEFAULT_TLS13_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// The default `CryptoProvider` backed by aws-lc-rs that only supports TLS1.2.
///
/// Use of TLS1.3 is **strongly** recommended.
pub const DEFAULT_TLS12_PROVIDER: CryptoProvider = CryptoProvider {
    tls13_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// `KeyProvider` impl for aws-lc-rs
pub static DEFAULT_KEY_PROVIDER: &dyn KeyProvider = &AwsLcRs;

/// `SecureRandom` impl for aws-lc-rs
pub static DEFAULT_SECURE_RANDOM: &dyn SecureRandom = &AwsLcRs;

#[derive(Debug)]
struct AwsLcRs;

impl SecureRandom for AwsLcRs {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        use aws_lc_rs::rand::SecureRandom;

        aws_lc_rs::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips()
    }
}

impl KeyProvider for AwsLcRs {
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

    fn fips(&self) -> bool {
        fips()
    }
}

impl TicketerFactory for AwsLcRs {
    /// Make the recommended `Ticketer`.
    ///
    /// This produces tickets:
    ///
    /// - where each lasts for at least 6 hours,
    /// - with randomly generated keys, and
    /// - where keys are rotated every 6 hours.
    ///
    /// The `Ticketer` uses the [RFC 5077 §4] "Recommended Ticket Construction",
    /// using AES 256 for encryption and HMAC-SHA256 for ciphertext authentication.
    ///
    /// [RFC 5077 §4]: https://www.rfc-editor.org/rfc/rfc5077#section-4
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        #[cfg(feature = "std")]
        {
            Ok(Arc::new(TicketRotator::new(
                TicketRotator::SIX_HOURS,
                Rfc5077Ticketer::new,
            )?))
        }
        #[cfg(not(feature = "std"))]
        {
            Err(Error::General(
                "AwsLcRs::ticketer() relies on std-only RwLock via TicketRotator".into(),
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
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(not(feature = "fips"))]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(not(feature = "fips"))]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.3 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS13_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    #[cfg(not(feature = "fips"))]
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.2 cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.3 cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
];

/// All defined cipher suites supported by aws-lc-rs appear in this module.
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
/// compiled against aws-lc-rs.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P256_SHA512,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ECDSA_P384_SHA512,
        webpki_algs::ECDSA_P521_SHA256,
        webpki_algs::ECDSA_P521_SHA384,
        webpki_algs::ECDSA_P521_SHA512,
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
                webpki_algs::ECDSA_P521_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
                webpki_algs::ECDSA_P521_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[
                webpki_algs::ECDSA_P521_SHA512,
                webpki_algs::ECDSA_P384_SHA512,
                webpki_algs::ECDSA_P256_SHA512,
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

/// All defined key exchange groups supported by aws-lc-rs appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
/// [`DEFAULT_KX_GROUPS`] is provided as an array of this provider's defaults.
pub mod kx_group {
    pub use super::kx::{
        MLKEM768, SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519, X25519MLKEM768,
    };
}

/// A list of the default key exchange groups supported by this provider.
///
/// This does not contain MLKEM768; by default MLKEM768 is only offered
/// in hybrid with X25519.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    #[cfg(not(feature = "fips"))]
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

/// A list of all the key exchange groups supported by this provider.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::SECP256R1MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
    kx_group::MLKEM768,
];

/// Compatibility shims between ring 0.16.x and 0.17.x API
mod ring_shim {
    use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};

    use crate::crypto::kx::SharedSecret;

    pub(super) fn agree_ephemeral(
        priv_key: EphemeralPrivateKey,
        peer_key: &UnparsedPublicKey<&[u8]>,
    ) -> Result<SharedSecret, ()> {
        agreement::agree_ephemeral(priv_key, peer_key, (), |secret| {
            Ok(SharedSecret::from(secret))
        })
    }
}

/// Are we in FIPS mode?
pub(super) fn fips() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

pub(super) fn unspecified_err(e: aws_lc_rs::error::Unspecified) -> Error {
    Error::Other(OtherError::new(e))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[cfg(feature = "fips")]
    #[test]
    fn default_suites_are_fips() {
        assert!(
            super::DEFAULT_TLS12_CIPHER_SUITES
                .iter()
                .all(|scs| scs.fips())
        );
        assert!(
            super::DEFAULT_TLS13_CIPHER_SUITES
                .iter()
                .all(|scs| scs.fips())
        );
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_suites() {
        assert_eq!(
            super::DEFAULT_TLS12_CIPHER_SUITES,
            super::ALL_TLS12_CIPHER_SUITES
        );
        assert_eq!(
            super::DEFAULT_TLS13_CIPHER_SUITES,
            super::ALL_TLS13_CIPHER_SUITES
        );
    }

    #[test]
    fn certificate_sig_algs() {
        // `all` should not contain duplicates (not incorrect, but a waste of time)
        assert_eq!(
            super::SUPPORTED_SIG_ALGS
                .all
                .iter()
                .map(|alg| {
                    (
                        alg.public_key_alg_id()
                            .as_ref()
                            .to_vec(),
                        alg.signature_alg_id().as_ref().to_vec(),
                    )
                })
                .collect::<HashSet<_>>()
                .len(),
            super::SUPPORTED_SIG_ALGS.all.len(),
        );
    }
}
