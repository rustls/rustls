use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::enums::SignatureScheme;
use crate::rand::GetRandomFailed;
use crate::sign::SigningKey;
use crate::suites::SupportedCipherSuite;
use crate::webpki::WebPkiSupportedAlgorithms;
use crate::Error;

use pki_types::PrivateKeyDer;
use webpki::ring as webpki_algs;

use alloc::borrow::ToOwned;
use alloc::sync::Arc;

pub(crate) use ring as ring_like;

/// Using software keys for authentication.
pub mod sign;

pub(crate) mod hash;
pub(crate) mod hmac;
pub(crate) mod kx;
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
        use ring_like::rand::SecureRandom;

        ring_like::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [SupportedCipherSuite] {
        DEFAULT_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn SupportedKxGroup] {
        ALL_KX_GROUPS
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
            .map_err(|_| Error::General("invalid private key".to_owned()))
    }

    fn signature_verification_algorithms(&self) -> WebPkiSupportedAlgorithms {
        SUPPORTED_SIG_ALGS
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
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme. for TLS1.3 it is.
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
pub mod kx_group {
    pub use super::kx::SECP256R1;
    pub use super::kx::SECP384R1;
    pub use super::kx::X25519;
}

pub use kx::ALL_KX_GROUPS;
pub use ticketer::Ticketer;

/// Compatibility shims between ring 0.16.x and 0.17.x API
mod ring_shim {
    use super::ring_like;
    use crate::crypto::SharedSecret;

    pub(super) fn agree_ephemeral(
        priv_key: ring_like::agreement::EphemeralPrivateKey,
        peer_key: &ring_like::agreement::UnparsedPublicKey<&[u8]>,
    ) -> Result<SharedSecret, ()> {
        ring_like::agreement::agree_ephemeral(priv_key, peer_key, |secret| {
            SharedSecret::from(secret)
        })
        .map_err(|_| ())
    }

    pub(super) fn rsa_key_pair_public_modulus_len(kp: &ring_like::signature::RsaKeyPair) -> usize {
        kp.public().modulus_len()
    }

    pub(super) fn ecdsa_key_pair_from_pkcs8(
        alg: &'static ring_like::signature::EcdsaSigningAlgorithm,
        data: &[u8],
        rng: &dyn ring_like::rand::SecureRandom,
    ) -> Result<ring_like::signature::EcdsaKeyPair, ()> {
        ring_like::signature::EcdsaKeyPair::from_pkcs8(alg, data, rng).map_err(|_| ())
    }
}
