//! This crate provide a [`CryptoProvider`] built on the default aws-lc-rs default provider.
//!
//! Features:
//!
//! - `aws-lc-rs-unstable`: adds support for three variants of the experimental ML-DSA signature
//!   algorithm.
//!
//! Before rustls 0.23.22, this crate additionally provided support for the ML-KEM key exchange
//! (both "pure" and hybrid variants), but these have been moved to the rustls crate itself.
//! In rustls 0.23.22 and later, you can use rustls' `prefer-post-quantum` feature to determine
//! whether the ML-KEM key exchange is preferred over non-post-quantum key exchanges.

#[cfg(feature = "aws-lc-rs-unstable")]
use rustls::SignatureScheme;
use rustls::crypto::CryptoProvider;
#[cfg(feature = "aws-lc-rs-unstable")]
use rustls::crypto::WebPkiSupportedAlgorithms;
pub use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};
#[cfg(feature = "aws-lc-rs-unstable")]
use webpki::aws_lc_rs as webpki_algs;

pub fn provider() -> CryptoProvider {
    #[cfg_attr(not(feature = "aws-lc-rs-unstable"), allow(unused_mut))]
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "aws-lc-rs-unstable")]
    {
        provider.signature_verification_algorithms = SUPPORTED_SIG_ALGS;
    }
    provider
}

/// Keep in sync with the `SUPPORTED_SIG_ALGS` in `rustls::crypto::aws_lc_rs`.
#[cfg(feature = "aws-lc-rs-unstable")]
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
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
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_44,
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_65,
        #[cfg(feature = "aws-lc-rs-unstable")]
        webpki_algs::ML_DSA_87,
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
            &[webpki_algs::ECDSA_P521_SHA512],
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
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_44, &[webpki_algs::ML_DSA_44]),
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_65, &[webpki_algs::ML_DSA_65]),
        #[cfg(feature = "aws-lc-rs-unstable")]
        (SignatureScheme::ML_DSA_87, &[webpki_algs::ML_DSA_87]),
    ],
};
