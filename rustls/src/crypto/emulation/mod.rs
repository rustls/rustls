use crate::{SignatureScheme, SupportedCipherSuite};

use super::{aws_lc_rs, WebPkiSupportedAlgorithms};
use webpki::ring as webpki_algs;

pub static CHROME_CIPHER_SUITES: [SupportedCipherSuite; 16] = [
      aws_lc_rs::cipher_suite::TLS13_RESERVED_GREASE, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
      aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
      aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
      aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
      aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA, // fake cipher suite from the patch
      aws_lc_rs::cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA, // fake cipher suite from the patch
];

pub static CHROME_SIGNATURE_VERIFICATION_ALGOS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
    ],
    mapping: &[
        (
          SignatureScheme::ECDSA_NISTP256_SHA256,
          &[webpki_algs::ECDSA_P256_SHA256],
        ),
        (
          SignatureScheme::RSA_PSS_SHA256,
          &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
          SignatureScheme::RSA_PKCS1_SHA256,
          &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
        (
          SignatureScheme::ECDSA_NISTP384_SHA384,
          &[webpki_algs::ECDSA_P384_SHA384],
        ),
        (
          SignatureScheme::RSA_PSS_SHA384,
          &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
          SignatureScheme::RSA_PKCS1_SHA384,
          &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
          SignatureScheme::RSA_PSS_SHA512,
          &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
          SignatureScheme::RSA_PKCS1_SHA512,
          &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
    ],
};
