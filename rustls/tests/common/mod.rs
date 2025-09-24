#![allow(dead_code)]
#![allow(clippy::disallowed_types)]

use std::borrow::Cow;
pub use std::sync::Arc;

use rustls::client::{ServerVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientVerifierBuilder, WebPkiClientVerifier};
use rustls::{RootCertStore, SupportedCipherSuite};

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ClientVerifierBuilder {
    if exactly_one_provider() {
        WebPkiClientVerifier::builder(roots)
    } else {
        WebPkiClientVerifier::builder_with_provider(roots, provider)
    }
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ServerVerifierBuilder {
    if exactly_one_provider() {
        WebPkiServerVerifier::builder(roots)
    } else {
        WebPkiServerVerifier::builder_with_provider(roots, provider)
    }
}

fn exactly_one_provider() -> bool {
    cfg!(any(
        all(feature = "ring", not(feature = "aws-lc-rs")),
        all(feature = "aws-lc-rs", not(feature = "ring"))
    ))
}

pub fn provider_with_one_suite(
    provider: &CryptoProvider,
    suite: SupportedCipherSuite,
) -> CryptoProvider {
    provider_with_suites(provider, &[suite])
}

pub fn provider_with_suites(
    provider: &CryptoProvider,
    suites: &[SupportedCipherSuite],
) -> CryptoProvider {
    let mut tls12_cipher_suites = vec![];
    let mut tls13_cipher_suites = vec![];

    for suite in suites {
        match suite {
            SupportedCipherSuite::Tls12(suite) => {
                tls12_cipher_suites.push(*suite);
            }
            SupportedCipherSuite::Tls13(suite) => {
                tls13_cipher_suites.push(*suite);
            }
            _ => unreachable!(),
        }
    }
    CryptoProvider {
        tls12_cipher_suites: Cow::Owned(tls12_cipher_suites),
        tls13_cipher_suites: Cow::Owned(tls13_cipher_suites),
        ..provider.clone()
    }
}
