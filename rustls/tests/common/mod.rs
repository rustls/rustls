#![allow(dead_code)]
#![allow(clippy::disallowed_types)]

pub use std::sync::Arc;

use rustls::client::{ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::{RootCertStore, SupportedCipherSuite};

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ClientCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiClientVerifier::builder(roots)
    } else {
        WebPkiClientVerifier::builder_with_provider(roots, provider)
    }
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ServerCertVerifierBuilder {
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

pub fn all_versions(provider: &CryptoProvider) -> impl Iterator<Item = CryptoProvider> {
    vec![
        provider.clone().with_only_tls12(),
        provider.clone().with_only_tls13(),
    ]
    .into_iter()
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
    let mut provider = CryptoProvider {
        tls12_cipher_suites: vec![],
        tls13_cipher_suites: vec![],
        ..provider.clone()
    };
    for suite in suites {
        match suite {
            SupportedCipherSuite::Tls12(suite) => {
                provider.tls12_cipher_suites.push(suite);
            }
            SupportedCipherSuite::Tls13(suite) => {
                provider.tls13_cipher_suites.push(suite);
            }
            _ => unreachable!(),
        }
    }
    provider
}
