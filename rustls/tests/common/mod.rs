#![allow(dead_code)]
#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

pub use std::sync::Arc;

use rustls::client::{ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::{ConstCryptoProvider, CryptoProvider, OwnedCryptoProvider};
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::{RootCertStore, SupportedCipherSuite};
pub use rustls_test::*;

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &dyn CryptoProvider,
) -> ClientCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiClientVerifier::builder(roots)
    } else {
        WebPkiClientVerifier::builder_with_provider(roots, provider)
    }
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &dyn CryptoProvider,
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

pub fn all_versions(provider: &ConstCryptoProvider) -> impl Iterator<Item = OwnedCryptoProvider> {
    vec![
        provider.into_owned().with_only_tls12(),
        provider.into_owned().with_only_tls13(),
    ]
    .into_iter()
}

pub fn provider_with_one_suite(
    provider: &dyn CryptoProvider,
    suite: SupportedCipherSuite,
) -> OwnedCryptoProvider {
    provider_with_suites(provider, &[suite])
}

pub fn provider_with_suites(
    provider: &dyn CryptoProvider,
    suites: &[SupportedCipherSuite],
) -> OwnedCryptoProvider {
    let mut provider = OwnedCryptoProvider {
        tls12_cipher_suites: vec![],
        tls13_cipher_suites: vec![],
        ..OwnedCryptoProvider::new(provider)
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
