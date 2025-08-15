#![allow(dead_code)]
#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

pub use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::{ClientConfig, ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientCertVerifierBuilder, ServerConfig, WebPkiClientVerifier};
pub use rustls_test::*;

pub fn server_config_builder(
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    rustls::ServerConfig::builder_with_provider(provider.clone().into())
}

pub fn client_config_builder(
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    rustls::ClientConfig::builder_with_provider(provider.clone().into())
}

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ClientCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiClientVerifier::builder(roots)
    } else {
        WebPkiClientVerifier::builder_with_provider(roots, provider.clone().into())
    }
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ServerCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiServerVerifier::builder(roots)
    } else {
        WebPkiServerVerifier::builder_with_provider(roots, provider.clone().into())
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
