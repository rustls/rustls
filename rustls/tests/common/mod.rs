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
    // ensure `ServerConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(provider::provider().into())`.
    if exactly_one_provider() {
        rustls::ServerConfig::builder()
    } else {
        rustls::ServerConfig::builder_with_provider(provider.clone().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn server_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    if exactly_one_provider() {
        rustls::ServerConfig::builder_with_protocol_versions(versions)
    } else {
        rustls::ServerConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(versions)
            .unwrap()
    }
}

pub fn client_config_builder(
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    // ensure `ClientConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(provider::provider().into())`.
    if exactly_one_provider() {
        rustls::ClientConfig::builder()
    } else {
        rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn client_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    if exactly_one_provider() {
        rustls::ClientConfig::builder_with_protocol_versions(versions)
    } else {
        rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(versions)
            .unwrap()
    }
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
