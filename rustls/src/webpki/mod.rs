mod anchors;
mod client_verifier_builder;
mod verify;

pub use anchors::{OwnedTrustAnchor, RootCertStore};

pub use client_verifier_builder::{ClientCertVerifierBuilder, ClientCertVerifierBuilderError};

pub use verify::{UnparsedCertRevocationList, WebPkiClientVerifier, WebPkiSupportedAlgorithms};

// Conditionally exported from crate.
#[allow(unreachable_pub)]
pub use verify::{
    verify_server_cert_signed_by_trust_anchor, verify_server_name, ParsedCertificate,
    WebPkiServerVerifier,
};
