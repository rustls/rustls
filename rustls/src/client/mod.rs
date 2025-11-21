pub(super) mod builder;
mod client_conn;
mod common;
mod ech;
pub(super) mod handy;
mod hs;
#[cfg(test)]
mod test;
mod tls12;
mod tls13;

pub use builder::WantsClientCert;
pub use client_conn::{
    ClientConfig, ClientConnectionData, ClientCredentialResolver, ClientSessionStore,
    CredentialRequest, EarlyDataError, MayEncryptEarlyData, Resumption, Tls12Resumption,
    UnbufferedClientConnection,
};
#[cfg(feature = "std")]
pub use client_conn::{ClientConnection, WriteEarlyData};
pub use ech::{EchConfig, EchGreaseConfig, EchMode, EchStatus};
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ClientSessionMemoryCache;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use super::builder::danger::DangerousClientConfigBuilder;
    pub use super::client_conn::danger::DangerousClientConfig;
    pub use crate::verify::{
        HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
        SignatureVerificationInput,
    };
}

pub(crate) use hs::ClientHandler;
pub(crate) use tls12::TLS12_HANDLER;
pub(crate) use tls13::TLS13_HANDLER;

pub use crate::msgs::persist::{Tls12ClientSessionValue, Tls13ClientSessionValue};
pub use crate::webpki::{
    ServerVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
    verify_identity_signed_by_trust_anchor, verify_server_name,
};
