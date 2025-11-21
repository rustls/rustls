pub use crate::msgs::persist::{Tls12ClientSessionValue, Tls13ClientSessionValue};
pub use crate::webpki::{
    ServerVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
    verify_identity_signed_by_trust_anchor, verify_server_name,
};

mod client_conn;
pub use client_conn::{
    ClientConfig, ClientConnectionData, ClientCredentialResolver, ClientSessionStore,
    CredentialRequest, EarlyDataError, MayEncryptEarlyData, Resumption, Tls12Resumption,
    UnbufferedClientConnection,
};
#[cfg(feature = "std")]
pub use client_conn::{ClientConnection, WriteEarlyData};

mod common;

pub(super) mod config;
pub use config::WantsClientCert;

mod ech;
pub use ech::{EchConfig, EchGreaseConfig, EchMode, EchStatus};

pub(super) mod handy;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ClientSessionMemoryCache;

mod hs;
pub(crate) use hs::ClientHandler;

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use super::client_conn::danger::DangerousClientConfig;
    pub use super::config::danger::DangerousClientConfigBuilder;
    pub use crate::verify::{
        HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
        SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;
