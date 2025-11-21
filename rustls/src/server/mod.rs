pub(crate) mod builder;
pub(crate) mod handy;
mod hs;
mod server_conn;
#[cfg(test)]
mod test;
mod tls12;
mod tls13;

pub use builder::WantsServerCert;
pub use handy::NoServerSessionStorage;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerNameResolver;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerSessionMemoryCache;
#[cfg(feature = "std")]
pub use server_conn::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
pub use server_conn::{
    ClientHello, InvalidSniPolicy, ServerConfig, ServerConnectionData, ServerCredentialResolver,
    StoresServerSessions, UnbufferedServerConnection,
};

pub use crate::verify::NoClientAuth;
pub use crate::webpki::{
    ClientVerifierBuilder, ParsedCertificate, VerifierBuilderError, WebPkiClientVerifier,
};

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use crate::verify::{
        ClientIdentity, ClientVerifier, PeerVerified, SignatureVerificationInput,
    };
}

pub(crate) use hs::ServerHandler;
pub(crate) use tls12::TLS12_HANDLER;
pub(crate) use tls13::TLS13_HANDLER;
