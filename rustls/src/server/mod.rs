pub use crate::verify::NoClientAuth;
pub use crate::webpki::{
    ClientVerifierBuilder, ParsedCertificate, VerifierBuilderError, WebPkiClientVerifier,
};

pub(crate) mod config;
pub use config::{
    ClientHello, InvalidSniPolicy, ServerConfig, ServerCredentialResolver, StoresServerSessions,
    WantsServerCert,
};

pub(crate) mod handy;
pub use handy::NoServerSessionStorage;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerNameResolver;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerSessionMemoryCache;

mod hs;
pub(crate) use hs::ServerHandler;

mod server_conn;
#[cfg(feature = "std")]
pub use server_conn::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
pub use server_conn::{ServerConnectionData, UnbufferedServerConnection};

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use crate::verify::{
        ClientIdentity, ClientVerifier, PeerVerified, SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;
