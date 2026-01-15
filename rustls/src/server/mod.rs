pub use crate::verify::NoClientAuth;
pub use crate::webpki::{
    ClientVerifierBuilder, ParsedCertificate, VerifierBuilderError, WebPkiClientVerifier,
};

pub(crate) mod config;
pub use config::{
    ClientHello, InvalidSniPolicy, ServerConfig, ServerCredentialResolver, StoresServerSessions,
    WantsServerCert,
};

mod connection;
#[cfg(feature = "std")]
pub use connection::{Accepted, AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};
pub use connection::{ServerSide, UnbufferedServerConnection};

pub(crate) mod handy;
pub use handy::NoServerSessionStorage;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerNameResolver;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ServerSessionMemoryCache;

mod hs;
pub(crate) use hs::ServerHandler;

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
