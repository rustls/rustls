use alloc::vec::Vec;

use crate::compress;
use crate::crypto::{SelectedCredential, SignatureScheme};
use crate::enums::CertificateType;
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificateChain, ProtocolName, ServerExtensions};
pub use crate::msgs::persist::{Tls12ClientSessionValue, Tls13ClientSessionValue};
use crate::verify::DistinguishedName;
pub use crate::webpki::{
    ServerVerifierBuilder, VerifierBuilderError, WebPkiServerVerifier,
    verify_identity_signed_by_trust_anchor, verify_server_name,
};

mod config;
pub use config::{
    ClientConfig, ClientCredentialResolver, ClientSessionKey, ClientSessionStore,
    CredentialRequest, Resumption, Tls12Resumption, WantsClientCert,
};

mod connection;
#[cfg(feature = "std")]
pub use connection::{ClientConnection, WriteEarlyData};
pub use connection::{
    ClientConnectionData, EarlyDataError, MayEncryptEarlyData, UnbufferedClientConnection,
};

mod ech;
pub use ech::{EchConfig, EchGreaseConfig, EchMode, EchStatus};

mod handy;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use handy::ClientSessionMemoryCache;

mod hs;
pub(crate) use hs::ClientHandler;

mod tls12;
pub(crate) use tls12::TLS12_HANDLER;

mod tls13;
pub(crate) use tls13::TLS13_HANDLER;

mod state;
pub use state::{
    AwaitServerFlight, ClientState, ProvideCredential, ReceiveTraffic, ReceivedApplicationData,
    ReceivedTrafficState, SendClientFlight, SendEarlyData, SendTraffic, VerifyServerIdentity,
};

/// Dangerous configuration that should be audited and used with extreme care.
pub mod danger {
    pub use super::config::danger::{DangerousClientConfig, DangerousClientConfigBuilder};
    pub use crate::verify::{
        HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
        SignatureVerificationInput,
    };
}

#[cfg(test)]
mod test;

#[derive(Debug)]
struct ServerCertDetails {
    cert_chain: CertificateChain<'static>,
    ocsp_response: Vec<u8>,
}

impl ServerCertDetails {
    fn new(cert_chain: CertificateChain<'static>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }
}

struct ClientHelloDetails {
    alpn_protocols: Vec<ProtocolName>,
    sent_extensions: Vec<ExtensionType>,
    extension_order_seed: u16,
    offered_cert_compression: bool,
}

impl ClientHelloDetails {
    fn new(alpn_protocols: Vec<ProtocolName>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
        }
    }

    fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &ServerExtensions<'_>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        let mut extensions = received_exts.collect_used();
        extensions.extend(
            received_exts
                .unknown_extensions
                .iter()
                .map(|ext| ExtensionType::from(*ext)),
        );
        for ext_type in extensions {
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        credentials: SelectedCredential,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    },
}

impl ClientAuthDetails {
    fn resolve(
        negotiated_type: CertificateType,
        resolver: &dyn ClientCredentialResolver,
        root_hint_subjects: Option<&[DistinguishedName]>,
        signature_schemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let server_hello = CredentialRequest {
            negotiated_type,
            root_hint_subjects: root_hint_subjects.unwrap_or_default(),
            signature_schemes,
        };

        if let Some(credentials) = resolver.resolve(&server_hello) {
            debug!("Attempting client auth");
            return Self::Verify {
                credentials,
                auth_context_tls13,
                compressor,
            };
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}
