use alloc::vec::Vec;

use super::{ClientCredentialResolver, CredentialRequest};
use crate::compress;
use crate::crypto::{SelectedCredential, SignatureScheme};
use crate::enums::CertificateType;
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificateChain, ProtocolName, ServerExtensions};
use crate::verify::DistinguishedName;

#[derive(Debug)]
pub(super) struct ServerCertDetails {
    pub(super) cert_chain: CertificateChain<'static>,
    pub(super) ocsp_response: Vec<u8>,
}

impl ServerCertDetails {
    pub(super) fn new(cert_chain: CertificateChain<'static>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) alpn_protocols: Vec<ProtocolName>,
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) extension_order_seed: u16,
    pub(super) offered_cert_compression: bool,
}

impl ClientHelloDetails {
    pub(super) fn new(alpn_protocols: Vec<ProtocolName>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
        }
    }

    pub(super) fn server_sent_unsolicited_extensions(
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

pub(super) enum ClientAuthDetails {
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
    pub(super) fn resolve(
        negotiated_type: CertificateType,
        resolver: &dyn ClientCredentialResolver,
        root_hint_subjects: Option<&[DistinguishedName]>,
        signature_schemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let server_hello = CredentialRequest {
            negotiated_type,
            signature_schemes,
            root_hint_subjects: root_hint_subjects.unwrap_or_default(),
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
