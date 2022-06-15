use super::{ResolvesClientCert, ServerName};
#[cfg(feature = "tls12")]
use crate::conn::ConnectionRandoms;
use crate::hash_hs::HandshakeHash;
use crate::key::Certificate;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificatePayload, SCTList, ServerExtension};
use crate::verify::construct_tls13_server_verify_message;
#[cfg(feature = "tls12")]
use crate::version::{TLS12, TLS13};
#[cfg(feature = "tls12")]
use crate::SupportedProtocolVersion;
use crate::{sign, DigitallySignedStruct, DistinguishedNames, SignatureScheme};

use std::sync::Arc;
use std::time::SystemTime;

/// Input for server certificate and signature verification.
///
/// This is used as input for the `ServerCertVerifier::verify()` method.
#[allow(unreachable_pub)] // conditional on `cfg(feature = "dangerous_configuration")`
pub struct ServerVerifyInput<'a> {
    /// Certificate for the end entity.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementor to handle invalid data. It is recommended that the implementor returns
    /// [`crate::Error::InvalidCertificateEncoding`] when these cases are encountered.
    pub end_entity: &'a Certificate,
    /// Intermediate certificates the client sent along with the end-entity certificate.
    ///
    /// It is in the same order that the peer sent them and may be empty.
    ///
    /// Note that none of the certificates have been parsed yet, so it is the responsibility of
    /// the implementor to handle invalid data. It is recommended that the implementor returns
    /// [`crate::Error::InvalidCertificateEncoding`] when these cases are encountered.
    pub intermediates: &'a [Certificate],
    /// The server name the certificate should be valid for.
    pub server_name: &'a ServerName,
    /// The time at which the certificate must be valid.
    pub now: SystemTime,
    /// The certificate's signature.
    pub server_signature: &'a DigitallySignedStruct,
    pub(crate) details: &'a ServerCertDetails,
    pub(crate) version: ServerVerifyVersionInput<'a>,
}

#[allow(unreachable_pub)] // conditional on `cfg(feature = "dangerous_configuration")`
impl<'a> ServerVerifyInput<'a> {
    /// Construct the signature message that the server should have signed
    pub fn server_verify_message(&self) -> Vec<u8> {
        use ServerVerifyVersionInput::*;
        match self.version {
            #[cfg(feature = "tls12")]
            Tls12 { randoms, kx_params } => {
                // Build up the contents of the signed message.
                // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
                let mut message = Vec::new();
                message.extend_from_slice(&randoms.client);
                message.extend_from_slice(&randoms.server);
                message.extend_from_slice(kx_params);
                message
            }
            Tls13 { transcript } => {
                // Constructs the signature message specified in section 4.4.3 of RFC8446
                let handshake_hash = transcript.get_current_hash();
                construct_tls13_server_verify_message(&handshake_hash)
            }
        }
    }

    /// Signed Certificate Timestamps (SCTs) provided by the server, if any.
    pub fn scts(&self) -> impl Iterator<Item = &[u8]> {
        self.details
            .scts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|payload| payload.0.as_slice())
    }

    /// OCSP response received from the server.
    #[inline]
    pub fn ocsp_response(&self) -> &[u8] {
        &self.details.ocsp_response
    }

    /// Protocol version for the handshake.
    #[cfg(feature = "tls12")]
    #[inline]
    pub fn version(&self) -> &'static SupportedProtocolVersion {
        match self.version {
            #[cfg(feature = "tls12")]
            ServerVerifyVersionInput::Tls12 { .. } => &TLS12,
            ServerVerifyVersionInput::Tls13 { .. } => &TLS13,
        }
    }
}

pub(crate) enum ServerVerifyVersionInput<'a> {
    #[cfg(feature = "tls12")]
    Tls12 {
        randoms: &'a ConnectionRandoms,
        kx_params: &'a [u8],
    },
    Tls13 {
        transcript: &'a HandshakeHash,
    },
}

#[derive(Debug)]
pub(crate) struct ServerCertDetails {
    pub(super) cert_chain: CertificatePayload,
    ocsp_response: Vec<u8>,
    pub(super) scts: Option<SCTList>,
}

impl ServerCertDetails {
    pub(super) fn new(
        cert_chain: CertificatePayload,
        ocsp_response: Vec<u8>,
        scts: Option<SCTList>,
    ) -> Self {
        Self {
            cert_chain,
            ocsp_response,
            scts,
        }
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) sent_extensions: Vec<ExtensionType>,
}

impl ClientHelloDetails {
    pub(super) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
        }
    }

    pub(super) fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions
            .contains(&ExtensionType::SCT)
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {:?}", ext_type);
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
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
    },
}

impl ClientAuthDetails {
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&DistinguishedNames>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
    ) -> Self {
        let acceptable_issuers = canames
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                };
            }
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}
