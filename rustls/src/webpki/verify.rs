use alloc::vec::Vec;
use core::fmt;

use pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};

use super::anchors::RootCertStore;
use super::pki_error;
use crate::enums::SignatureScheme;
use crate::error::{Error, PeerMisbehaved};

use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the trust anchors in the `roots` [RootCertStore].
///
/// This function is primarily useful when building a custom certificate verifier. It
/// performs **no revocation checking**. Implementors must handle this themselves,
/// along with checking that the server certificate is valid for the subject name
/// being used (see [`verify_server_name`]).
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's `Certificate` message. It is in the
/// same order that the server sent them and may be empty.
#[allow(dead_code)]
pub fn verify_server_cert_signed_by_trust_anchor(
    cert: &ParsedCertificate,
    roots: &RootCertStore,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    verify_server_cert_signed_by_trust_anchor_impl(
        cert,
        roots,
        intermediates,
        None, // No revocation checking supported with this API.
        now,
        supported_algs,
    )
}

/// Verify that the `end_entity` has a name or alternative name matching the `server_name`
/// note: this only verifies the name and should be used in conjuction with more verification
/// like [verify_server_cert_signed_by_trust_anchor]
pub fn verify_server_name(
    cert: &ParsedCertificate,
    server_name: &ServerName<'_>,
) -> Result<(), Error> {
    cert.0
        .verify_is_valid_for_subject_name(server_name)
        .map_err(pki_error)
}

/// Describes which `webpki` signature verification algorithms are supported and
/// how they map to TLS `SignatureScheme`s.
#[derive(Clone, Copy)]
#[allow(unreachable_pub)]
pub struct WebPkiSupportedAlgorithms {
    /// A list of all supported signature verification algorithms.
    ///
    /// Used for verifying certificate chains.
    ///
    /// The order of this list is not significant.
    pub all: &'static [&'static dyn SignatureVerificationAlgorithm],

    /// A mapping from TLS `SignatureScheme`s to matching webpki signature verification algorithms.
    ///
    /// This is one (`SignatureScheme`) to many ([`SignatureVerificationAlgorithm`]) because
    /// (depending on the protocol version) there is not necessary a 1-to-1 mapping.
    ///
    /// For TLS1.2, all `SignatureVerificationAlgorithm`s are tried in sequence.
    ///
    /// For TLS1.3, only the first is tried.
    ///
    /// The supported schemes in this mapping is communicated to the peer and the order is significant.
    /// The first mapping is our highest preference.
    pub mapping: &'static [(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )],
}

impl WebPkiSupportedAlgorithms {
    /// Return all the `scheme` items in `mapping`, maintaining order.
    pub(crate) fn supported_schemes(&self) -> Vec<SignatureScheme> {
        self.mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }

    /// Return the first item in `mapping` that matches `scheme`.
    fn convert_scheme(
        &self,
        scheme: SignatureScheme,
    ) -> Result<&[&'static dyn SignatureVerificationAlgorithm], Error> {
        self.mapping
            .iter()
            .filter_map(|item| if item.0 == scheme { Some(item.1) } else { None })
            .next()
            .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }
}

impl fmt::Debug for WebPkiSupportedAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebPkiSupportedAlgorithms {{ all: [ .. ], mapping: ")?;
        f.debug_list()
            .entries(self.mapping.iter().map(|item| item.0))
            .finish()?;
        write!(f, " }}")
    }
}

/// Wrapper around internal representation of a parsed certificate.
///
/// This is used in order to avoid parsing twice when specifying custom verification
pub struct ParsedCertificate<'a>(pub(crate) webpki::EndEntityCert<'a>);

impl<'a> TryFrom<&'a CertificateDer<'a>> for ParsedCertificate<'a> {
    type Error = Error;
    fn try_from(value: &'a CertificateDer<'a>) -> Result<ParsedCertificate<'a>, Self::Error> {
        webpki::EndEntityCert::try_from(value)
            .map_err(pki_error)
            .map(ParsedCertificate)
    }
}

fn verify_sig_using_any_alg(
    cert: &webpki::EndEntityCert,
    algs: &[&'static dyn SignatureVerificationAlgorithm],
    message: &[u8],
    sig: &[u8],
) -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single pki_types::SignatureVerificationAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(*alg, message, sig) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

pub(crate) fn verify_signed_struct(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    let possible_algs = supported_schemes.convert_scheme(dss.scheme)?;
    let cert = webpki::EndEntityCert::try_from(cert).map_err(pki_error)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

pub(crate) fn verify_tls13(
    msg: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !dss.scheme.supported_in_tls13() {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }

    let alg = supported_schemes.convert_scheme(dss.scheme)?[0];

    let cert = webpki::EndEntityCert::try_from(cert).map_err(pki_error)?;

    cert.verify_signature(alg, msg, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the trust anchors in the `roots` [RootCertStore].
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's `Certificate` message. It is in the
/// same order that the server sent them and may be empty.
///
/// `revocation` controls how revocation checking is performed, if at all.
///
/// This function exists to be used by [`verify_server_cert_signed_by_trust_anchor`],
/// and differs only in providing a `Option<webpki::RevocationOptions>` argument. We
/// can't include this argument in `verify_server_cert_signed_by_trust_anchor` because
/// it will leak the webpki types into Rustls' public API.
pub(crate) fn verify_server_cert_signed_by_trust_anchor_impl(
    cert: &ParsedCertificate,
    roots: &RootCertStore,
    intermediates: &[CertificateDer<'_>],
    revocation: Option<webpki::RevocationOptions>,
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    let result = cert.0.verify_for_usage(
        supported_algs,
        &roots.roots,
        intermediates,
        now,
        webpki::KeyUsage::server_auth(),
        revocation,
        None,
    );
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(pki_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "CertificateDer(0x6162)",
            format!("{:?}", CertificateDer::from(b"ab".to_vec()))
        );
    }

    #[cfg(feature = "ring")]
    #[test]
    fn webpki_supported_algorithms_is_debug() {
        assert_eq!(
            "WebPkiSupportedAlgorithms { all: [ .. ], mapping: [ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256, ED25519, RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256] }",
            format!("{:?}", crate::crypto::ring::RING.signature_verification_algorithms())
        );
    }
}
