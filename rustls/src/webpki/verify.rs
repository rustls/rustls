use alloc::vec::Vec;
use core::fmt;

use pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
#[cfg(feature = "ring")]
use webpki::ring as webpki_algs;

use super::anchors::RootCertStore;
use super::pki_error;
use crate::client::ServerName;
use crate::enums::SignatureScheme;
use crate::error::{CertificateError, Error, PeerMisbehaved};

use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the trust anchors in the `roots` [RootCertStore].
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
    cert.0
        .verify_for_usage(
            supported_algs,
            &roots.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None, // no CRLs
        )
        .map_err(pki_error)
        .map(|_| ())
}

/// Verify that the `end_entity` has a name or alternative name matching the `server_name`
/// note: this only verifies the name and should be used in conjuction with more verification
/// like [verify_server_cert_signed_by_trust_anchor]
pub fn verify_server_name(cert: &ParsedCertificate, server_name: &ServerName) -> Result<(), Error> {
    match server_name {
        ServerName::DnsName(dns_name) => {
            // unlikely error because dns_name::DnsNameRef and webpki::DnsNameRef
            // should have the same encoding rules.
            let dns_name = webpki::DnsNameRef::try_from_ascii_str(dns_name.as_ref())
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
            let name = webpki::SubjectNameRef::DnsName(dns_name);
            cert.0
                .verify_is_valid_for_subject_name(name)
                .map_err(pki_error)?;
        }
        ServerName::IpAddress(ip_addr) => {
            let ip_addr = webpki::IpAddr::from(*ip_addr);
            cert.0
                .verify_is_valid_for_subject_name(webpki::SubjectNameRef::IpAddress(
                    webpki::IpAddrRef::from(&ip_addr),
                ))
                .map_err(pki_error)?;
        }
    }
    Ok(())
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

/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against *ring*.
#[cfg(feature = "ring")]
pub(crate) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme. for TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "CertificateDer(Der([97, 98]))",
            format!("{:?}", CertificateDer::from(b"ab".to_vec()))
        );
    }

    #[cfg(feature = "ring")]
    #[test]
    fn webpki_supported_algorithms_is_debug() {
        assert_eq!(
            "WebPkiSupportedAlgorithms { all: [ .. ], mapping: [ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256, ED25519, RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256] }",
            format!("{:?}", SUPPORTED_SIG_ALGS)
        );
    }
}
