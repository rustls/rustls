use pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime,
};
use webpki::ExtendedKeyUsage;

use super::anchors::RootCertStore;
use super::pki_error;
use crate::crypto::WebPkiSupportedAlgorithms;
use crate::error::{ApiMisuse, Error, PeerMisbehaved};
use crate::verify::{HandshakeSignatureValid, SignatureVerificationInput, SignerPublicKey};

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the trust anchors in the `roots` [RootCertStore].
///
/// This function is primarily useful when building a custom certificate verifier. It
/// performs **no revocation checking**. Implementers must handle this themselves,
/// along with checking that the server certificate is valid for the subject name
/// being used (see [`verify_server_name`]).
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's `Certificate` message. It is in the
/// same order that the server sent them and may be empty.
pub fn verify_identity_signed_by_trust_anchor(
    cert: &ParsedCertificate<'_>,
    roots: &RootCertStore,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    verify_identity_signed_by_trust_anchor_impl(
        cert,
        roots,
        intermediates,
        None, // No revocation checking supported with this API.
        now,
        supported_algs,
    )
}

/// Verify that the `end_entity` has an alternative name matching the `server_name`.
///
/// Note: this only verifies the name and should be used in conjunction with more verification
/// like [verify_identity_signed_by_trust_anchor]
pub fn verify_server_name(
    cert: &ParsedCertificate<'_>,
    server_name: &ServerName<'_>,
) -> Result<(), Error> {
    cert.0
        .verify_is_valid_for_subject_name(server_name)
        .map_err(pki_error)
}

/// Wrapper around internal representation of a parsed certificate.
///
/// This is used in order to avoid parsing twice when specifying custom verification
pub struct ParsedCertificate<'a>(pub(crate) webpki::EndEntityCert<'a>);

impl ParsedCertificate<'_> {
    /// Get the parsed certificate's SubjectPublicKeyInfo (SPKI)
    pub fn subject_public_key_info(&self) -> SubjectPublicKeyInfoDer<'static> {
        self.0.subject_public_key_info()
    }
}

impl<'a> TryFrom<&'a CertificateDer<'a>> for ParsedCertificate<'a> {
    type Error = Error;
    fn try_from(value: &'a CertificateDer<'a>) -> Result<Self, Self::Error> {
        webpki::EndEntityCert::try_from(value)
            .map_err(pki_error)
            .map(ParsedCertificate)
    }
}

/// Verify a message signature using the `cert` public key and any supported scheme.
///
/// This function verifies the `dss` signature over `message` using the subject public key from
/// `cert`. Since TLS 1.2 doesn't provide enough information to map the `dss.scheme` into a single
/// [`SignatureVerificationAlgorithm`], this function will map to several candidates and try each in
/// succession until one succeeds or we exhaust all candidates.
///
/// See [WebPkiSupportedAlgorithms::mapping] for more information.
pub fn verify_tls12_signature(
    input: &SignatureVerificationInput<'_>,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    let possible_algs = supported_schemes.convert_scheme(input.signature.scheme)?;
    let cert = match input.signer {
        SignerPublicKey::X509(cert_der) => {
            webpki::EndEntityCert::try_from(*cert_der).map_err(pki_error)?
        }
        SignerPublicKey::RawPublicKey(_) => {
            return Err(ApiMisuse::InvalidSignerForProtocolVersion.into());
        }
    };

    let mut error = None;
    for alg in possible_algs {
        match cert.verify_signature(*alg, input.message, input.signature.signature()) {
            Err(err @ webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_)) => {
                error = Some(err);
                continue;
            }
            Err(e) => return Err(pki_error(e)),
            Ok(()) => return Ok(HandshakeSignatureValid::assertion()),
        }
    }

    Err(match error {
        Some(e) => pki_error(e),
        None => Error::ApiMisuse(ApiMisuse::NoSignatureVerificationAlgorithms),
    })
}

/// Verify a message signature using the `cert` public key and the first TLS 1.3 compatible
/// supported scheme.
///
/// This function verifies the `dss` signature over `message` using the subject public key from
/// `cert`. Unlike [verify_tls12_signature], this function only tries the first matching scheme. See
/// [WebPkiSupportedAlgorithms::mapping] for more information.
pub fn verify_tls13_signature(
    input: &SignatureVerificationInput<'_>,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !input
        .signature
        .scheme
        .supported_in_tls13()
    {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }

    let alg = supported_schemes.convert_scheme(input.signature.scheme)?[0];
    match input.signer {
        SignerPublicKey::X509(cert_der) => {
            webpki::EndEntityCert::try_from(*cert_der).and_then(|cert| {
                cert.verify_signature(alg, input.message, input.signature.signature())
            })
        }
        SignerPublicKey::RawPublicKey(spki) => webpki::RawPublicKeyEntity::try_from(*spki)
            .and_then(|rpk| rpk.verify_signature(alg, input.message, input.signature.signature())),
    }
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
/// This function exists to be used by [`verify_identity_signed_by_trust_anchor`],
/// and differs only in providing a `Option<webpki::RevocationOptions>` argument. We
/// can't include this argument in `verify_identity_signed_by_trust_anchor` because
/// it will leak the webpki types into Rustls' public API.
pub(crate) fn verify_identity_signed_by_trust_anchor_impl(
    cert: &ParsedCertificate<'_>,
    roots: &RootCertStore,
    intermediates: &[CertificateDer<'_>],
    revocation: Option<webpki::RevocationOptions<'_>>,
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    let result = cert.0.verify_for_usage(
        supported_algs,
        &roots.roots,
        intermediates,
        now,
        &ExtendedKeyUsage::server_auth(),
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
    use std::format;

    use super::*;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "CertificateDer(0x6162)",
            format!("{:?}", CertificateDer::from(b"ab".to_vec()))
        );
    }

    #[test]
    fn webpki_supported_algorithms_is_debug() {
        assert_eq!(
            "WebPkiSupportedAlgorithms { all: [ .. ], mapping: [] }",
            format!(
                "{:?}",
                WebPkiSupportedAlgorithms {
                    all: &[],
                    mapping: &[]
                }
            )
        );
    }
}
