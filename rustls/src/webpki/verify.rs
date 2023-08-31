use alloc::sync::Arc;
use std::fmt;
use std::time::SystemTime;

use pki_types::{CertificateDer, TrustAnchor};

use super::anchors::RootCertStore;
use super::client_verifier_builder::ClientCertVerifierBuilder;
use super::pki_error;
use crate::client::ServerName;
use crate::enums::SignatureScheme;
use crate::error::{CertRevocationListError, CertificateError, Error, PeerMisbehaved};
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::handshake::DistinguishedName;
use crate::verify::{
    ClientCertVerified, ClientCertVerifier, DigitallySignedStruct, HandshakeSignatureValid,
    NoClientAuth, ServerCertVerified, ServerCertVerifier,
};

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the [TrustAnchor]s in the `roots` [RootCertStore].
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's `Certificate` message. It is in the
/// same order that the server sent them and may be empty.
#[allow(dead_code)]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
pub fn verify_server_cert_signed_by_trust_anchor(
    cert: &ParsedCertificate,
    roots: &RootCertStore,
    intermediates: &[CertificateDer<'_>],
    now: SystemTime,
    supported_algs: &[&dyn webpki::SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    let trust_roots = trust_roots(roots);
    let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

    cert.0
        .verify_for_usage(
            supported_algs,
            &trust_roots,
            intermediates,
            webpki_now,
            webpki::KeyUsage::server_auth(),
            None, // no CRLs
        )
        .map_err(pki_error)
        .map(|_| ())
}

/// Verify that the `end_entity` has a name or alternative name matching the `server_name`
/// note: this only verifies the name and should be used in conjuction with more verification
/// like [verify_server_cert_signed_by_trust_anchor]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
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

impl ServerCertVerifier for WebPkiServerVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    /// - Valid for DNS entry
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported.all,
        )?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
pub struct WebPkiServerVerifier {
    roots: Arc<RootCertStore>,
    supported: WebPkiSupportedAlgorithms,
}

#[allow(unreachable_pub)]
impl WebPkiServerVerifier {
    /// Constructs a new `WebPkiServerVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    #[cfg(feature = "ring")]
    pub fn new(roots: impl Into<Arc<RootCertStore>>) -> Self {
        Self::new_with_algorithms(roots, SUPPORTED_SIG_ALGS)
    }

    /// Constructs a new `WebPkiVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    /// `supported` is the set of supported algorithms that will be used for
    /// certificate verification and TLS handshake signature verification.
    pub fn new_with_algorithms(
        roots: impl Into<Arc<RootCertStore>>,
        supported: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            roots: roots.into(),
            supported,
        }
    }

    /// A full implementation of `ServerCertVerifier::verify_tls12_signature` or
    /// `ClientCertVerifier::verify_tls12_signature`.
    #[cfg(feature = "ring")]
    pub fn default_verify_tls12_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::verify_tls13_signature` or
    /// `ClientCertVerifier::verify_tls13_signature`.
    #[cfg(feature = "ring")]
    pub fn default_verify_tls13_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::supported_verify_schemes()` or
    /// `ClientCertVerifier::supported_verify_schemes()`.
    #[cfg(feature = "ring")]
    pub fn default_supported_verify_schemes() -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }
}

fn trust_roots(roots: &RootCertStore) -> Vec<TrustAnchor<'_>> {
    roots
        .roots
        .iter()
        .map(|with_dn| {
            let inner = with_dn.inner();
            TrustAnchor {
                subject: inner.subject.as_ref().into(),
                subject_public_key_info: inner
                    .subject_public_key_info
                    .as_ref()
                    .into(),
                name_constraints: inner
                    .name_constraints
                    .as_ref()
                    .map(|nc| nc.as_ref().into()),
            }
        })
        .collect()
}

/// A client certificate verifier that uses the `webpki` crate[^1] to perform client certificate
/// validation. It must be created via the [WebPkiClientVerifier::builder()] function.
///
/// Once built, the provided `Arc<dyn ClientCertVerifier>` can be used with a Rustls [crate::server::ServerConfig]
/// to configure client certificate validation using [`with_client_cert_verifier`][crate::ConfigBuilder<ClientConfig, WantsVerifier>::with_client_cert_verifier].
///
/// Example:
///
/// To require all clients present a client certificate issued by a trusted CA:
/// ```no_run
/// # use rustls::RootCertStore;
/// # use rustls::server::WebPkiClientVerifier;
/// # let roots = RootCertStore::empty();
/// let client_verifier = WebPkiClientVerifier::builder(roots.into())
///   .build()
///   .unwrap();
/// ```
///
/// Or, to allow clients presenting a client certificate authenticated by a trusted CA, or
/// anonymous clients that present no client certificate:
/// ```no_run
/// # use rustls::RootCertStore;
/// # use rustls::server::WebPkiClientVerifier;
/// # let roots = RootCertStore::empty();
/// let client_verifier = WebPkiClientVerifier::builder(roots.into())
///   .allow_unauthenticated()
///   .build()
///   .unwrap();
/// ```
///
/// If you wish to disable advertising client authentication:
/// ```no_run
/// # use rustls::RootCertStore;
/// # use rustls::server::WebPkiClientVerifier;
/// # let roots = RootCertStore::empty();
/// let client_verifier = WebPkiClientVerifier::no_client_auth();
/// ```
///
/// You can also configure the client verifier to check for certificate revocation with
/// client certificate revocation lists (CRLs):
/// ```no_run
/// # use rustls::RootCertStore;
/// # use rustls::server::{WebPkiClientVerifier};
/// # let roots = RootCertStore::empty();
/// # let crls = Vec::new();
/// let client_verifier = WebPkiClientVerifier::builder(roots.into())
///   .with_crls(crls)
///   .build()
///   .unwrap();
/// ```
///
/// [^1]: <https://github.com/rustls/webpki>
pub struct WebPkiClientVerifier {
    roots: Arc<RootCertStore>,
    subjects: Vec<DistinguishedName>,
    crls: Vec<webpki::OwnedCertRevocationList>,
    anonymous_policy: AnonymousClientPolicy,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl WebPkiClientVerifier {
    /// Create builder to build up the `webpki` client certificate verifier configuration.
    /// Client certificate authentication will be offered by the server, and client certificates
    /// will be verified using the trust anchors found in the provided `roots`. If you
    /// wish to disable client authentication use [WebPkiClientVerifier::no_client_auth()] instead.
    ///
    /// For more information, see the [`ClientCertVerifierBuilder`] documentation.
    pub fn builder(roots: Arc<RootCertStore>) -> ClientCertVerifierBuilder {
        ClientCertVerifierBuilder::new(roots)
    }

    /// Create a new `WebPkiClientVerifier` that disables client authentication. The server will
    /// not offer client authentication and anonymous clients will be accepted.
    ///
    /// This is in contrast to using `WebPkiClientVerifier::builder().allow_unauthenticated().build()`,
    /// which will produce a verifier that will offer client authentication, but not require it.
    pub fn no_client_auth() -> Arc<dyn ClientCertVerifier> {
        Arc::new(NoClientAuth {})
    }

    /// Construct a new `WebpkiClientVerifier`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    /// `crls` are an iterable of owned certificate revocation lists (CRLs) to use for
    /// client certificate validation.
    /// `anonymous_policy` controls whether client authentication is required, or if anonymous
    /// clients can connect.
    /// `supported_algs` is which signature verification algorithms should be used.
    pub(crate) fn new(
        roots: Arc<RootCertStore>,
        crls: Vec<webpki::OwnedCertRevocationList>,
        anonymous_policy: AnonymousClientPolicy,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            subjects: roots
                .roots
                .iter()
                .map(|r| r.subject().clone())
                .collect(),
            crls,
            roots,
            anonymous_policy,
            supported_algs,
        }
    }
}

impl ClientCertVerifier for WebPkiClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        match self.anonymous_policy {
            AnonymousClientPolicy::Allow => false,
            AnonymousClientPolicy::Deny => true,
        }
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        let trust_roots = trust_roots(&self.roots);
        let now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

        #[allow(trivial_casts)] // Cast to &dyn trait is required.
        let crls = self
            .crls
            .iter()
            .map(|crl| crl as &dyn webpki::CertRevocationList)
            .collect::<Vec<_>>();

        let revocation = if crls.is_empty() {
            None
        } else {
            Some(
                webpki::RevocationOptionsBuilder::new(&crls)
                    .expect("invalid crls")
                    .allow_unknown_status()
                    .build(),
            )
        };

        cert.0
            .verify_for_usage(
                self.supported_algs.all,
                &trust_roots,
                intermediates,
                now,
                webpki::KeyUsage::client_auth(),
                revocation,
            )
            .map_err(pki_error)
            .map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Controls how the [WebPkiClientVerifier] handles anonymous clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnonymousClientPolicy {
    /// Clients that do not present a client certificate are allowed.
    Allow,
    /// Clients that do not present a client certificate are denied.
    Deny,
}

impl From<webpki::Error> for CertRevocationListError {
    fn from(e: webpki::Error) -> Self {
        use webpki::Error::*;
        match e {
            InvalidCrlSignatureForPublicKey
            | UnsupportedCrlSignatureAlgorithm
            | UnsupportedCrlSignatureAlgorithmForPublicKey => Self::BadSignature,
            InvalidCrlNumber => Self::InvalidCrlNumber,
            InvalidSerialNumber => Self::InvalidRevokedCertSerialNumber,
            IssuerNotCrlSigner => Self::IssuerInvalidForCrl,
            MalformedExtensions | BadDer | BadDerTime => Self::ParseError,
            UnsupportedCriticalExtension => Self::UnsupportedCriticalExtension,
            UnsupportedCrlVersion => Self::UnsupportedCrlVersion,
            UnsupportedDeltaCrl => Self::UnsupportedDeltaCrl,
            UnsupportedIndirectCrl => Self::UnsupportedIndirectCrl,
            UnsupportedRevocationReason => Self::UnsupportedRevocationReason,

            _ => Self::Other(Arc::new(e)),
        }
    }
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
    pub all: &'static [&'static dyn webpki::SignatureVerificationAlgorithm],

    /// A mapping from TLS `SignatureScheme`s to matching webpki signature verification algorithms.
    ///
    /// This is one (`SignatureScheme`) to many (`webpki::SignatureVerificationAlgorithm`) because
    /// (depending on the protocol version) there is not necessary a 1-to-1 mapping.
    ///
    /// For TLS1.2, all `webpki:SignatureVerificationAlgorithm`s are tried in sequence.
    ///
    /// For TLS1.3, only the first is tried.
    ///
    /// The supported schemes in this mapping is communicated to the peer and the order is significant.
    /// The first mapping is our highest preference.
    pub mapping: &'static [(
        SignatureScheme,
        &'static [&'static dyn webpki::SignatureVerificationAlgorithm],
    )],
}

// FIXME: make webpki::SignatureVerificationAlgorithm Debug and delete this.
impl fmt::Debug for WebPkiSupportedAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebPkiSupportedAlgorithms {{ all: [ .. ], mapping: ")?;
        f.debug_list()
            .entries(self.mapping.iter().map(|item| item.0))
            .finish()?;
        write!(f, " }}")
    }
}

#[cfg(feature = "ring")]
#[test]
fn test_webpkisupportedalgorithms_is_debug() {
    assert_eq!(
        "WebPkiSupportedAlgorithms { all: [ .. ], mapping: [ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256, ED25519, RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256] }",
        format!("{:?}", SUPPORTED_SIG_ALGS)
    );
}

impl WebPkiSupportedAlgorithms {
    /// Return all the `scheme` items in `mapping`, maintaining order.
    fn supported_schemes(&self) -> Vec<SignatureScheme> {
        self.mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }

    /// Return the first item in `mapping` that matches `scheme`.
    fn convert_scheme(
        &self,
        scheme: SignatureScheme,
    ) -> Result<&[&'static dyn webpki::SignatureVerificationAlgorithm], Error> {
        self.mapping
            .iter()
            .filter(|item| item.0 == scheme)
            .map(|item| item.1)
            .next()
            .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }
}

/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against *ring*.
#[cfg(feature = "ring")]
pub(crate) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki::ECDSA_P256_SHA256,
        webpki::ECDSA_P256_SHA384,
        webpki::ECDSA_P384_SHA256,
        webpki::ECDSA_P384_SHA384,
        webpki::ED25519,
        webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki::RSA_PKCS1_2048_8192_SHA256,
        webpki::RSA_PKCS1_2048_8192_SHA384,
        webpki::RSA_PKCS1_2048_8192_SHA512,
        webpki::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme. for TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[webpki::ECDSA_P384_SHA384, webpki::ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[webpki::ECDSA_P256_SHA256, webpki::ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[webpki::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

fn verify_sig_using_any_alg(
    cert: &webpki::EndEntityCert,
    algs: &[&'static dyn webpki::SignatureVerificationAlgorithm],
    message: &[u8],
    sig: &[u8],
) -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureVerificationAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(*alg, message, sig) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

fn verify_signed_struct(
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

fn verify_tls13(
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

#[test]
fn pki_crl_errors() {
    // CRL signature errors should be turned into BadSignature.
    assert_eq!(
        pki_error(webpki::Error::InvalidCrlSignatureForPublicKey),
        Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
    );
    assert_eq!(
        pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithm),
        Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
    );
    assert_eq!(
        pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey),
        Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
    );

    // Revoked cert errors should be turned into Revoked.
    assert_eq!(
        pki_error(webpki::Error::CertRevoked),
        Error::InvalidCertificate(CertificateError::Revoked),
    );

    // Issuer not CRL signer errors should be turned into IssuerInvalidForCrl
    assert_eq!(
        pki_error(webpki::Error::IssuerNotCrlSigner),
        Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl)
    );
}

#[test]
fn crl_error_from_webpki() {
    use crate::CertRevocationListError::*;
    let testcases = &[
        (webpki::Error::InvalidCrlSignatureForPublicKey, BadSignature),
        (
            webpki::Error::UnsupportedCrlSignatureAlgorithm,
            BadSignature,
        ),
        (
            webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey,
            BadSignature,
        ),
        (webpki::Error::InvalidCrlNumber, InvalidCrlNumber),
        (
            webpki::Error::InvalidSerialNumber,
            InvalidRevokedCertSerialNumber,
        ),
        (webpki::Error::IssuerNotCrlSigner, IssuerInvalidForCrl),
        (webpki::Error::MalformedExtensions, ParseError),
        (webpki::Error::BadDer, ParseError),
        (webpki::Error::BadDerTime, ParseError),
        (
            webpki::Error::UnsupportedCriticalExtension,
            UnsupportedCriticalExtension,
        ),
        (webpki::Error::UnsupportedCrlVersion, UnsupportedCrlVersion),
        (webpki::Error::UnsupportedDeltaCrl, UnsupportedDeltaCrl),
        (
            webpki::Error::UnsupportedIndirectCrl,
            UnsupportedIndirectCrl,
        ),
        (
            webpki::Error::UnsupportedRevocationReason,
            UnsupportedRevocationReason,
        ),
    ];
    for t in testcases {
        assert_eq!(
            <webpki::Error as Into<CertRevocationListError>>::into(t.0),
            t.1
        );
    }

    assert!(matches!(
        <webpki::Error as Into<CertRevocationListError>>::into(
            webpki::Error::NameConstraintViolation
        ),
        Other(_)
    ));
}

/// wrapper around internal representation of a parsed certificate. This is used in order to avoid parsing twice when specifying custom verification
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
pub struct ParsedCertificate<'a>(pub(crate) webpki::EndEntityCert<'a>);

impl<'a> TryFrom<&'a CertificateDer<'a>> for ParsedCertificate<'a> {
    type Error = Error;
    fn try_from(value: &'a CertificateDer<'a>) -> Result<ParsedCertificate<'a>, Self::Error> {
        webpki::EndEntityCert::try_from(value)
            .map_err(pki_error)
            .map(ParsedCertificate)
    }
}

#[cfg(test)]
mod test {
    use super::CertificateDer;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "CertificateDer(Der([97, 98]))",
            format!("{:?}", CertificateDer::from(b"ab".to_vec()))
        );
    }
}
