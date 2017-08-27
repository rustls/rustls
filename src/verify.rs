use webpki;
use time;
use untrusted;
use sct;
use std;

use key::Certificate;
use msgs::handshake::DigitallySignedStruct;
use msgs::handshake::SCTList;
use msgs::enums::SignatureScheme;
use error::TLSError;
use anchors::RootCertStore;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA256,
                                                   &webpki::ECDSA_P256_SHA384,
                                                   &webpki::ECDSA_P384_SHA256,
                                                   &webpki::ECDSA_P384_SHA384,
                                                   &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA1,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA256,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA384,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA512,
                                                   &webpki::RSA_PKCS1_3072_8192_SHA384];

/// Marker types.  These are used to bind the fact some verification
/// (certificate chain or handshake signature) has taken place into
/// protocol states.  We use this to have the compiler check that there
/// are no 'goto fail'-style elisions of important checks before we
/// reach the traffic stage.
///
/// These types are public, but cannot be directly constructed.  This
/// means their origins can be precisely determined by looking
/// for their `assertion` constructors.
pub struct HandshakeSignatureValid(());
impl HandshakeSignatureValid { pub fn assertion() -> Self { Self { 0: () } } }

pub struct FinishedMessageVerified(());
impl FinishedMessageVerified { pub fn assertion() -> Self { Self { 0: () } } }

/// Zero-sized marker type representing verification of a server cert chain.
pub struct ServerCertVerified(());
impl ServerCertVerified {
    /// Make a `ServerCertVerified`
    pub fn assertion() -> Self { Self { 0: () } }
}

/// Zero-sized marker type representing verification of a client cert chain.
pub struct ClientCertVerified(());
impl ClientCertVerified {
    /// Make a `ClientCertVerified`
    pub fn assertion() -> Self { Self { 0: () } }
}

/// Something that can verify a server certificate chain
pub trait ServerCertVerifier : Send + Sync {
    /// Verify a the certificate chain `presented_certs` against the roots
    /// configured in `roots`.  Make sure that `dns_name` is quoted by
    /// the top certificate in the chain.
    fn verify_server_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate],
                          dns_name: &str,
                          ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError>;
}

/// Something that can verify a client certificate chain
pub trait ClientCertVerifier : Send + Sync {
    /// Verify a certificate chain `presented_certs` is rooted in `roots`.
    /// Does no further checking of the certificate.
    fn verify_client_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate]) -> Result<ClientCertVerified, TLSError>;
}

pub struct WebPKIVerifier {
    pub time: fn() -> Result<webpki::Time, TLSError>,
}

impl ServerCertVerifier for WebPKIVerifier {
    fn verify_server_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate],
                          dns_name: &str,
                          ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError> {
        let cert = self.verify_common_cert(roots, presented_certs)?;

        if !ocsp_response.is_empty() {
            info!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        cert.verify_is_valid_for_dns_name(untrusted::Input::from(dns_name.as_bytes()))
            .map_err(TLSError::WebPKIError)
            .map(|_| ServerCertVerified::assertion())
    }
}

impl ClientCertVerifier for WebPKIVerifier {
    fn verify_client_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate]) -> Result<ClientCertVerified, TLSError> {
        self.verify_common_cert(roots, presented_certs)
            .map(|_| ClientCertVerified::assertion())
    }
}

impl WebPKIVerifier {
    pub fn new() -> WebPKIVerifier {
        WebPKIVerifier {
            time: ||
                webpki::Time::try_from(std::time::SystemTime::now())
                    .map_err(|_| TLSError::FailedToGetCurrentTime),
        }
    }

    /// Check `presented_certs` is non-empty and rooted in `roots`.
    /// Return the `webpki::EndEntityCert` for the top certificate
    /// in `presented_certs`.
    fn verify_common_cert<'a>(&self,
                              roots: &RootCertStore,
                              presented_certs: &'a [Certificate])
                              -> Result<webpki::EndEntityCert<'a>, TLSError> {
        if presented_certs.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        // EE cert must appear first.
        let cert_der = untrusted::Input::from(&presented_certs[0].0);
        let cert = webpki::EndEntityCert::from(cert_der)
            .map_err(TLSError::WebPKIError)?;

        let now = (self.time)()?;

        let chain: Vec<untrusted::Input> = presented_certs.iter()
            .skip(1)
            .map(|cert| untrusted::Input::from(&cert.0))
            .collect();

        let trustroots: Vec<webpki::TrustAnchor> = roots.roots
            .iter()
            .map(|x| x.to_trust_anchor())
            .collect();
        let trustroots = webpki::TLSServerTrustAnchors(&trustroots);

        cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &trustroots, &chain, now)
            .map_err(TLSError::WebPKIError)
            .map(|_| cert)
    }
}

static ECDSA_SHA256: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA256,
                                             &webpki::ECDSA_P384_SHA256];
static ECDSA_SHA384: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA384,
                                             &webpki::ECDSA_P384_SHA384];

static RSA_SHA1: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA1];
static RSA_SHA256: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA256];
static RSA_SHA384: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA384];
static RSA_SHA512: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA512];
static RSA_PSS_SHA256: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
static RSA_PSS_SHA384: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
static RSA_PSS_SHA512: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];

fn convert_scheme(scheme: SignatureScheme) -> Result<SignatureAlgorithms, TLSError> {
    match scheme {
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme.
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(ECDSA_SHA256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(ECDSA_SHA384),

        SignatureScheme::RSA_PKCS1_SHA1 => Ok(RSA_SHA1),
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(RSA_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(RSA_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(RSA_SHA512),

        SignatureScheme::RSA_PSS_SHA256 => Ok(RSA_PSS_SHA256),
        SignatureScheme::RSA_PSS_SHA384 => Ok(RSA_PSS_SHA384),
        SignatureScheme::RSA_PSS_SHA512 => Ok(RSA_PSS_SHA512),

        _ => {
            let error_msg = format!("received unadvertised sig scheme {:?}", scheme);
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

fn verify_sig_using_any_alg(cert: &webpki::EndEntityCert,
                            algs: SignatureAlgorithms,
                            message: &[u8],
                            sig: &[u8])
                            -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(alg,
                                    untrusted::Input::from(message),
                                    untrusted::Input::from(sig)) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

/// Verify the signed `message` using the public key quoted in
/// `cert` and algorithm and signature in `dss`.
///
/// `cert` MUST have been authenticated before using this function,
/// typically using `verify_cert`.
pub fn verify_signed_struct(message: &[u8],
                            cert: &Certificate,
                            dss: &DigitallySignedStruct)
                            -> Result<HandshakeSignatureValid, TLSError> {

    let possible_algs = convert_scheme(dss.scheme)?;
    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, &dss.sig.0)
        .map_err(TLSError::WebPKIError)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn convert_alg_tls13(scheme: SignatureScheme)
                     -> Result<&'static webpki::SignatureAlgorithm, TLSError> {
    use msgs::enums::SignatureScheme::*;

    match scheme {
        ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
        ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
        RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        _ => {
            let error_msg = format!("received unsupported sig scheme {:?}", scheme);
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

pub fn verify_tls13(cert: &Certificate,
                    dss: &DigitallySignedStruct,
                    handshake_hash: &[u8],
                    context_string_with_0: &[u8])
                    -> Result<HandshakeSignatureValid, TLSError> {
    let alg = convert_alg_tls13(dss.scheme)?;

    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash);

    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)?;

    cert.verify_signature(alg,
                          untrusted::Input::from(&msg),
                          untrusted::Input::from(&dss.sig.0))
        .map_err(TLSError::WebPKIError)
        .map(|_| HandshakeSignatureValid::assertion())
}

pub fn verify_scts(cert: &Certificate,
                   scts: &SCTList,
                   logs: &[&sct::Log]) -> Result<(), TLSError> {
    let mut valid_scts = 0;
    let now = (time::get_time().sec * 1000) as u64;
    let mut last_sct_error = None;

    for sct in scts {
        match sct::verify_sct(&cert.0, &sct.0, now, logs) {
            Ok(index) => {
                info!("Valid SCT signed by {} on {}",
                      logs[index].operated_by, logs[index].description);
                valid_scts += 1;
            }
            Err(e) => {
                if e.should_be_fatal() {
                    return Err(TLSError::InvalidSCT(e));
                }
                info!("SCT ignored because {:?}", e);
                last_sct_error = Some(e);
            }
        }
    }

    /* If we were supplied with some logs, and some SCTs,
     * but couldn't verify any of them, fail the handshake. */
    if !logs.is_empty() && !scts.is_empty() && valid_scts == 0 {
        warn!("No valid SCTs provided");
        return Err(TLSError::InvalidSCT(last_sct_error.unwrap()));
    }

    Ok(())
}
