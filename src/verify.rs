use webpki;
use time;
use untrusted;

use msgs::handshake::ASN1Cert;
use msgs::handshake::DigitallySignedStruct;
use msgs::enums::SignatureScheme;
use error::TLSError;
use anchors::RootCertStore;

/// Disable all verifications, for testing purposes.
const DANGEROUS_DISABLE_VERIFY: bool = false;

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

/// Check `presented_certs` is non-empty and rooted in `roots`.
/// Return the `webpki::EndEntityCert` for the top certificate
/// in `presented_certs`.
fn verify_common_cert<'a>(roots: &RootCertStore,
                          presented_certs: &'a [ASN1Cert])
                          -> Result<webpki::EndEntityCert<'a>, TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert_der = untrusted::Input::from(&presented_certs[0].0);
    let cert = try! {
        webpki::EndEntityCert::from(cert_der)
        .map_err(TLSError::WebPKIError)
    };

    let chain: Vec<untrusted::Input> = presented_certs.iter()
        .skip(1)
        .map(|cert| untrusted::Input::from(&cert.0))
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots.roots
        .iter()
        .map(|x| x.to_trust_anchor())
        .collect();

    if DANGEROUS_DISABLE_VERIFY {
        warn!("DANGEROUS_DISABLE_VERIFY is turned on, skipping certificate verification");
        return Ok(cert);
    }

    cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &trustroots, &chain, time::get_time())
        .map_err(TLSError::WebPKIError)
        .map(|_| cert)
}

/// Verify a the certificate chain `presented_certs` against the roots
/// configured in `roots`.  Make sure that `dns_name` is quoted by
/// the top certificate in the chain.
pub fn verify_server_cert(roots: &RootCertStore,
                          presented_certs: &[ASN1Cert],
                          dns_name: &str)
                          -> Result<(), TLSError> {
    let cert = try!(verify_common_cert(roots, presented_certs));

    if DANGEROUS_DISABLE_VERIFY {
        warn!("DANGEROUS_DISABLE_VERIFY is turned on, skipping server name verification");
        return Ok(());
    }

    cert.verify_is_valid_for_dns_name(untrusted::Input::from(dns_name.as_bytes()))
        .map_err(TLSError::WebPKIError)
}

/// Verify a certificate chain `presented_certs` is rooted in `roots`.
/// Does no further checking of the certificate.
pub fn verify_client_cert(roots: &RootCertStore,
                          presented_certs: &[ASN1Cert])
                          -> Result<(), TLSError> {
    verify_common_cert(roots, presented_certs).map(|_| ())
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
                            cert: &ASN1Cert,
                            dss: &DigitallySignedStruct)
                            -> Result<(), TLSError> {

    let possible_algs = try!(convert_scheme(dss.scheme));
    let cert_in = untrusted::Input::from(&cert.0);
    let cert = try! {
        webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)
    };

    verify_sig_using_any_alg(&cert, possible_algs, message, &dss.sig.0)
        .map_err(TLSError::WebPKIError)
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

pub fn verify_tls13(cert: &ASN1Cert,
                    dss: &DigitallySignedStruct,
                    handshake_hash: &[u8],
                    context_string_with_0: &[u8])
                    -> Result<(), TLSError> {
    let alg = try!(convert_alg_tls13(dss.scheme));

    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash);

    let cert_in = untrusted::Input::from(&cert.0);
    let cert = try! {
        webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)
    };

    cert.verify_signature(alg,
                          untrusted::Input::from(&msg),
                          untrusted::Input::from(&dss.sig.0))
    .map_err(TLSError::WebPKIError)
}
