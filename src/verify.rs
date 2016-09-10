extern crate webpki;
extern crate ring;
extern crate time;
extern crate untrusted;

use msgs::handshake::ASN1Cert;
use msgs::handshake::DigitallySignedStruct;
use msgs::handshake::SignatureAndHashAlgorithm;
use msgs::handshake::{DistinguishedName, DistinguishedNames};
use error::TLSError;
use pemfile;
use x509;

use std::io;

/// Disable all verifications, for testing purposes.
const DANGEROUS_DISABLE_VERIFY: bool = false;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
  &webpki::ECDSA_P256_SHA1,
  &webpki::ECDSA_P256_SHA256,
  &webpki::ECDSA_P256_SHA384,
  &webpki::ECDSA_P256_SHA512,
  &webpki::ECDSA_P384_SHA1,
  &webpki::ECDSA_P384_SHA256,
  &webpki::ECDSA_P384_SHA384,
  &webpki::ECDSA_P384_SHA512,
  &webpki::RSA_PKCS1_2048_8192_SHA1,
  &webpki::RSA_PKCS1_2048_8192_SHA256,
  &webpki::RSA_PKCS1_2048_8192_SHA384,
  &webpki::RSA_PKCS1_2048_8192_SHA512,
  &webpki::RSA_PKCS1_3072_8192_SHA384
];

/// This is like a webpki::TrustAnchor, except it owns
/// rather than borrows its memory.  That prevents lifetimes
/// leaking up the object tree.
struct OwnedTrustAnchor {
  subject: Vec<u8>,
  spki: Vec<u8>,
  name_constraints: Option<Vec<u8>>
}

impl OwnedTrustAnchor {
  fn from_trust_anchor(t: &webpki::TrustAnchor) -> OwnedTrustAnchor {
    OwnedTrustAnchor {
      subject: t.subject.to_vec(),
      spki: t.spki.to_vec(),
      name_constraints: t.name_constraints.map(|x| x.to_vec())
    }
  }

  fn to_trust_anchor(&self) -> webpki::TrustAnchor {
    webpki::TrustAnchor {
      subject: &self.subject,
      spki: &self.spki,
      name_constraints: self.name_constraints.as_ref().map(|x| x.as_slice())
    }
  }
}

/// A container for root certificates able to provide a root-of-trust
/// for connection authentication.
pub struct RootCertStore {
  roots: Vec<OwnedTrustAnchor>
}

impl RootCertStore {
  /// Make a new, empty `RootCertStore`.
  pub fn empty() -> RootCertStore {
    RootCertStore { roots: Vec::new() }
  }

  /// Say how many certificates are in the container.
  pub fn len(&self) -> usize {
    self.roots.len()
  }

  /// Return the Subject Names for certificates in the container.
  pub fn get_subjects(&self) -> DistinguishedNames {
    let mut r = DistinguishedNames::new();

    for ota in &self.roots {
      let mut name = Vec::new();
      name.extend_from_slice(&ota.subject);
      x509::wrap_in_sequence(&mut name);
      r.push(DistinguishedName::new(name));
    }

    r
  }

  /// Add a single DER-encoded certificate to the store.
  pub fn add(&mut self, der: &[u8]) -> Result<(), webpki::Error> {
    let ta = try!(
      webpki::trust_anchor_util::cert_der_as_trust_anchor(untrusted::Input::from(der))
    );

    let ota = OwnedTrustAnchor::from_trust_anchor(&ta);
    self.roots.push(ota);
    Ok(())
  }

  /// Adds all the given TrustAnchors `anchors`.  This does not
  /// fail.
  pub fn add_trust_anchors(&mut self, anchors: &[webpki::TrustAnchor]) {
    for ta in anchors {
      self.roots.push(OwnedTrustAnchor::from_trust_anchor(ta));
    }
  }

  /// Parse a PEM file and add all certificates found inside.
  /// Errors are non-specific; they may be io errors in `rd` and
  /// PEM format errors, but not certificate validity errors.
  ///
  /// This is because large collections of root certificates often
  /// include ancient or syntactictally invalid certificates.  CAs
  /// are competent like that.
  ///
  /// Returns the number of certificates added, and the number
  /// which were extracted from the PEM but ultimately unsuitable.
  pub fn add_pem_file(&mut self, rd: &mut io::BufRead) -> Result<(usize, usize), ()> {
    let ders = try!(pemfile::certs(rd));
    let mut valid_count = 0;
    let mut invalid_count = 0;

    for der in ders {
      match self.add(&der) {
        Ok(_) => valid_count += 1,
        Err(err) => {
          debug!("invalid cert der {:?}", der);
          info!("certificate parsing failed: {:?}", err);
          invalid_count += 1
        }
      }
    }

    info!("add_pem_file processed {} valid and {} invalid certs",
          valid_count, invalid_count);

    Ok((valid_count, invalid_count))
  }
}

/// Check `presented_certs` is non-empty and rooted in `roots`.
/// Return the webpki::EndEntityCert for the top certificate
/// in `presented_certs`.
fn verify_common_cert<'a>(roots: &RootCertStore,
                          presented_certs: &'a [ASN1Cert])
    -> Result<webpki::EndEntityCert<'a>, TLSError> {
  if presented_certs.is_empty() {
    return Err(TLSError::NoCertificatesPresented);
  }

  /* EE cert must appear first. */
  let cert_der = untrusted::Input::from(&presented_certs[0].0);
  let cert = try!(
    webpki::EndEntityCert::from(cert_der)
      .map_err(|err| TLSError::WebPKIError(err))
  );

  let chain: Vec<untrusted::Input> = presented_certs.iter()
    .skip(1)
    .map(|cert| untrusted::Input::from(&cert.0))
    .collect();

  let trustroots: Vec<webpki::TrustAnchor> = roots.roots.iter()
    .map(|x| x.to_trust_anchor())
    .collect();

  if DANGEROUS_DISABLE_VERIFY {
    warn!("DANGEROUS_DISABLE_VERIFY is turned on, skipping certificate verification");
    return Ok(cert);
  }

  cert.verify_is_valid_tls_server_cert(&SUPPORTED_SIG_ALGS,
                                       &trustroots,
                                       &chain,
                                       time::get_time())
    .map_err(|err| TLSError::WebPKIError(err))
    .map(|_| cert)
}

/// Verify a the certificate chain `presented_certs` against the roots
/// configured in `roots`.  Make sure that `dns_name` is quoted by
/// the top certificate in the chain.
pub fn verify_server_cert(roots: &RootCertStore,
                          presented_certs: &Vec<ASN1Cert>,
                          dns_name: &str) -> Result<(), TLSError> {
  let cert = try!(verify_common_cert(roots, presented_certs));

  if DANGEROUS_DISABLE_VERIFY {
    warn!("DANGEROUS_DISABLE_VERIFY is turned on, skipping server name verification");
    return Ok(());
  }

  cert.verify_is_valid_for_dns_name(untrusted::Input::from(dns_name.as_bytes()))
    .map_err(|err| TLSError::WebPKIError(err))
}

/// Verify a certificate chain `presented_certs` is rooted in `roots`.
/// Does no further checking of the certificate.
pub fn verify_client_cert(roots: &RootCertStore,
                          presented_certs: &Vec<ASN1Cert>) -> Result<(), TLSError> {
  verify_common_cert(roots, presented_certs)
    .map(|_| ())
}

static ECDSA_SHA1: SignatureAlgorithms = &[
  &webpki::ECDSA_P256_SHA1, &webpki::ECDSA_P384_SHA1
];
static ECDSA_SHA256: SignatureAlgorithms = &[
  &webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA256
];
static ECDSA_SHA384: SignatureAlgorithms = &[
  &webpki::ECDSA_P256_SHA384, &webpki::ECDSA_P384_SHA384
];
static ECDSA_SHA512: SignatureAlgorithms = &[
  &webpki::ECDSA_P256_SHA512, &webpki::ECDSA_P384_SHA512
];

static RSA_SHA1: SignatureAlgorithms = &[ &webpki::RSA_PKCS1_2048_8192_SHA1 ];
static RSA_SHA256: SignatureAlgorithms = &[ &webpki::RSA_PKCS1_2048_8192_SHA256 ];
static RSA_SHA384: SignatureAlgorithms = &[ &webpki::RSA_PKCS1_2048_8192_SHA384 ];
static RSA_SHA512: SignatureAlgorithms = &[ &webpki::RSA_PKCS1_2048_8192_SHA512 ];

fn convert_alg(sh: &SignatureAndHashAlgorithm) -> Result<SignatureAlgorithms, TLSError> {
  use msgs::enums::SignatureAlgorithm::{ECDSA, RSA};
  use msgs::enums::HashAlgorithm::{SHA1, SHA256, SHA384, SHA512};

  match (&sh.sign, &sh.hash) {
    (&ECDSA, &SHA1)   => Ok(ECDSA_SHA1),
    (&ECDSA, &SHA256) => Ok(ECDSA_SHA256),
    (&ECDSA, &SHA384) => Ok(ECDSA_SHA384),
    (&ECDSA, &SHA512) => Ok(ECDSA_SHA512),
    (&RSA, &SHA1)     => Ok(RSA_SHA1),
    (&RSA, &SHA256)   => Ok(RSA_SHA256),
    (&RSA, &SHA384)   => Ok(RSA_SHA384),
    (&RSA, &SHA512)   => Ok(RSA_SHA512),
    _ => {
      let error_msg = format!("received unadvertised sigalg {:?} {:?}",
                              sh.sign, sh.hash);
      Err(TLSError::PeerMisbehavedError(error_msg))
    }
  }
}

fn verify_sig_using_any_alg(cert: &webpki::EndEntityCert,
                            algs: SignatureAlgorithms,
                            message: &[u8],
                            sig: &[u8]) -> Result<(), webpki::Error> {
  /* TLS doesn't itself give us enough info to map to a single webpki::SignatureAlgorithm.
   * Therefore, in convert_algs maps to several and we try them all. */
  for alg in algs {
    match cert.verify_signature(alg,
                                untrusted::Input::from(message),
                                untrusted::Input::from(sig)) {
      Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
      res => return res
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
                            dss: &DigitallySignedStruct) -> Result<(), TLSError> {

  let possible_algs = try!(convert_alg(&dss.alg));
  let cert_in = untrusted::Input::from(&cert.0);
  let cert = try!(webpki::EndEntityCert::from(cert_in)
                  .map_err(|err| TLSError::WebPKIError(err)));

  verify_sig_using_any_alg(&cert, &possible_algs, message, &dss.sig.0)
    .map_err(|err| TLSError::WebPKIError(err))
}

