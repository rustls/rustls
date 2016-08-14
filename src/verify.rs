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

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: &'static [&'static webpki::SignatureAlgorithm] = &[
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
fn verify_common_cert(roots: &RootCertStore,
                      presented_certs: &Vec<ASN1Cert>) -> Result<(), TLSError> {
  if presented_certs.len() == 0 {
    return Err(TLSError::NoCertificatesPresented);
  }

  /* EE cert must appear first. */
  let ee = untrusted::Input::from(&presented_certs[0].0);

  let chain: Vec<untrusted::Input> = presented_certs.iter()
    .skip(1)
    .map(|cert| untrusted::Input::from(&cert.0))
    .collect();

  let trustroots: Vec<webpki::TrustAnchor> = roots.roots.iter()
    .map(|x| x.to_trust_anchor())
    .collect();

  webpki::verify_tls_cert(&SUPPORTED_SIG_ALGS,
                          &trustroots,
                          &chain,
                          ee,
                          time::get_time())
    .map_err(|err| TLSError::WebPKIError(err))
}

/// Verify a the certificate chain `presented_certs` against the roots
/// configured in `roots`.  Make sure that `dns_name` is quoted by
/// the top certificate in the chain.
pub fn verify_server_cert(roots: &RootCertStore,
                          presented_certs: &Vec<ASN1Cert>,
                          dns_name: &str) -> Result<(), TLSError> {
  try!(verify_common_cert(roots, presented_certs));

  webpki::verify_cert_dns_name(
    untrusted::Input::from(&presented_certs[0].0),
    untrusted::Input::from(dns_name.as_bytes())
  )
  .map_err(|err| TLSError::WebPKIError(err))
}

/// Verify a certificate chain `presented_certs` is rooted in `roots`.
/// Does no further checking of the certificate.
pub fn verify_client_cert(roots: &RootCertStore,
                          presented_certs: &Vec<ASN1Cert>) -> Result<(), TLSError> {
  verify_common_cert(roots, presented_certs)
}

/* TODO: this is a bit gross. consider doing it another way */
static ECDSA_SHA1: &'static [u8] = b"\x06\x07\x2a\x86\x48\xce\x3d\x04\x01";
static ECDSA_SHA256: &'static [u8] = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
static ECDSA_SHA384: &'static [u8] = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03";
static ECDSA_SHA512: &'static [u8] = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04";
static RSA_SHA1: &'static [u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05";
static RSA_SHA256: &'static [u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b";
static RSA_SHA384: &'static [u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c";
static RSA_SHA512: &'static [u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d";


fn convert_alg(sh: &SignatureAndHashAlgorithm) -> Result<&'static [u8], TLSError> {
  use msgs::enums::SignatureAlgorithm::{ECDSA, RSA};
  use msgs::enums::HashAlgorithm::{SHA1, SHA256, SHA384, SHA512};

  match (&sh.sign, &sh.hash) {
    (&ECDSA, &SHA1) => Ok(ECDSA_SHA1),
    (&ECDSA, &SHA256) => Ok(ECDSA_SHA256),
    (&ECDSA, &SHA384) => Ok(ECDSA_SHA384),
    (&ECDSA, &SHA512) => Ok(ECDSA_SHA512),
    (&RSA, &SHA1) => Ok(RSA_SHA1),
    (&RSA, &SHA256) => Ok(RSA_SHA256),
    (&RSA, &SHA384) => Ok(RSA_SHA384),
    (&RSA, &SHA512) => Ok(RSA_SHA512),
    _ => Err(TLSError::General("convert_alg cannot map to oid".to_string()))
  }
}

/// Verify the signed `message` using the public key quoted in
/// `cert` and algorithm and signature in `dss`.
///
/// `cert` MUST have been authenticated before using this function,
/// typically using `verify_cert`.
pub fn verify_signed_struct(message: &[u8],
                            cert: &ASN1Cert,
                            dss: &DigitallySignedStruct) -> Result<(), TLSError> {

  let alg = try!(convert_alg(&dss.alg));

  let signed_data = webpki::signed_data::SignedData {
    data: untrusted::Input::from(message),
    algorithm: untrusted::Input::from(alg),
    signature: untrusted::Input::from(&dss.sig.0)
  };

  let cert_in = untrusted::Input::from(&cert.0);
  let cert = try!(webpki::trust_anchor_util::cert_der_as_trust_anchor(cert_in)
                  .map_err(|err| TLSError::WebPKIError(err)));

  webpki::signed_data::verify_signed_data(&SUPPORTED_SIG_ALGS,
                                          untrusted::Input::from(cert.spki),
                                          &signed_data)
    .map_err(|err| TLSError::WebPKIError(err))
}

