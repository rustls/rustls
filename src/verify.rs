extern crate webpki;
extern crate ring;
extern crate time;

use self::ring::input::Input;

use msgs::handshake::ASN1Cert;
use handshake::HandshakeError;

/* Which signature verification mechanisms we support.  No particular
 * order. */
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

/* This is like a webpki::TrustAnchor, except it owns
 * rather than borrows its memory.  That prevents lifetimes
 * leaking up the object tree. */
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

pub struct RootCertStore {
  roots: Vec<OwnedTrustAnchor>
}

impl RootCertStore {
  pub fn empty() -> RootCertStore {
    RootCertStore { roots: Vec::new() }
  }

  pub fn add(&mut self, der: &[u8]) -> Result<(), webpki::Error> {
    let ta = try!(
      webpki::trust_anchor_util::cert_der_as_trust_anchor(Input::new(der).unwrap())
    );

    let ota = OwnedTrustAnchor::from_trust_anchor(&ta);
    self.roots.push(ota);
    Ok(())
  }
}

pub fn verify_cert(roots: &RootCertStore,
                   presented_certs: &Vec<ASN1Cert>,
                   dns_name: &str) -> Result<(), HandshakeError> {
  if presented_certs.len() == 0 {
    return Err(HandshakeError::NoCertificatesPresented);
  }

  /* EE cert must appear first. */
  let ee = Input::new(&presented_certs[0].body).unwrap();

  let chain: Vec<Input> = presented_certs.iter()
    .skip(1)
    .map(|cert| Input::new(&cert.body).unwrap())
    .collect();

  let trustroots: Vec<webpki::TrustAnchor> = roots.roots.iter()
    .map(|x| x.to_trust_anchor())
    .collect();

  webpki::verify_tls_cert(&SUPPORTED_SIG_ALGS,
                          &trustroots,
                          &chain,
                          ee,
                          time::get_time())
    .and_then(|_| webpki::verify_cert_dns_name(ee,
                          Input::new(dns_name.as_bytes()).unwrap()))
    .map_err(|err| HandshakeError::WebPKIError(err))
}
