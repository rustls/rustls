use msgs::enums::{SignatureAlgorithm, SignatureScheme};
use util;
use key;
use error::TLSError;

use untrusted;

use ring;
use ring::signature;
use ring::signature::RSAKeyPair;

use std::sync::Arc;
use std::mem;

/// An abstract signing key.
pub trait SigningKey : Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer : Send + Sync {
    /// Signs `message` using the selected scheme.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError>;

    /// Reveals which scheme will be used when you call `sign()`.
    fn get_scheme(&self) -> SignatureScheme;
}

/// A packaged together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response and/or SCT.
#[derive(Clone)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<key::Certificate>,

    /// The certified key.
    pub key: Arc<Box<SigningKey>>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,

    /// An optional collection of SCTs from CT logs, proving the
    /// certificate is included on those logs.  This must be
    /// a `SignedCertificateTimestampList` encoding; see RFC6962.
    pub sct_list: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<key::Certificate>, key: Arc<Box<SigningKey>>) -> CertifiedKey {
        CertifiedKey { cert: cert, key: key, ocsp: None, sct_list: None }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&key::Certificate, ()> {
        self.cert.get(0).ok_or(())
    }

    /// Steal ownership of the certificate chain.
    pub fn take_cert(&mut self) -> Vec<key::Certificate> {
        mem::replace(&mut self.cert, Vec::new())
    }

    /// Return true if there's an OCSP response.
    pub fn has_ocsp(&self) -> bool {
        self.ocsp.is_some()
    }

    /// Steal ownership of the OCSP response.
    pub fn take_ocsp(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.ocsp, None)
    }

    /// Return true if there's an SCT list.
    pub fn has_sct_list(&self) -> bool {
        self.sct_list.is_some()
    }

    /// Steal ownership of the SCT list.
    pub fn take_sct_list(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.sct_list, None)
    }
}

/// A `SigningKey` for RSA-PKCS1 or RSA-PSS
pub struct RSASigningKey {
    key: Arc<RSAKeyPair>,
}

static ALL_RSA_SCHEMES: &'static [SignatureScheme] = &[
     SignatureScheme::RSA_PSS_SHA512,
     SignatureScheme::RSA_PSS_SHA384,
     SignatureScheme::RSA_PSS_SHA256,
     SignatureScheme::RSA_PKCS1_SHA512,
     SignatureScheme::RSA_PKCS1_SHA384,
     SignatureScheme::RSA_PKCS1_SHA256,
];

impl RSASigningKey {
    /// Make a new `RSASigningKey` from a DER encoding, in either
    /// PKCS#1 or PKCS#8 format.
    pub fn new(der: &key::PrivateKey) -> Result<RSASigningKey, ()> {
        RSAKeyPair::from_der(untrusted::Input::from(&der.0))
            .or_else(|_| RSAKeyPair::from_pkcs8(untrusted::Input::from(&der.0)))
            .map(|s| {
                 RSASigningKey {
                     key: Arc::new(s),
                 }
            })
            .map_err(|_| ())
    }
}

impl SigningKey for RSASigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<Signer>> {
        util::first_in_both(ALL_RSA_SCHEMES, offered)
            .map(|scheme| RSASigner::new(self.key.clone(), scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

struct RSASigner {
    key: Arc<RSAKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static signature::RSAEncoding
}

impl RSASigner {
    fn new(key: Arc<RSAKeyPair>, scheme: SignatureScheme) -> Box<Signer> {
        let encoding: &signature::RSAEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        Box::new(RSASigner { key, scheme, encoding })
    }
}

impl Signer for RSASigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let rng = ring::rand::SystemRandom::new();
        let mut signer = signature::RSASigningState::new(self.key.clone())
            .map_err(|_| TLSError::General("signing state creation failed".to_string()))?;

        signer.sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| TLSError::General("signing failed".to_string()))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
