use msgs::enums::{SignatureAlgorithm, SignatureScheme};
use util;
use key;
use error::TLSError;

use untrusted;

use ring;
use ring::signature;
use ring::signature::RSAKeyPair;

use std::sync::Arc;

/// An abstract signing key.
pub trait SigningKey : Send + Sync {
    /// Choose a SignatureScheme from those offered.
    ///
    /// Expresses the choice something that implements Signer,
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

/// A packaged together certificate chain and matching SigningKey.
pub type CertChainAndSigningKey = (Vec<key::Certificate>, Arc<Box<SigningKey>>);

/// A SigningKey for RSA-PKCS1 or RSA-PSS
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
    /// Make a new RSASigningKey from a DER encoding, in either
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
