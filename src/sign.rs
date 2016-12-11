use msgs::enums::{SignatureAlgorithm, SignatureScheme};
use msgs::handshake::SupportedSignatureSchemes;
use util;
use untrusted;
use ring;
use ring::signature;
use std::sync::Arc;
use key;

/// A thing that can sign a message.
pub trait Signer {
    /// Choose a SignatureScheme from those offered.
    fn choose_scheme(&self, offered: &SupportedSignatureSchemes) -> Option<SignatureScheme>;

    /// Signs `message` using `scheme`.
    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ()>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A Signer for RSA-PKCS1 or RSA-PSS
pub struct RSASigner {
    key: Arc<signature::RSAKeyPair>,
    schemes: SupportedSignatureSchemes,
}

fn all_schemes() -> SupportedSignatureSchemes {
    vec![
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
  ]
}

impl RSASigner {
    pub fn new(der: &key::PrivateKey) -> Result<RSASigner, ()> {
        let key = signature::RSAKeyPair::from_der(untrusted::Input::from(&der.0));
        key.map(|s| {
                RSASigner {
                    key: Arc::new(s),
                    schemes: all_schemes(),
                }
            })
            .map_err(|_| ())
    }
}

impl Signer for RSASigner {
    fn choose_scheme(&self, offered: &SupportedSignatureSchemes) -> Option<SignatureScheme> {
        util::first_in_both(&self.schemes, offered)
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let encoding: &signature::RSAEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => return Err(()),
        };

        let rng = ring::rand::SystemRandom::new();
        let mut signer = try!(
      signature::RSASigningState::new(self.key.clone())
      .map_err(|_| ())
    );

        signer.sign(encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| ())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}
