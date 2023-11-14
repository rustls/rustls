use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::msgs::enums::HpkeKem;
use crate::msgs::handshake::HpkeSymmetricCipherSuite;
use crate::Error;

/// A provider for [RFC 9180] Hybrid Public Key Encryption (HPKE) in base mode.
///
/// At a minimum each provider must support the [HPKE ciphersuite profile] required for
/// encrypted client hello (ECH):
///  * KEM: DHKEM(X25519, HKDF-SHA256)
///  * symmetric ciphersuite:  AES-128-GCM w/ HKDF-SHA256
///
/// [RFC 9180]: <https://www.rfc-editor.org/rfc/rfc9180.html>
/// [HPKE ciphersuite profile]: <https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-9>
pub trait HpkeProvider: Debug + Send + Sync + 'static {
    /// Start setting up to use HPKE in base mode with the chosen suite.
    ///
    /// May return an error if the suite is unsupported by the provider.
    fn start(&self, suite: &HpkeSuite) -> Result<Box<dyn Hpke>, Error>;

    /// Does the provider support the given [HpkeSuite]?
    fn supports_suite(&self, suite: &HpkeSuite) -> bool;
}

/// An HPKE suite, specifying a key encapsulation mechanism and a symmetric cipher suite.
pub struct HpkeSuite {
    /// The choice of HPKE key encapsulation mechanism.
    pub kem: HpkeKem,

    /// The choice of HPKE symmetric cipher suite.
    ///
    /// This combines a choice of authenticated encryption with additional data (AEAD) algorithm
    /// and a key derivation function (KDF).
    pub sym: HpkeSymmetricCipherSuite,
}

/// An HPKE instance that can be used for base-mode single-shot encryption and decryption.
pub trait Hpke: Debug + Send + Sync {
    /// Seal the provided `plaintext` to the recipient public key `pk_r` with application supplied
    /// `info`, and additional data `aad`.
    ///
    /// Returns ciphertext that can be used with [Self::open] by the recipient to recover plaintext
    /// using the same `info` and `aad` and the private key corresponding to `pk_r`.
    fn seal(
        &mut self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error>;

    /// Open the provided `ciphertext` using the encapsulated secret `enc`, with application
    /// supplied `info`, and additional data `aad`.
    ///
    /// Returns plaintext if  the `info` and `aad` match those used with [Self::seal], and
    /// decryption with `sk_r` succeeds.
    fn open(
        &mut self,
        enc: &EncapsulatedSecret,
        sk_r: &HpkePrivateKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

/// An HPKE public key.
pub struct HpkePublicKey(pub Vec<u8>);

/// An HPKE private key.
pub struct HpkePrivateKey(Vec<u8>);

impl HpkePrivateKey {
    /// Return the private key bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// An HPKE key pair, made of a matching public and private key.
pub struct HpkeKeyPair {
    /// A HPKE public key.
    pub public_key: HpkePublicKey,
    /// A HPKE private key.
    pub private_key: HpkePrivateKey,
}

/// An encapsulated secret returned from setting up a sender or receiver context.
pub struct EncapsulatedSecret(pub Vec<u8>);
