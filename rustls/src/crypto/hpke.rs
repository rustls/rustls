use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use zeroize::Zeroize;

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
    fn start(&self, suite: &HpkeSuite) -> Result<Box<dyn Hpke + 'static>, Error>;

    /// Does the provider support the given [HpkeSuite]?
    fn supports_suite(&self, suite: &HpkeSuite) -> bool;
}

/// An HPKE suite, specifying a key encapsulation mechanism and a symmetric cipher suite.
#[derive(Clone, Copy, Debug)]
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
    /// Seal the provided `plaintext` to the recipient public key `pub_key` with application supplied
    /// `info`, and additional data `aad`.
    ///
    /// Returns ciphertext that can be used with [Self::open] by the recipient to recover plaintext
    /// using the same `info` and `aad` and the private key corresponding to `pub_key`. RFC 9180
    /// refers to `pub_key` as `pkR`.
    fn seal(
        &mut self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error>;

    /// Set up a sealer context for the receiver public key `pub_key` with application supplied `info`.
    ///
    /// Returns both an encapsulated ciphertext and a sealer context that can be used to seal
    /// messages to the recipient. RFC 9180 refers to `pub_key` as `pkR`.
    fn setup_sealer(
        &mut self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error>;

    /// Open the provided `ciphertext` using the encapsulated secret `enc`, with application
    /// supplied `info`, and additional data `aad`.
    ///
    /// Returns plaintext if  the `info` and `aad` match those used with [Self::seal], and
    /// decryption with `secret_key` succeeds. RFC 9180 refers to `secret_key` as `skR`.
    fn open(
        &mut self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error>;

    /// Set up an opener context for the secret key `secret_key` with application supplied `info`.
    ///
    /// Returns an opener context that can be used to open sealed messages encrypted to the
    /// public key corresponding to `secret_key`. RFC 9180 refers to `secret_key` as `skR`.
    fn setup_opener(
        &mut self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error>;
}

/// An HPKE sealer context.
///
/// This is a stateful object that can be used to seal messages for receipt by
/// a receiver.
pub trait HpkeSealer: Debug + Send + Sync + 'static {
    /// Seal the provided `plaintext` with additional data `aad`, returning
    /// ciphertext.
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
}

/// An HPKE opener context.
///
/// This is a stateful object that can be used to open sealed messages sealed
/// by a sender.
pub trait HpkeOpener: Debug + Send + Sync + 'static {
    /// Open the provided `ciphertext` with additional data `aad`, returning plaintext.
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

/// An HPKE public key.
#[derive(Clone, Debug)]
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

impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
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
#[derive(Debug)]
pub struct EncapsulatedSecret(pub Vec<u8>);
