use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::FipsStatus;
use zeroize::Zeroize;

use crate::Error;
use crate::error::InvalidMessage;
use crate::msgs::{Codec, ListLength, Reader, TlsListElement};

/// An HPKE suite, specifying a key encapsulation mechanism and a symmetric cipher suite.
#[expect(clippy::exhaustive_structs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        &self,
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
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error>;

    /// Open the provided `ciphertext` using the encapsulated secret `enc`, with application
    /// supplied `info`, and additional data `aad`.
    ///
    /// Returns plaintext if  the `info` and `aad` match those used with [Self::seal], and
    /// decryption with `secret_key` succeeds. RFC 9180 refers to `secret_key` as `skR`.
    fn open(
        &self,
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
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error>;

    /// Generate a new public key and private key pair compatible with this HPKE instance.
    ///
    /// Key pairs should be encoded as raw big endian fixed length integers sized based
    /// on the suite's DH KEM algorithm.
    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error>;

    /// Return the FIPS validation status of the HPKE instance.
    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }

    /// Return the [HpkeSuite] that this HPKE instance supports.
    fn suite(&self) -> HpkeSuite;
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
#[expect(clippy::exhaustive_structs)]
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

/// An HPKE symmetric cipher suite, combining a KDF and an AEAD algorithm.
#[expect(clippy::exhaustive_structs)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HpkeSymmetricCipherSuite {
    /// The KDF to use for this cipher suite.
    pub kdf_id: HpkeKdf,
    /// The AEAD to use for this cipher suite.
    pub aead_id: HpkeAead,
}

impl Codec<'_> for HpkeSymmetricCipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            kdf_id: HpkeKdf::read(r)?,
            aead_id: HpkeAead::read(r)?,
        })
    }
}

/// draft-ietf-tls-esni-24: `HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;`
impl TlsListElement for HpkeSymmetricCipherSuite {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("HpkeSymmetricCipherSuites"),
    };
}

enum_builder! {
    /// The Key Encapsulation Mechanism (`Kem`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.1]
    ///
    /// [RFC 9180 Section 7.1]: <https://datatracker.ietf.org/doc/html/rfc9180#kemid-values>
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    pub enum HpkeKem {
        DHKEM_P256_HKDF_SHA256 => 0x0010,
        DHKEM_P384_HKDF_SHA384 => 0x0011,
        DHKEM_P521_HKDF_SHA512 => 0x0012,
        DHKEM_X25519_HKDF_SHA256 => 0x0020,
        DHKEM_X448_HKDF_SHA512 => 0x0021,
    }
}

enum_builder! {
    /// The Key Derivation Function (`Kdf`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.2]
    ///
    /// [RFC 9180 Section 7.2]: <https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd>
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub enum HpkeKdf {
        // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
        #[default]
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

enum_builder! {
    /// The Authenticated Encryption with Associated Data (`Aead`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.3]
    ///
    /// [RFC 9180 Section 7.3]: <https://datatracker.ietf.org/doc/html/rfc9180#name-authenticated-encryption-wi>
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    pub enum HpkeAead {
        // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
        #[default]
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        CHACHA20_POLY_1305 => 0x0003,
        EXPORT_ONLY => 0xFFFF,
    }
}

impl HpkeAead {
    /// Returns the length of the tag for the AEAD algorithm, or none if the AEAD is EXPORT_ONLY.
    pub(crate) fn tag_len(&self) -> Option<usize> {
        match self {
            // See RFC 9180 Section 7.3, column `Nt`, the length in bytes of the authentication tag
            // for the algorithm.
            // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
            Self::AES_128_GCM | Self::AES_256_GCM | Self::CHACHA20_POLY_1305 => Some(16),
            _ => None,
        }
    }
}

/// An HPKE key pair, made of a matching public and private key.
#[expect(clippy::exhaustive_structs)]
pub struct HpkeKeyPair {
    /// A HPKE public key.
    pub public_key: HpkePublicKey,
    /// A HPKE private key.
    pub private_key: HpkePrivateKey,
}

/// An encapsulated secret returned from setting up a sender or receiver context.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct EncapsulatedSecret(pub Vec<u8>);
