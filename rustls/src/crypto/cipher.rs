use crate::error::Error;
use crate::msgs::codec;
pub use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.3 cipher suites.
pub trait Tls13AeadAlgorithm: Send + Sync {
    /// Build a `MessageEncrypter` for the given key/iv.
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;

    /// The length of key in bytes required by `encrypter()` and `decrypter()`.
    fn key_len(&self) -> usize;

    #[cfg(feature = "secret_extraction")]
    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.3 cipher suites.
pub trait Tls12AeadAlgorithm: Send + Sync + 'static {
    /// Build a `MessageEncrypter` for the given key/iv and extra key block (which can be used for
    /// improving explicit nonce size security, if needed).
    fn encrypter(&self, key: &[u8], iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    fn decrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn MessageDecrypter>;

    #[cfg(feature = "secret_extraction")]
    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    fn extract_keys(&self, key: &[u8], iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets;
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.
    fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    /// Encrypt the message `m`.
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

/// Size of TLS nonces (incorrectly termed "IV" in standard) for all supported ciphersuites
/// (AES-GCM, Chacha20Poly1305)
const NONCE_LEN: usize = 12;

/// A write or read IV.
#[derive(Default)]
pub struct Iv(pub(crate) [u8; NONCE_LEN]);

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

impl Iv {
    #[cfg(feature = "tls12")]
    fn new(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// Combine an `Iv` and sequence number to produce a unique nonce.
///
/// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
pub fn make_nonce(iv: &Iv, seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce
        .iter_mut()
        .zip(iv.0.iter())
        .for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

    nonce
}

/// Largest possible AEAD key in the ciphersuites we support.
const MAX_AEAD_KEY_LEN: usize = 32;

/// A key for an AEAD algorithm.
///
/// This is a value type for a byte string up to `MAX_AEAD_KEY_LEN` bytes in length.
pub struct AeadKey {
    buf: [u8; MAX_AEAD_KEY_LEN],
    used: usize,
}

impl From<[u8; MAX_AEAD_KEY_LEN]> for AeadKey {
    fn from(bytes: [u8; MAX_AEAD_KEY_LEN]) -> Self {
        Self {
            buf: bytes,
            used: MAX_AEAD_KEY_LEN,
        }
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl AeadKey {
    pub(crate) fn with_length(self, len: usize) -> Self {
        assert!(len <= self.used);
        Self {
            buf: self.buf,
            used: len,
        }
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowedPlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }
}
