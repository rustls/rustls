use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::codec;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
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
    ///
    /// The length of `key` is set by [`crate::Tls12CipherSuite::aead_key_len`].
    ///
    /// The length of `iv` is set by [`crate::Tls12CipherSuite::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`crate::Tls12CipherSuite::explicit_nonce_len`].
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    ///
    /// The length of `key` is set by [`crate::Tls12CipherSuite::aead_key_len`].
    ///
    /// The length of `iv` is set by [`crate::Tls12CipherSuite::fixed_iv_len`].
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;

    #[cfg(feature = "secret_extraction")]
    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    ///
    /// The length of `key` is set by [`crate::Tls12CipherSuite::aead_key_len`].
    ///
    /// The length of `iv` is set by [`crate::Tls12CipherSuite::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`crate::Tls12CipherSuite::explicit_nonce_len`].
    fn extract_keys(&self, key: AeadKey, iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets;
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.
    fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;

    /// For TLS1.3 (only), checks the length m.payload is valid and removes the padding.
    fn tls13_check_length_and_unpad(&self, mut msg: OpaqueMessage) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(payload);
        if msg.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.version = ProtocolVersion::TLSv1_3;
        Ok(msg.into_plain_message())
    }
}

/// `v` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
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
    /// Create a new `Iv` from a byte slice, of precisely `NONCE_LEN` bytes.
    pub fn copy(value: &[u8]) -> Self {
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
#[inline]
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

/// Returns a TLS1.3 `additional_data` encoding.
///
/// See RFC8446 s5.2 for the `additional_data` definition.
#[inline]
pub fn make_tls13_aad(payload_len: usize) -> [u8; 5] {
    [
        ContentType::ApplicationData.get_u8(),
        // nb. this is `legacy_record_version`, ie TLS1.2 even for TLS1.3.
        (ProtocolVersion::TLSv1_2.get_u16() >> 8) as u8,
        (ProtocolVersion::TLSv1_2.get_u16() & 0xff) as u8,
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// Returns a TLS1.2 `additional_data` encoding.
///
/// See RFC5246 s6.2.3.3 for the `additional_data` definition.
#[inline]
pub fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.get_u8();
    codec::put_u16(vers.get_u16(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    out
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
    #[cfg(feature = "tls12")]
    pub(crate) fn new(buf: &[u8]) -> Self {
        debug_assert!(buf.len() <= MAX_AEAD_KEY_LEN);
        let mut key = Self::from([0u8; MAX_AEAD_KEY_LEN]);
        key.buf[..buf.len()].copy_from_slice(buf);
        key.used = buf.len();
        key
    }

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
