use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroize;

use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{ApiMisuse, Error, InvalidMessage};
use crate::msgs::base::hex;
use crate::msgs::codec::{self, Codec, Reader};
use crate::msgs::message::{MessageError, read_opaque_message_header};
use crate::suites::ConnectionTrafficSecrets;

mod inbound;
pub use inbound::{BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage};

mod outbound;
pub use outbound::{OutboundChunks, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload};

mod record_layer;
pub(crate) use record_layer::{Decrypted, PreEncryptAction, RecordLayer};

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.3 cipher suite.
pub trait Tls13AeadAlgorithm: Send + Sync {
    /// Build a `MessageEncrypter` for the given key/iv.
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;

    /// The length of key in bytes required by `encrypter()` and `decrypter()`.
    fn key_len(&self) -> usize;

    /// The length of IV in bytes required by `encrypter()` and `decrypter()`.
    fn iv_len(&self) -> usize {
        NONCE_LEN
    }

    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    ///
    /// May return [`UnsupportedOperationError`] if the AEAD algorithm is not a supported
    /// variant of `ConnectionTrafficSecrets`.
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.2 cipher suite.
pub trait Tls12AeadAlgorithm: Send + Sync + 'static {
    /// Build a `MessageEncrypter` for the given key/iv and extra key block (which can be used for
    /// improving explicit nonce size security, if needed).
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`KeyBlockShape::explicit_nonce_len`].
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;

    /// Return a `KeyBlockShape` that defines how large the `key_block` is and how it
    /// is split up prior to calling `encrypter()`, `decrypter()` and/or `extract_keys()`.
    fn key_block_shape(&self) -> KeyBlockShape;

    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`KeyBlockShape::explicit_nonce_len`].
    ///
    /// May return [`UnsupportedOperationError`] if the AEAD algorithm is not a supported
    /// variant of `ConnectionTrafficSecrets`.
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// An error indicating that the AEAD algorithm does not support the requested operation.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct UnsupportedOperationError;

impl From<UnsupportedOperationError> for Error {
    fn from(value: UnsupportedOperationError) -> Self {
        Self::General(value.to_string())
    }
}

impl fmt::Display for UnsupportedOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation not supported")
    }
}

#[cfg(feature = "std")]
impl core::error::Error for UnsupportedOperationError {}

/// How a TLS1.2 `key_block` is partitioned.
///
/// Note: ciphersuites with non-zero `mac_key_length` are  not currently supported.
#[expect(clippy::exhaustive_structs)]
pub struct KeyBlockShape {
    /// How long keys are.
    ///
    /// `enc_key_length` terminology is from the standard ([RFC5246 A.6]).
    ///
    /// [RFC5246 A.6]: <https://www.rfc-editor.org/rfc/rfc5246#appendix-A.6>
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// `fixed_iv_length` terminology is from the standard ([RFC5246 A.6]).
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    ///
    /// [RFC5246 A.6]: <https://www.rfc-editor.org/rfc/rfc5246#appendix-A.6>
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Decrypt the given TLS message `msg`, using the sequence number
    /// `seq` which can be used to derive a unique [`Nonce`].
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    /// Encrypt the given TLS message `msg`, using the sequence number
    /// `seq` which can be used to derive a unique [`Nonce`].
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error>;

    /// Return the length of the ciphertext that results from encrypting plaintext of
    /// length `payload_len`
    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
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

/// A write or read IV.
#[derive(Default, Clone)]
pub struct Iv {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Iv {
    /// Create a new `Iv` from a byte slice.
    ///
    /// Returns an error if the length of `value` exceeds [`Self::MAX_LEN`].
    pub fn new(value: &[u8]) -> Result<Self, Error> {
        if value.len() > Self::MAX_LEN {
            return Err(ApiMisuse::IvLengthExceedsMaximum {
                actual: value.len(),
                maximum: Self::MAX_LEN,
            }
            .into());
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..value.len()].copy_from_slice(value);
        Ok(Self {
            buf,
            used: value.len(),
        })
    }

    /// Return the IV length.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.used
    }

    /// Maximum supported IV length.
    pub const MAX_LEN: usize = 16;
}

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self::new(&bytes).expect("NONCE_LEN is within MAX_LEN")
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A nonce.  This is unique for all messages on a connection.
pub struct Nonce {
    buf: [u8; Iv::MAX_LEN],
    len: usize,
}

impl Nonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a big-endian integer.
    #[inline]
    pub fn new(iv: &Iv, seq: u64) -> Self {
        Self::new_inner(None, iv, seq)
    }

    /// Creates a unique nonce based on the multipath `path_id`, the `iv` and packet number `pn`.
    ///
    /// The nonce is computed as the XOR between the `iv` and the big-endian integer formed
    /// by concatenating `path_id` (or 0) and `pn`.
    pub fn quic(path_id: Option<u32>, iv: &Iv, pn: u64) -> Self {
        Self::new_inner(path_id, iv, pn)
    }

    /// Creates a unique nonce based on the iv and sequence number seq.
    #[inline]
    fn new_inner(path_id: Option<u32>, iv: &Iv, seq: u64) -> Self {
        let iv_len = iv.len();
        let mut buf = [0u8; Iv::MAX_LEN];

        if iv_len >= 8 {
            codec::put_u64(seq, &mut buf[iv_len - 8..iv_len]);
            if let Some(path_id) = path_id {
                if iv_len >= 12 {
                    buf[iv_len - 12..iv_len - 8].copy_from_slice(&path_id.to_be_bytes());
                }
            }
        } else {
            let seq_bytes = seq.to_be_bytes();
            buf[..iv_len].copy_from_slice(&seq_bytes[8 - iv_len..]);
        }

        buf[..iv_len]
            .iter_mut()
            .zip(iv.as_ref())
            .for_each(|(s, iv)| *s ^= *iv);

        Self { buf, len: iv_len }
    }

    /// Convert to a fixed-size array of length `N`.
    ///
    /// Returns an error if the nonce length is not `N`.
    ///
    /// For standard nonces, use `nonce.to_array::<NONCE_LEN>()?` or just `nonce.to_array()?`
    /// which defaults to `NONCE_LEN`.
    pub fn to_array<const N: usize>(&self) -> Result<[u8; N], Error> {
        if self.len != N {
            return Err(ApiMisuse::NonceArraySizeMismatch {
                expected: N,
                actual: self.len,
            }
            .into());
        }
        Ok(self.buf[..N]
            .try_into()
            .expect("nonce buffer conversion failed"))
    }

    /// Return the nonce value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the nonce length.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Size of TLS nonces (incorrectly termed "IV" in standard) for all supported ciphersuites
/// (AES-GCM, Chacha20Poly1305)
pub const NONCE_LEN: usize = 12;

/// Returns a TLS1.3 `additional_data` encoding.
///
/// See RFC8446 s5.2 for the `additional_data` definition.
#[inline]
pub fn make_tls13_aad(payload_len: usize) -> [u8; 5] {
    let version = ProtocolVersion::TLSv1_2.to_array();
    [
        ContentType::ApplicationData.into(),
        // Note: this is `legacy_record_version`, i.e. TLS1.2 even for TLS1.3.
        version[0],
        version[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

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
    out[8] = typ.into();
    codec::put_u16(vers.into(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    out
}

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// A key for an AEAD algorithm.
///
/// This is a value type for a byte string up to `AeadKey::MAX_LEN` bytes in length.
pub struct AeadKey {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl AeadKey {
    pub(crate) fn new(buf: &[u8]) -> Self {
        debug_assert!(buf.len() <= Self::MAX_LEN);
        let mut key = Self::from([0u8; Self::MAX_LEN]);
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

    /// Largest possible AEAD key in the ciphersuites we support.
    pub(crate) const MAX_LEN: usize = 32;
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl From<[u8; Self::MAX_LEN]> for AeadKey {
    fn from(bytes: [u8; Self::MAX_LEN]) -> Self {
        Self {
            buf: bytes,
            used: Self::MAX_LEN,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[expect(clippy::exhaustive_structs)]
#[derive(Clone, Debug)]
pub struct PlainMessage {
    /// The content type of this message.
    pub typ: ContentType,
    /// The protocol version of this message.
    pub version: ProtocolVersion,
    /// The payload of this message.
    pub payload: Payload<'static>,
}

impl PlainMessage {
    /// Construct by decoding from a [`Reader`].
    ///
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, MessageError> {
        let (typ, version, len) = read_opaque_message_header(r)?;

        let content = r
            .take(len as usize)
            .ok_or(MessageError::TooShortForLength)?;

        Ok(Self {
            typ,
            version,
            payload: Payload::Owned(content.to_vec()),
        })
    }

    /// Convert into an unencrypted [`OutboundOpaqueMessage`] (without decrypting).
    pub fn into_unencrypted_opaque(self) -> OutboundOpaqueMessage {
        OutboundOpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: PrefixedPayload::from(self.payload.bytes()),
        }
    }

    /// Borrow as an [`InboundPlainMessage`].
    pub fn borrow_inbound(&self) -> InboundPlainMessage<'_> {
        InboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes(),
        }
    }

    /// Borrow as an [`OutboundPlainMessage`].
    pub fn borrow_outbound(&self) -> OutboundPlainMessage<'_> {
        OutboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes().into(),
        }
    }
}

/// An externally length'd payload
#[non_exhaustive]
#[derive(Clone, Eq, PartialEq)]
pub enum Payload<'a> {
    /// Borrowed payload
    Borrowed(&'a [u8]),
    /// Owned payload
    Owned(Vec<u8>),
}

impl<'a> Payload<'a> {
    /// A reference to the payload's bytes
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Borrowed(bytes) => bytes.to_vec(),
            Self::Owned(bytes) => bytes,
        }
    }

    pub(crate) fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }
}

impl Payload<'static> {
    /// Create a new owned payload from the given `bytes`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Owned(bytes.into())
    }
}

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.bytes());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(f, self.bytes())
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(
        &mut self,
        _m: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        _m: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

#[cfg(all(test, feature = "aws-lc-rs"))]
pub(crate) struct FakeAead;

#[cfg(all(test, feature = "aws-lc-rs"))]
impl Tls12AeadAlgorithm for FakeAead {
    fn encrypter(&self, _: AeadKey, _: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        todo!()
    }

    fn decrypter(&self, _: AeadKey, _: &[u8]) -> Box<dyn MessageDecrypter> {
        todo!()
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        todo!()
    }

    fn extract_keys(
        &self,
        _: AeadKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Using test values provided in the spec in
    /// <https://www.ietf.org/archive/id/draft-ietf-quic-multipath-15.html#section-2.4>
    #[test]
    fn multipath_nonce() {
        const PATH_ID: u32 = 3;
        const PN: u64 = 54321;
        const IV: [u8; 16] = 0x6b26114b9cba2b63a9e8dd4fu128.to_be_bytes();
        const EXPECTED_NONCE: [u8; 16] = 0x6b2611489cba2b63a9e8097eu128.to_be_bytes();
        let nonce = Nonce::quic(Some(PATH_ID), &Iv::new(&IV[4..]).unwrap(), PN);
        assert_eq!(&EXPECTED_NONCE[4..], nonce.as_bytes());
    }

    #[test]
    fn iv_len() {
        let iv = Iv::new(&[1u8; NONCE_LEN]).unwrap();
        assert_eq!(iv.len(), NONCE_LEN);

        let short_iv = Iv::new(&[1u8, 2, 3]).unwrap();
        assert_eq!(short_iv.len(), 3);

        let empty_iv = Iv::new(&[]).unwrap();
        assert_eq!(empty_iv.len(), 0);
    }

    #[test]
    fn iv_as_ref() {
        let iv_data = [1u8, 2, 3, 4, 5];
        let iv = Iv::new(&iv_data).unwrap();
        let iv_ref: &[u8] = iv.as_ref();
        assert_eq!(iv_ref, &iv_data);
    }

    #[test]
    fn nonce_with_short_iv() {
        let short_iv = Iv::new(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let seq = 0x1122334455667788u64;
        let nonce = Nonce::new(&short_iv, seq);

        // The nonce should XOR the last 4 bytes of seq with the IV
        assert_eq!(nonce.len(), 4);
        let seq_bytes = seq.to_be_bytes();
        let expected = [
            0xAA ^ seq_bytes[4],
            0xBB ^ seq_bytes[5],
            0xCC ^ seq_bytes[6],
            0xDD ^ seq_bytes[7],
        ];
        assert_eq!(nonce.as_bytes(), &expected);
    }

    #[test]
    fn nonce_len() {
        let iv = Iv::new(&[1u8; NONCE_LEN]).unwrap();
        let nonce = Nonce::new(&iv, 42);
        assert_eq!(nonce.len(), NONCE_LEN);

        let short_iv = Iv::new(&[1u8, 2]).unwrap();
        let short_nonce = Nonce::new(&short_iv, 42);
        assert_eq!(short_nonce.len(), 2);
    }

    #[test]
    fn nonce_as_ref() {
        let iv = Iv::new(&[1u8; NONCE_LEN]).unwrap();
        let nonce = Nonce::new(&iv, 42);
        let nonce_ref: &[u8] = nonce.as_ref();
        assert_eq!(nonce_ref.len(), NONCE_LEN);
    }

    #[test]
    fn nonce_to_array_correct_size() {
        let iv = Iv::new(&[1u8; NONCE_LEN]).unwrap();
        let nonce = Nonce::new(&iv, 42);
        let array: [u8; NONCE_LEN] = nonce.to_array().unwrap();
        assert_eq!(array.len(), NONCE_LEN);
    }

    #[test]
    fn nonce_to_array_wrong_size() {
        let iv = Iv::new(&[1u8; NONCE_LEN]).unwrap();
        let nonce = Nonce::new(&iv, 42);
        let result: Result<[u8; 16], Error> = nonce.to_array();
        assert!(matches!(
            result,
            Err(Error::ApiMisuse(ApiMisuse::NonceArraySizeMismatch {
                expected: 16,
                actual: NONCE_LEN
            }))
        ));
    }

    #[test]
    fn nonce_to_array_variable_length_error() {
        // Create an IV with a non-standard length (8 bytes instead of 12)
        let short_iv = Iv::new(&[0xAAu8; 8]).unwrap();
        let nonce = Nonce::new(&short_iv, 42);

        // Attempting to convert to standard NONCE_LEN should fail
        let result: Result<[u8; NONCE_LEN], Error> = nonce.to_array();
        if let Err(Error::ApiMisuse(ApiMisuse::NonceArraySizeMismatch { expected, actual })) =
            result
        {
            assert_eq!(expected, NONCE_LEN);
            assert_eq!(actual, 8);
        } else {
            panic!("Expected Error::ApiMisuse(NonceArraySizeMismatch)");
        }

        // But converting to the correct length should work
        let result_correct: Result<[u8; 8], Error> = nonce.to_array();
        assert!(result_correct.is_ok());
    }

    #[test]
    fn nonce_xor_with_iv() {
        let iv_data = [0xFFu8; NONCE_LEN];
        let iv = Iv::new(&iv_data).unwrap();
        let seq = 0x0000000000000001u64;
        let nonce = Nonce::new(&iv, seq);

        // The last byte should be 0xFF XOR 0x01 = 0xFE
        let nonce_bytes = nonce.as_bytes();
        assert_eq!(nonce_bytes[NONCE_LEN - 1], 0xFE);
    }

    #[test]
    fn iv_length_exceeds_maximum() {
        let too_long_iv = [0xAAu8; Iv::MAX_LEN + 1];
        let result = Iv::new(&too_long_iv);

        assert!(matches!(
            result,
            Err(Error::ApiMisuse(ApiMisuse::IvLengthExceedsMaximum {
                actual: 17,
                maximum: 16
            }))
        ));
    }
}
