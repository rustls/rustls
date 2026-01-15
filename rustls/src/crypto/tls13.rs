use alloc::boxed::Box;
use alloc::vec::Vec;

use pki_types::FipsStatus;
use zeroize::Zeroize;

use super::hmac;
use super::kx::ActiveKeyExchange;
use crate::enums::ProtocolVersion;
use crate::error::Error;

/// Implementation of `HkdfExpander` via `hmac::Key`.
pub struct HkdfExpanderUsingHmac(Box<dyn hmac::Key>);

impl HkdfExpanderUsingHmac {
    fn expand_unchecked(&self, info: &[&[u8]], output: &mut [u8]) {
        let mut term = hmac::Tag::new(b"");

        for (n, chunk) in output
            .chunks_mut(self.0.tag_len())
            .enumerate()
        {
            term = self
                .0
                .sign_concat(term.as_ref(), info, &[(n + 1) as u8]);
            chunk.copy_from_slice(&term.as_ref()[..chunk.len()]);
        }
    }
}

impl HkdfExpander for HkdfExpanderUsingHmac {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        if output.len() > 255 * self.0.tag_len() {
            return Err(OutputLengthError);
        }

        self.expand_unchecked(info, output);
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut tag = [0u8; hmac::Tag::MAX_LEN];
        let reduced_tag = &mut tag[..self.0.tag_len()];
        self.expand_unchecked(info, reduced_tag);
        OkmBlock::new(reduced_tag)
    }

    fn hash_len(&self) -> usize {
        self.0.tag_len()
    }
}

/// Implementation of `Hkdf` (and thence `HkdfExpander`) via `hmac::Hmac`.
#[expect(clippy::exhaustive_structs)]
pub struct HkdfUsingHmac<'a>(pub &'a dyn hmac::Hmac);

impl Hkdf for HkdfUsingHmac<'_> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; hmac::Tag::MAX_LEN];
        Box::new(HkdfExpanderUsingHmac(self.0.with_key(
            &self.extract_prk_from_secret(salt, &zeroes[..self.0.hash_output_len()]),
        )))
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(HkdfExpanderUsingHmac(
            self.0
                .with_key(&self.extract_prk_from_secret(salt, secret)),
        ))
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(HkdfExpanderUsingHmac(self.0.with_key(okm.as_ref())))
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag {
        self.0
            .with_key(key.as_ref())
            .sign(&[message])
    }
}

impl HkdfPrkExtract for HkdfUsingHmac<'_> {
    fn extract_prk_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Vec<u8> {
        let zeroes = [0u8; hmac::Tag::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.hash_output_len()],
        };
        self.0
            .with_key(salt)
            .sign(&[secret])
            .as_ref()
            .to_vec()
    }
}

/// Implementation of `HKDF-Expand` with an implicitly stored and immutable `PRK`.
pub trait HkdfExpander: Send + Sync {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where:
    ///
    /// - `PRK` is the implicit key material represented by this instance.
    /// - `L` is `output.len()`.
    /// - `info` is a slice of byte slices, which should be processed sequentially
    ///   (or concatenated if that is not possible).
    ///
    /// Returns `Err(OutputLengthError)` if `L` is larger than `255 * HashLen`.
    /// Otherwise, writes to `output`.
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError>;

    /// `HKDF-Expand(PRK, info, L=HashLen)` returned as a value.
    ///
    /// - `PRK` is the implicit key material represented by this instance.
    /// - `L := HashLen`.
    /// - `info` is a slice of byte slices, which should be processed sequentially
    ///   (or concatenated if that is not possible).
    ///
    /// This is infallible, because by definition `OkmBlock` is always exactly
    /// `HashLen` bytes long.
    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock;

    /// Return what `HashLen` is for this instance.
    ///
    /// This must be no larger than [`OkmBlock::MAX_LEN`].
    fn hash_len(&self) -> usize;
}

/// A HKDF implementation oriented to the needs of TLS1.3.
///
/// See [RFC5869](https://datatracker.ietf.org/doc/html/rfc5869) for the terminology
/// used in this definition.
///
/// You can use [`HkdfUsingHmac`] which implements this trait on top of an implementation
/// of [`hmac::Hmac`].
pub trait Hkdf: Send + Sync {
    /// `HKDF-Extract(salt, 0_HashLen)`
    ///
    /// `0_HashLen` is a string of `HashLen` zero bytes.
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander>;

    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander>;

    /// `HKDF-Extract(salt, shared_secret)` where `shared_secret` is the result of a key exchange.
    ///
    /// Custom implementations should complete the key exchange by calling
    /// `kx.complete(peer_pub_key)` and then using this as the input keying material to
    /// `HKDF-Extract`.
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    fn extract_from_kx_shared_secret(
        &self,
        salt: Option<&[u8]>,
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
    ) -> Result<Box<dyn HkdfExpander>, Error> {
        Ok(self.extract_from_secret(
            salt,
            kx.complete_for_tls_version(peer_pub_key, ProtocolVersion::TLSv1_3)?
                .secret_bytes(),
        ))
    }

    /// Build a `HkdfExpander` using `okm` as the secret PRK.
    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander>;

    /// Signs `message` using `key` viewed as a HMAC key.
    ///
    /// This should use the same hash function as the HKDF functions in this
    /// trait.
    ///
    /// See [RFC2104](https://datatracker.ietf.org/doc/html/rfc2104) for the
    /// definition of HMAC.
    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> hmac::Tag;

    /// Return the FIPS validation status of this implementation.
    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }
}

/// An extended HKDF implementation that supports directly extracting a pseudo-random key (PRK).
///
/// The base [`Hkdf`] trait is tailored to the needs of TLS 1.3, where all extracted PRKs
/// are expanded as-is, and so can be safely encapsulated without exposing the caller
/// to the key material.
///
/// In other contexts (for example, hybrid public key encryption (HPKE)) it may be necessary
/// to use the extracted PRK directly for purposes other than an immediate expansion.
/// This trait can be implemented to offer this functionality when it is required.
pub trait HkdfPrkExtract: Hkdf {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero bytes.
    ///
    /// In most cases you should prefer [`Hkdf::extract_from_secret`] and using the
    /// returned [HkdfExpander] instead of handling the PRK directly.
    fn extract_prk_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Vec<u8>;
}

/// `HKDF-Expand(PRK, info, L)` to construct any type from a byte array.
///
/// - `PRK` is the implicit key material represented by this instance.
/// - `L := N`; N is the size of the byte array.
/// - `info` is a slice of byte slices, which should be processed sequentially
///   (or concatenated if that is not possible).
///
/// This is infallible, because the set of types (and therefore their length) is known
/// at compile time.
pub fn expand<T, const N: usize>(expander: &dyn HkdfExpander, info: &[&[u8]]) -> T
where
    T: From<[u8; N]>,
{
    let mut output = [0u8; N];
    expander
        .expand_slice(info, &mut output)
        .expect("expand type parameter T is too large");
    T::from(output)
}

/// Output key material from HKDF, as a value type.
#[derive(Clone)]
pub struct OkmBlock {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl OkmBlock {
    /// Build a single OKM block by copying a byte slice.
    ///
    /// The slice can be up to [`OkmBlock::MAX_LEN`] bytes in length.
    pub fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; Self::MAX_LEN],
            used: bytes.len(),
        };
        tag.buf[..bytes.len()].copy_from_slice(bytes);
        tag
    }

    /// Maximum supported HMAC tag size: supports up to SHA512.
    pub const MAX_LEN: usize = 64;
}

impl Drop for OkmBlock {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for OkmBlock {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// An error type used for `HkdfExpander::expand_slice` when
/// the slice exceeds the maximum HKDF output length.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct OutputLengthError;
