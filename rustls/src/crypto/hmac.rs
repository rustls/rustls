use alloc::boxed::Box;
use core::mem;

use pki_types::FipsStatus;
use zeroize::Zeroize;

/// A concrete HMAC implementation, for a single cryptographic hash function.
///
/// You should have one object that implements this trait for HMAC-SHA256, another
/// for HMAC-SHA384, etc.
pub trait Hmac: Send + Sync {
    /// Prepare to use `key` as a HMAC key.
    fn with_key(&self, key: &[u8]) -> Box<dyn Key>;

    /// Give the length of the underlying hash function.  In RFC2104 terminology this is `L`.
    fn hash_output_len(&self) -> usize;

    /// Return the FIPS validation status of this implementation.
    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }
}

/// A secret HMAC tag, stored as a value.
///
/// The value is considered secret and sensitive, and is zeroized
/// on drop.
///
/// This is suitable if the value is (for example) used as key
/// material.
#[derive(Clone)]
pub struct Tag(PublicTag);

impl Tag {
    /// Build a tag by copying a byte slice.
    ///
    /// The slice can be up to [`Tag::MAX_LEN`] bytes in length.
    pub fn new(bytes: &[u8]) -> Self {
        Self(PublicTag::new(bytes))
    }

    /// Declare this tag is public.
    ///
    /// Uses of this function should explain why this tag is public.
    pub(crate) fn into_public(self) -> PublicTag {
        let public = self.0.clone();
        mem::forget(self);
        public
    }

    /// Maximum supported HMAC tag size: supports up to SHA512.
    pub const MAX_LEN: usize = 64;
}

impl Drop for Tag {
    fn drop(&mut self) {
        self.0.buf.zeroize();
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A non-secret HMAC tag, stored as a value.
///
/// A value of this type is **not** zeroized on drop.
///
/// A tag is "public" if it is published on the wire, as opposed to
/// being used as key material. For example, the `verify_data` field
/// of TLS `Finished` messages are public (as they are published on
/// the wire in TLS1.2, or sent encrypted under pre-authenticated
/// secrets in TLS1.3).
#[derive(Clone)]
pub(crate) struct PublicTag {
    buf: [u8; Tag::MAX_LEN],
    used: usize,
}

impl PublicTag {
    /// Build a tag by copying a byte slice.
    ///
    /// The slice can be up to [`Tag::MAX_LEN`] bytes in length.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; Tag::MAX_LEN],
            used: bytes.len(),
        };
        tag.buf[..bytes.len()].copy_from_slice(bytes);
        tag
    }
}

impl AsRef<[u8]> for PublicTag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A HMAC key that is ready for use.
///
/// The algorithm used is implicit in the `Hmac` object that produced the key.
pub trait Key: Send + Sync {
    /// Calculates a tag over `data` -- a slice of byte slices.
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    /// Calculates a tag over the concatenation of `first`, the items in `middle`, and `last`.
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag;

    /// Returns the length of the tag returned by a computation using
    /// this key.
    fn tag_len(&self) -> usize;
}
