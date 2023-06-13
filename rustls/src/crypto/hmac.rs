/// A concrete HMAC implementation, reified with a hash function.
///
/// You should have one object that implements this trait for HMAC-SHA256, another
/// for HMAC-SHA384, etc.
pub trait Hmac: Send + Sync {
    /// Prepare to use `key` as a HMAC key.
    fn open_key(&self, key: &[u8]) -> Box<dyn Key>;

    /// Give the length of the underlying hash function.  In RFC2104 terminology this is `L`.
    fn hash_output_len(&self) -> usize;
}

/// Maximum supported HMAC tag size: supports up to SHA512.
pub(crate) const HMAC_MAX_TAG: usize = 64;

/// A HMAC tag, stored as a value.
#[derive(Clone)]
pub struct Tag {
    buf: [u8; HMAC_MAX_TAG],
    used: usize,
}

impl Tag {
    /// Build a tag by copying a byte slice.
    ///
    /// The slice can be up to `HMAC_MAX_TAG` bytes in length.
    pub fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0u8; HMAC_MAX_TAG],
            used: bytes.len(),
        };
        tag.buf[..bytes.len()].copy_from_slice(bytes);
        tag
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A HMAC key that is ready for use.
///
/// The algorithm used is implicit in the `Hmac` object that produced the key.
pub trait Key: Send + Sync {
    /// Calculates a tag over `data` -- an slice of byte slices.
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    /// Calculates a tag over the concatenation of `first`, the items in `middle`, and `last`.
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag;

    /// Returns the length of the tag returned by a computation using
    /// this key.
    fn tag_len(&self) -> usize;
}
