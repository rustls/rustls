pub use crate::msgs::enums::HashAlgorithm;

/// Describes a single hash function.
pub trait Hash: Send + Sync {
    /// Which hash function this is, eg, `HashAlgorithm::SHA256`.
    fn algorithm(&self) -> HashAlgorithm;

    /// The length in bytes of this hash function's output.
    fn output_len(&self) -> usize;

    /// Start an incremental hash computation.
    fn start(&self) -> Box<dyn Context>;

    /// Return the output of this hash function with input `data`.
    fn compute(&self, data: &[u8]) -> Output;
}

/// Maximum support hash output size: supports up to SHA512.
pub(crate) const HASH_MAX_OUTPUT: usize = 64;

/// A hash output, stored as a value.
pub struct Output {
    buf: [u8; HASH_MAX_OUTPUT],
    used: usize,
}

impl Output {
    /// Build a `hash::Output` from a slice of no more than `HASH_MAX_OUTPUT` bytes.
    pub fn new(bytes: &[u8]) -> Self {
        let mut output = Self {
            buf: [0u8; HASH_MAX_OUTPUT],
            used: bytes.len(),
        };
        output.buf[..bytes.len()].copy_from_slice(bytes);
        output
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// How to incrementally compute a hash.
pub trait Context: Send + Sync {
    /// Add `data` to computation.
    fn update(&mut self, data: &[u8]);

    /// Fork the computation, producing another context that has the
    /// same prefix as this one.
    fn fork(&self) -> Box<dyn Context>;

    /// Finish the computation, returning the resulting output.
    ///
    /// The computation remains valid, and more data can be added later with
    /// `update()`.  Compare with `finish()` which consumes the computation
    /// and prevents any further data being added.  This can be more efficient
    /// because it avoids a hash context copy to apply MD-padding.
    fn fork_finish(&self) -> Output;

    /// Terminate and finish the computation, returning the resulting output.
    fn finish(self: Box<Self>) -> Output;
}
