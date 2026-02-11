use core::mem;
use core::ops::Range;

/// Accounting structure tracking progress in parsing a single buffer.
#[derive(Clone, Debug)]
pub(crate) struct BufferProgress {
    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl BufferProgress {
    pub(super) fn new(processed: usize) -> Self {
        Self {
            processed,
            discard: 0,
        }
    }

    #[inline]
    pub(crate) fn add_discard(&mut self, discard: usize) {
        self.discard += discard;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self
            .processed
            .saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

/// Reordering the underlying buffer based on ranges.
pub(crate) struct Coalescer<'b> {
    slice: &'b mut [u8],
}

impl<'b> Coalescer<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b mut [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn copy_within(&mut self, from: Range<usize>, to: Range<usize>) {
        debug_assert!(from.len() == to.len());
        debug_assert!(self.slice.get(from.clone()).is_some());
        debug_assert!(self.slice.get(to.clone()).is_some());
        self.slice.copy_within(from, to.start);
    }

    #[inline]
    pub(crate) fn delocator(self) -> Delocator<'b> {
        Delocator::new(self.slice)
    }
}

/// Conversion from a `Range` offset to the original slice.
pub(crate) struct Delocator<'b> {
    slice: &'b [u8],
}

impl<'b> Delocator<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn slice_from_range(&'_ self, range: &Range<usize>) -> &'b [u8] {
        // safety: this unwrap is safe so long as `range` came from `locate()`
        // for the same buffer
        self.slice.get(range.clone()).unwrap()
    }

    #[inline]
    pub(crate) fn locator(self) -> Locator {
        Locator::new(self.slice)
    }
}

/// Conversion from a slice within a larger buffer into
/// a `Range` offset within.
#[derive(Debug)]
pub(crate) struct Locator {
    bounds: Range<*const u8>,
}

impl Locator {
    #[inline]
    pub(crate) fn new(slice: &[u8]) -> Self {
        Self {
            bounds: slice.as_ptr_range(),
        }
    }

    #[inline]
    pub(crate) fn locate(&self, slice: &[u8]) -> Range<usize> {
        let bounds = slice.as_ptr_range();
        debug_assert!(self.fully_contains(slice));
        let start = bounds.start as usize - self.bounds.start as usize;
        let len = bounds.end as usize - bounds.start as usize;
        Range {
            start,
            end: start + len,
        }
    }

    #[inline]
    pub(crate) fn fully_contains(&self, slice: &[u8]) -> bool {
        let bounds = slice.as_ptr_range();
        bounds.start >= self.bounds.start && bounds.end <= self.bounds.end
    }
}
