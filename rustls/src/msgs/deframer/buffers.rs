use core::ops::Range;

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
