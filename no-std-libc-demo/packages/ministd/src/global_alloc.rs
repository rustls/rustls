// based on `$(rustc +1.72.0 --print sysroot)/lib/rustlib/src/rust/library/std/src/sys/unix/alloc.rs`

use core::{
    alloc::{GlobalAlloc, Layout},
    mem, ptr,
};

use crate::libc;

#[global_allocator]
static HEAP: System = System;

struct System;

// alignment guaranteed by the architecture
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const MIN_ALIGN: usize = 16;

unsafe impl GlobalAlloc for System {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if can_use_unaligned_version(&layout, layout.size()) {
            libc::malloc(layout.size()).cast()
        } else {
            aligned_malloc(&layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        libc::free(ptr.cast())
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if can_use_unaligned_version(&layout, layout.size()) {
            libc::calloc(layout.size(), 1).cast()
        } else {
            self.alloc_zeroed_fallback(layout)
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if can_use_unaligned_version(&layout, new_size) {
            libc::realloc(ptr.cast(), new_size).cast()
        } else {
            self.realloc_fallback(ptr, layout, new_size)
        }
    }
}

// implementations of the default `GlobalAlloc` methods
impl System {
    unsafe fn realloc_fallback(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller must ensure that the `new_size` does not overflow.
        // `layout.align()` comes from a `Layout` and is thus guaranteed to be valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller must ensure that `new_layout` is greater than zero.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            // SAFETY: the previously allocated block cannot overlap the newly allocated block.
            // The safety contract for `dealloc` must be upheld by the caller.
            unsafe {
                ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(layout.size(), new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }

    unsafe fn alloc_zeroed_fallback(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        // SAFETY: the safety contract for `alloc` must be upheld by the caller.
        let ptr = unsafe { self.alloc(layout) };
        if !ptr.is_null() {
            // SAFETY: as allocation succeeded, the region from `ptr`
            // of size `size` is guaranteed to be valid for writes.
            unsafe { ptr::write_bytes(ptr, 0, size) };
        }
        ptr
    }
}

fn can_use_unaligned_version(layout: &Layout, size: usize) -> bool {
    let align = layout.align();

    align <= MIN_ALIGN && align <= size
}

unsafe fn aligned_malloc(layout: &Layout) -> *mut u8 {
    let align = layout
        .align()
        .max(mem::size_of::<usize>());

    let mut out = ptr::null_mut();
    let ret = libc::posix_memalign(&mut out, align, layout.size());
    if ret != 0 {
        ptr::null_mut()
    } else {
        out.cast()
    }
}
