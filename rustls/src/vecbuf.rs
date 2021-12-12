use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Read;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub(crate) struct ChunkVecBuffer {
    chunks: VecDeque<Vec<u8>>,
    limit: Option<usize>,
}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            limit,
        }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.
    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec());
        take
    }

    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }

        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        self.chunks.pop_front()
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0]
                .as_slice()
                .read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    #[cfg(feature = "read_buf")]
    #[allow(unsafe_code)]
    /// Read data out of this object, writing it into `buf`.
    pub(crate) fn read_buf(&mut self, buf: &mut io::ReadBuf<'_>) -> io::Result<()> {
        use std::mem::MaybeUninit;

        while !self.is_empty() {
            // There are three unsafe calls in this block to justify. First,
            // `ReadBuf::unfilled_mut()` requires that we "not de-initialize portions of the buffer
            // that have already been initialized." We write to the buffer using
            // `std::ptr::copy_nonoverlapping`, with a `[u8]` slice from this `ChunkVecBuffer` as
            // the source. All memory in the `[u8]` slice must be initialized, and the length of
            // the copy is less than or equal to the length of the `[u8]` slice, so we will not
            // de-initialize any of the `ReadBuf` buffer by performing this copy.
            //
            // Second, `std::ptr::copy_nonoverlapping` has several requirements. First, note that
            // the source and destination buffers do not overlap because the source is part of
            // `self`, which is mutably borrowed, so we can assume the other buffer does not alias
            // it. As we are copying `T=u8`, the alignment requirements on the source and
            // destination are trivially satisfied. Additionally, `u8` is `Copy`, so creating
            // bitwise copies is acceptible. The count argument is less than or equal to both the
            // length of the slice we are copying from, and the length of the unfilled part of the
            // buffer we are copying to. Thus, the source pointer is valid for reads of this
            // length, and the destination pointer is valid for writes of this length.
            //
            // Lastly, `ReadBuf::assume_init` requires that "the first `n` unfilled bytes of the
            // buffer have already been initialized". We write into the unfilled part of the buffer
            // using `std::ptr::copy_nonoverlapping`, and, as argued above, this causes these bytes
            // to become initialized, since we are copying from another buffer that is initialized.
            unsafe {
                let unfilled: &mut [MaybeUninit<u8>] = buf.unfilled_mut();
                if unfilled.is_empty() {
                    break;
                }
                let chunk = self.chunks[0].as_slice();
                let used = std::cmp::min(chunk.len(), unfilled.len());
                let unfilled_ptr: *mut MaybeUninit<u8> = unfilled.as_mut_ptr();
                // This pointer cast is fine because `MaybeUninit<u8>` and `u8` are guaranteed to
                // have the same memory layout.
                let unfilled_ptr = unfilled_ptr as *mut u8;
                std::ptr::copy_nonoverlapping(chunk.as_ptr(), unfilled_ptr, used);
                buf.assume_init(used);
                buf.add_filled(used);
                self.consume(used);
            }
        }

        Ok(())
    }

    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.chunks.pop_front() {
            if used < buf.len() {
                self.chunks
                    .push_front(buf.split_off(used));
                break;
            } else {
                used -= buf.len();
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }
}

#[cfg(test)]
mod test {
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new(Some(12));
        assert_eq!(cvb.append_limited_copy(b"hello"), 5);
        assert_eq!(cvb.append_limited_copy(b"world"), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"), 2);
        assert_eq!(cvb.append_limited_copy(b"world"), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }

    #[cfg(feature = "read_buf")]
    #[test]
    fn read_buf() {
        use std::alloc::{self, GlobalAlloc, Layout};
        use std::{io::ReadBuf, mem::MaybeUninit};

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"test ".to_vec());
            cvb.append(b"fixture ".to_vec());
            cvb.append(b"data".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf = ReadBuf::uninit(&mut buf);
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        #[allow(unsafe_code)]
        {
            const BUFFER_SIZE: usize = 1024 * 1024;

            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"short message".to_vec());

            let layout = Layout::new::<[MaybeUninit<u8>; BUFFER_SIZE]>();
            let byte_ptr: *mut u8 = unsafe { alloc::System.alloc(layout) };
            {
                let ptr = byte_ptr as *mut [MaybeUninit<u8>; BUFFER_SIZE];
                let buf: &mut [MaybeUninit<u8>; BUFFER_SIZE] = unsafe { &mut *ptr };
                let mut buf = ReadBuf::uninit(buf.as_mut());
                cvb.read_buf(&mut buf).unwrap();
                assert_eq!(buf.filled(), b"short message");
            }
            unsafe { alloc::System.dealloc(byte_ptr, layout) };
        }
    }
}
