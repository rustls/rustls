use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp;
#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "std")]
use crate::msgs::message::OutboundChunks;

/// A BufferQueue manages a sequence of buffers.
/// Keeping the buffers as is avoids copies at the
/// expense of complexity when consuming the data.
pub(crate) struct BufferQueue {
    // ring buffer
    buffers: VecDeque<Vec<u8>>,
    limit: usize,
}

impl BufferQueue {
    /// Constructor includes `set_limit(usize)`.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            buffers: VecDeque::new(),
            limit,
        }
    }

    /// Set an upper limit on the number of octets
    /// enqueued, with zero for unlimited.
    /// A lower value than `len()` is not an error.
    pub(crate) fn set_limit(&mut self, new_limit: usize) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for buf in &self.buffers {
            len += buf.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if self.limit != 0 {
            let space = self.limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// Place the buffer in line if it is not empty.
    pub(crate) fn enqueue(&mut self, buf: Vec<u8>) -> usize {
        let len = buf.len();

        if !buf.is_empty() {
            self.buffers.push_back(buf);
        }

        len
    }

    /// Take the next buffer in line, if any. Empty buffers are omitted.
    pub(crate) fn dequeue(&mut self) -> Option<Vec<u8>> {
        self.buffers.pop_front()
    }

    /// See the next buffer in line, if any. Empty buffers are omitted.
    fn peek(&mut self) -> Option<&mut Vec<u8>> {
        // The element at index 0 is the front of the queue.
        self.buffers.get_mut(0)
    }

    #[cfg(read_buf)]
    /// Dequeue and copy into `cursor` up to `capacity()` in size.
    pub(crate) fn read_buf(&mut self, mut cursor: core::io::BorrowedCursor<'_>) -> io::Result<()> {
        let mut space = cursor.capacity();

        while let Some(next) = self.peek() {
            if next.len() > space {
                if space != 0 {
                    let taken = &next.drain(..space);
                    cursor.append(taken.as_slice());
                    // space = 0;
                }
                break;
            }

            cursor.append(&next);
            space -= next.len();
            self.dequeue(); // drop peeked
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl BufferQueue {
    pub(crate) fn is_full(&self) -> bool {
        self.limit != 0 && self.limit <= self.len()
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn enqueue_limited_copy(&mut self, payload: OutboundChunks<'_>) -> usize {
        let take = self.apply_limit(payload.len());
        self.enqueue(payload.split_at(take).0.to_vec());
        take
    }

    /// Dequeue into `p` with the number of bytes copied in return.
    /// Reads of less than the capacity of `buf` imply queue exhaustion.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut i = 0; // write index in buf

        while let Some(next) = self.peek() {
            let end = i + next.len();
            if end > buf.len() {
                if i < buf.len() {
                    let left = &mut buf[i..];
                    let taken = next.drain(..left.len());
                    left.copy_from_slice(taken.as_slice());
                    i = buf.len();
                }
                break;
            }

            buf[i..end].copy_from_slice(&next);
            i = end;
            self.dequeue(); // drop peeked
        }

        Ok(i)
    }

    /// Discard the next n octets in line.
    fn consume(&mut self, mut n: usize) {
        while let Some(buf) = self.peek() {
            if buf.len() > n {
                if n != 0 {
                    buf.drain(..n);
                    // n = 0;
                }
                break;
            }
            n -= buf.len();
            self.dequeue(); // drop peeked
        }
    }

    /// Dequeue data written to w with the total number of octets in return.
    pub(crate) fn write_to(&mut self, w: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        // queue as "write vectors"
        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, buf) in bufs.iter_mut().zip(self.buffers.iter()) {
            *iov = io::IoSlice::new(buf);
        }
        let len = cmp::min(bufs.len(), self.buffers.len());

        let written = w.write_vectored(&bufs[..len])?;
        self.consume(written);
        Ok(written)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::BufferQueue;

    #[test]
    fn short_enqueue_copy_with_limit() {
        let mut cvb = BufferQueue::new(12);
        assert_eq!(cvb.enqueue_limited_copy(b"hello"[..].into()), 5);
        assert_eq!(cvb.enqueue_limited_copy(b"world"[..].into()), 5);
        assert_eq!(cvb.enqueue_limited_copy(b"hello"[..].into()), 2);
        assert_eq!(cvb.enqueue_limited_copy(b"world"[..].into()), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }

    #[cfg(read_buf)]
    #[test]
    fn read_buf() {
        use core::io::BorrowedBuf;
        use core::mem::MaybeUninit;

        {
            let mut cvb = BufferQueue::new(0);
            cvb.enqueue(b"test ".to_vec());
            cvb.enqueue(b"fixture ".to_vec());
            cvb.enqueue(b"data".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        {
            let mut cvb = BufferQueue::new(0);
            cvb.enqueue(b"short message".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
