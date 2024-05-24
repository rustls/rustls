use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp;
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::Read;

#[cfg(feature = "std")]
use crate::msgs::message::OutboundChunks;

/// A BufferQueue manages a sequence of buffers.
/// Keeping the buffers as is avoids copies at the
/// expense of complexity when consuming the data.
pub(crate) struct BufferQueue {
    // ring buffer
    buffers: VecDeque<Vec<u8>>,
    limit: Option<usize>,
}

impl BufferQueue {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            buffers: VecDeque::new(),
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
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
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

    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `cursor`.
    pub(crate) fn read_buf(&mut self, mut cursor: core::io::BorrowedCursor<'_>) -> io::Result<()> {
        while !self.is_empty() && cursor.capacity() > 0 {
            let buf = self.buffers[0].as_slice();
            let used = cmp::min(buf.len(), cursor.capacity());
            cursor.append(&buf[..used]);
            self.consume(used);
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl BufferQueue {
    pub(crate) fn is_full(&self) -> bool {
        self.limit
            .map(|limit| self.len() > limit)
            .unwrap_or_default()
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn enqueue_limited_copy(&mut self, payload: OutboundChunks<'_>) -> usize {
        let take = self.apply_limit(payload.len());
        self.enqueue(payload.split_at(take).0.to_vec());
        take
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.buffers[0]
                .as_slice()
                .read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.buffers.pop_front() {
            if used < buf.len() {
                buf.drain(..used);
                self.buffers.push_front(buf);
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
        for (iov, buf) in bufs.iter_mut().zip(self.buffers.iter()) {
            *iov = io::IoSlice::new(buf);
        }
        let len = cmp::min(bufs.len(), self.buffers.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::BufferQueue;

    #[test]
    fn short_enqueue_copy_with_limit() {
        let mut cvb = BufferQueue::new(Some(12));
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
            let mut cvb = BufferQueue::new(None);
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
            let mut cvb = BufferQueue::new(None);
            cvb.enqueue(b"short message".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
