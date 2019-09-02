use std::io::Read;
use std::io;
use std::cmp;
use std::collections::VecDeque;
use std::convert;

/// This trait specifies rustls's precise requirements doing writes with
/// vectored IO.
///
/// The purpose of vectored IO is to pass contigious output in many blocks
/// to the kernel without either coalescing it in user-mode (by allocating
/// and copying) or making many system calls.
///
/// We don't directly use types from the vecio crate because the traits
/// don't compose well: the most useful trait (`Rawv`) is hard to test
/// with (it can't be implemented without an FD) and implies a readable
/// source too.  You will have to write a trivial adaptor struct which
/// glues either `vecio::Rawv` or `vecio::Writev` to this trait.  See
/// the rustls examples.
pub trait WriteV {
    /// Writes as much data from `vbytes` as possible, returning
    /// the number of bytes written.
    fn writev(&mut self, vbytes: &[&[u8]]) -> io::Result<usize>;
}

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub struct ChunkVecBuffer {
    chunks: VecDeque<Vec<u8>>,
    limit: usize,
}

impl ChunkVecBuffer {
    pub fn new() -> ChunkVecBuffer {
        ChunkVecBuffer { chunks: VecDeque::new(), limit: 0 }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A zero limit is interpreted as no limit.
    pub fn set_limit(&mut self, new_limit: usize) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    pub fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub fn apply_limit(&self, len: usize) -> usize {
        if self.limit == 0 {
            len
        } else {
            let space =self.limit.saturating_sub(self.len());
            cmp::min(len, space)
        }
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec());
        take
    }

    /// Take and append the given `bytes`.
    pub fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }

        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub fn take_one(&mut self) -> Vec<u8> {
        self.chunks.pop_front().unwrap()
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0].as_slice().read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    fn consume(&mut self, mut used: usize) {
        while used > 0 && !self.is_empty() {
            if used >= self.chunks[0].len() {
                used -= self.chunks[0].len();
                self.take_one();
            } else {
                self.chunks[0] = self.chunks[0].split_off(used);
                used = 0;
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    pub fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let used = wr.write(&self.chunks[0])?;
        self.consume(used);
        Ok(used)
    }

    pub fn writev_to(&mut self, wr: &mut dyn WriteV) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let used = {
            let chunks = self.chunks.iter()
                .map(convert::AsRef::as_ref)
                .collect::<Vec<&[u8]>>();

            wr.writev(&chunks)?
        };
        self.consume(used);
        Ok(used)
    }
}

/// This is a simple wrapper around an object
/// which implements `std::io::Write` in order to autoimplement `WriteV`.
/// It uses the `write_vectored` method from `std::io::Write` in order
/// to do this.
pub struct WriteVAdapter<T: io::Write>(T);

impl<T: io::Write> WriteVAdapter<T> {
    /// build an adapter from a Write object
    pub fn new(inner: T) -> Self {
        WriteVAdapter(inner)
    }
}

impl<T: io::Write> WriteV for WriteVAdapter<T> {
    fn writev(&mut self, buffers: &[&[u8]]) -> io::Result<usize> {
        self.0.write_vectored(
            &buffers
                .iter()
                .map(|b| io::IoSlice::new(b))
                .collect::<Vec<io::IoSlice>>(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit()
    {
        let mut cvb = ChunkVecBuffer::new();
        cvb.set_limit(12);
        assert_eq!(cvb.append_limited_copy(b"hello"), 5);
        assert_eq!(cvb.append_limited_copy(b"world"), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"), 2);
        assert_eq!(cvb.append_limited_copy(b"world"), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(),
                   b"helloworldhe".to_vec());
    }
}
