use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::mem;

/// This is a byte buffer that is built from a deque of byte vectors.
///
/// This avoids extra copies when appending a new byte vector,
/// at the expense of more complexity when reading out.
pub(crate) struct ChunkVecBuffer {
    /// How many bytes have been consumed in the first chunk.
    ///
    /// Invariant: zero if `chunks.is_empty()`
    /// Invariant: 0 <= `prefix_used` < `chunks[0].len()`
    prefix_used: usize,

    chunks: VecDeque<Vec<u8>>,
}

impl ChunkVecBuffer {
    pub(crate) fn new() -> Self {
        Self {
            prefix_used: 0,
            chunks: VecDeque::new(),
        }
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.chunks
            .iter()
            .fold(0usize, |acc, chunk| acc + chunk.len())
            - self.prefix_used
    }

    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            if self.chunks.is_empty() {
                debug_assert_eq!(self.prefix_used, 0);
            }

            self.chunks.push_back(bytes);
        }

        len
    }

    /// Take one of the chunks from this object.
    ///
    /// This function returns `None` if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        let mut first = self.chunks.pop_front();

        if let Some(first) = &mut first {
            // slice off `prefix_used` if needed (uncommon)
            let prefix = mem::take(&mut self.prefix_used);
            first.drain(0..prefix);
        }

        first
    }

    /// Inspect the first chunk from this object.
    pub(crate) fn peek(&self) -> Option<&[u8]> {
        self.chunks
            .front()
            .map(|ch| ch.as_slice())
    }
}

impl ChunkVecBuffer {
    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let chunk = &self.chunks[0][self.prefix_used..];
            let used = Ord::min(chunk.len(), buf.len() - offs);
            buf[offs..offs + used].copy_from_slice(&chunk[..used]);

            self.consume(used);
            offs += used;
        }

        offs
    }

    fn consume(&mut self, used: usize) {
        // first, mark the rightmost extent of the used buffer
        self.prefix_used += used;

        // then reduce `prefix_used` by discarding wholly-covered
        // buffers
        while let Some(buf) = self.chunks.front() {
            if self.prefix_used < buf.len() {
                return;
            }

            self.prefix_used -= buf.len();
            self.chunks.pop_front();
        }

        debug_assert_eq!(
            self.prefix_used, 0,
            "attempted to `ChunkVecBuffer::consume` more than available"
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::ChunkVecBuffer;

    #[test]
    fn pop_slices_off_consumed_prefix() {
        let mut cvb = ChunkVecBuffer::new();
        cvb.append(b"hello".to_vec());
        cvb.append(b"world".to_vec());
        assert_eq!(cvb.read(&mut [0u8; 3]), 3);
        assert_eq!(cvb.pop(), Some(b"lo".to_vec()));
        assert_eq!(cvb.pop(), Some(b"world".to_vec()));
        assert_eq!(cvb.pop(), None);
        assert_eq!(cvb.len(), 0);
    }

    #[test]
    fn read_byte_by_byte() {
        let mut cvb = ChunkVecBuffer::new();
        cvb.append(b"test fixture data".to_vec());
        assert!(!cvb.is_empty());
        for expect in b"test fixture data" {
            let mut byte = [0];
            assert_eq!(cvb.read(&mut byte), 1);
            assert_eq!(byte[0], *expect);
        }

        assert_eq!(cvb.read(&mut [0]), 0);
    }

    #[test]
    fn every_possible_chunk_interleaving() {
        let input = (0..=0xffu8)
            .cycle()
            .take(4096)
            .collect::<Vec<u8>>();

        for input_chunk_len in 1..64usize {
            for output_chunk_len in 1..65usize {
                std::println!("check input={input_chunk_len} output={output_chunk_len}");
                let mut cvb = ChunkVecBuffer::new();
                for chunk in input.chunks(input_chunk_len) {
                    cvb.append(chunk.to_vec());
                }

                assert_eq!(cvb.len(), input.len());
                let mut buf = vec![0u8; output_chunk_len];

                for expect in input.chunks(output_chunk_len) {
                    assert_eq!(expect.len(), cvb.read(&mut buf));
                    assert_eq!(expect, &buf[..expect.len()]);
                }

                assert_eq!(cvb.read(&mut [0]), 0);
            }
        }
    }
}

#[cfg(all(test, bench))]
mod benchmarks {
    use alloc::vec;

    use super::ChunkVecBuffer;

    #[bench]
    fn read_one_byte_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new();
            cvb.append(vec![0u8; 16_384]);
            assert_eq!(1, cvb.read(&mut [0u8]));
        });
    }

    #[bench]
    fn read_all_individual_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new();
            cvb.append(vec![0u8; 16_384]);
            loop {
                if cvb.read(&mut [0u8]) == 0 {
                    break;
                }
            }
        });
    }

    #[bench]
    fn read_half_bytes_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new();
            cvb.append(vec![0u8; 16_384]);
            assert_eq!(8192, cvb.read(&mut [0u8; 8192]));
            assert_eq!(8192, cvb.read(&mut [0u8; 8192]));
        });
    }

    #[bench]
    fn read_entire_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new();
            cvb.append(vec![0u8; 16_384]);
            assert_eq!(16_384, cvb.read(&mut [0u8; 16_384]));
        });
    }
}
