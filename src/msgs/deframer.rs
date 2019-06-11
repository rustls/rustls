
use std::collections::VecDeque;
use std::io;

use crate::msgs::codec;
use crate::msgs::codec::Codec;
use crate::msgs::message::Message;

const HEADER_SIZE: usize = 1 + 2 + 2;

/// This is the maximum on-the-wire size of a TLSCiphertext.
/// That's 2^14 payload bytes, a header, and a 2KB allowance
/// for ciphertext overheads.
const MAX_MESSAGE: usize = 16384 + 2048 + HEADER_SIZE;

/// This deframer works to reconstruct TLS messages
/// from arbitrary-sized reads, buffering as necessary.
/// The input is `read()`, the output is the `frames` deque.
pub struct MessageDeframer {
    /// Completed frames for output.
    pub frames: VecDeque<Message>,

    /// Set to true if the peer is not talking TLS, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    pub desynced: bool,

    /// A fixed-size buffer containing the currently-accumulating
    /// TLS message.
    buf: Box<[u8; MAX_MESSAGE]>,

    /// What size prefix of `buf` is used.
    used: usize,
}

enum BufferContents {
    /// Contains an invalid message as a header.
    Invalid,

    /// Might contain a valid message if we receive more.
    /// Perhaps totally empty!
    Partial,

    /// Contains a valid frame as a prefix.
    Valid,
}

impl Default for MessageDeframer {
    fn default() -> Self { Self::new() }
}

impl MessageDeframer {
    pub fn new() -> MessageDeframer {
        MessageDeframer {
            frames: VecDeque::new(),
            desynced: false,
            buf: Box::new([0u8; MAX_MESSAGE]),
            used: 0,
        }
    }

    /// Read some bytes from `rd`, and add them to our internal
    /// buffer.  If this means our internal buffer contains
    /// full messages, decode them all.
    pub fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        // Try to do the largest reads possible.  Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        debug_assert!(self.used <= MAX_MESSAGE);
        let new_bytes = rd.read(&mut self.buf[self.used..])?;

        self.used += new_bytes;

        loop {
            match self.buf_contains_message() {
                BufferContents::Invalid => {
                    self.desynced = true;
                    break;
                }
                BufferContents::Valid => {
                    self.deframe_one();
                }
                BufferContents::Partial => break,
            }
        }

        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller
    /// to process, either whole messages in our output
    /// queue or partial messages in our buffer.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || self.used > 0
    }

    /// Does our `buf` contain a full message?  It does if it is big enough to
    /// contain a header, and that header has a length which falls within `buf`.
    fn buf_contains_message(&self) -> BufferContents {
        if self.used < HEADER_SIZE {
            return BufferContents::Partial;
        }

        let len_maybe = Message::check_header(&self.buf[..self.used]);

        // Header damaged.
        if len_maybe == None {
            return BufferContents::Invalid;
        }

        let len = len_maybe.unwrap();

        // This is just too large.
        if len >= MAX_MESSAGE - HEADER_SIZE {
            return BufferContents::Invalid;
        }

        let full_message = self.used >= len + HEADER_SIZE;
        if full_message { BufferContents::Valid } else { BufferContents::Partial }
    }

    /// Take a TLS message off the front of `buf`, and put it onto the back
    /// of our `frames` deque.
    fn deframe_one(&mut self) {
        let used = {
            let mut rd = codec::Reader::init(&self.buf[..self.used]);
            let m = Message::read(&mut rd).unwrap();
            self.frames.push_back(m);
            rd.used()
        };
        self.buf_consume(used);
    }

    fn buf_consume(&mut self, taken: usize) {
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */
            let used_after = self.used - taken;

            for i in 0..used_after {
                self.buf[i] = self.buf[i + taken];
            }

            self.used = used_after;
        } else if taken == self.used {
            self.used = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessageDeframer;
    use std::io;
    use crate::msgs;

    const FIRST_MESSAGE: &'static [u8] = include_bytes!("../testdata/deframer-test.1.bin");
    const SECOND_MESSAGE: &'static [u8] = include_bytes!("../testdata/deframer-test.2.bin");

    struct ByteRead<'a> {
        buf: &'a [u8],
        offs: usize,
    }

    impl<'a> ByteRead<'a> {
        fn new(bytes: &'a [u8]) -> ByteRead {
            ByteRead {
                buf: bytes,
                offs: 0,
            }
        }
    }

    impl<'a> io::Read for ByteRead<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut len = 0;

            while len < buf.len() && len < self.buf.len() - self.offs {
                buf[len] = self.buf[self.offs + len];
                len += 1;
            }

            self.offs += len;

            Ok(len)
        }
    }

    fn input_bytes(d: &mut MessageDeframer, bytes: &[u8]) -> io::Result<usize> {
        let mut rd = ByteRead::new(bytes);
        d.read(&mut rd)
    }

    fn input_bytes_concat(d: &mut MessageDeframer, bytes1: &[u8], bytes2: &[u8]) -> io::Result<usize> {
        let mut bytes = vec![0u8; bytes1.len() + bytes2.len()];
        bytes[..bytes1.len()].clone_from_slice(bytes1);
        bytes[bytes1.len()..].clone_from_slice(bytes2);
        let mut rd = ByteRead::new(&bytes);
        d.read(&mut rd)
    }

    struct ErrorRead {
        error: Option<io::Error>,
    }

    impl ErrorRead {
        fn new(error: io::Error) -> ErrorRead {
            ErrorRead { error: Some(error) }
        }
    }

    impl io::Read for ErrorRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }

            let error = self.error.take()
                .unwrap();
            Err(error)
        }
    }

    fn input_error(d: &mut MessageDeframer) {
        let error = io::Error::from(io::ErrorKind::TimedOut);
        let mut rd = ErrorRead::new(error);
        d.read(&mut rd)
            .expect_err("error not propagated");
    }

    fn input_whole_incremental(d: &mut MessageDeframer, bytes: &[u8]) {
        let frames_before = d.frames.len();

        for i in 0..bytes.len() {
            assert_len(1, input_bytes(d, &bytes[i..i + 1]));
            assert_eq!(d.has_pending(), true);

            if i < bytes.len() - 1 {
                assert_eq!(frames_before, d.frames.len());
            }
        }

        assert_eq!(frames_before + 1, d.frames.len());
    }

    fn assert_len(want: usize, got: io::Result<usize>) {
        if let Ok(gotval) = got {
            assert_eq!(gotval, want);
        } else {
            assert!(false, "read failed, expected {:?} bytes", want);
        }
    }

    fn pop_first(d: &mut MessageDeframer) {
        let mut m = d.frames.pop_front().unwrap();
        m.decode_payload();
        assert_eq!(m.typ, msgs::enums::ContentType::Handshake);
    }

    fn pop_second(d: &mut MessageDeframer) {
        let mut m = d.frames.pop_front().unwrap();
        m.decode_payload();
        assert_eq!(m.typ, msgs::enums::ContentType::Alert);
    }

    #[test]
    fn check_incremental() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert_eq!(d.has_pending(), true);
        assert_eq!(1, d.frames.len());
        pop_first(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn check_incremental_2() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert_eq!(d.has_pending(), true);
        input_whole_incremental(&mut d, SECOND_MESSAGE);
        assert_eq!(d.has_pending(), true);
        assert_eq!(2, d.frames.len());
        pop_first(&mut d);
        assert_eq!(d.has_pending(), true);
        pop_second(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn check_whole() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert_eq!(d.has_pending(), true);
        assert_eq!(d.frames.len(), 1);
        pop_first(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn check_whole_2() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert_len(SECOND_MESSAGE.len(), input_bytes(&mut d, SECOND_MESSAGE));
        assert_eq!(d.frames.len(), 2);
        pop_first(&mut d);
        pop_second(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn test_two_in_one_read() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        assert_len(FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
                   input_bytes_concat(&mut d, FIRST_MESSAGE, SECOND_MESSAGE));
        assert_eq!(d.frames.len(), 2);
        pop_first(&mut d);
        pop_second(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn test_two_in_one_read_shortest_first() {
        let mut d = MessageDeframer::new();
        assert_eq!(d.has_pending(), false);
        assert_len(FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
                   input_bytes_concat(&mut d, SECOND_MESSAGE, FIRST_MESSAGE));
        assert_eq!(d.frames.len(), 2);
        pop_second(&mut d);
        pop_first(&mut d);
        assert_eq!(d.has_pending(), false);
    }

    #[test]
    fn test_incremental_with_nonfatal_read_error() {
        let mut d = MessageDeframer::new();
        assert_len(3, input_bytes(&mut d, &FIRST_MESSAGE[..3]));
        input_error(&mut d);
        assert_len(FIRST_MESSAGE.len() - 3,
                   input_bytes(&mut d, &FIRST_MESSAGE[3..]));
        assert_eq!(d.frames.len(), 1);
        pop_first(&mut d);
        assert_eq!(d.has_pending(), false);
    }
}
