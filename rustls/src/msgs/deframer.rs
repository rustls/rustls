use std::io;

use super::enums::ContentType;
use crate::error::Error;
use crate::msgs::codec;
use crate::msgs::message::{MessageError, OpaqueMessage};
use crate::record_layer::{Decrypted, RecordLayer};

/// This deframer works to reconstruct TLS messages
/// from arbitrary-sized reads, buffering as necessary.
/// The input is `read()`, get the output from `pop()`.
#[derive(Default)]
pub struct MessageDeframer {
    /// Set to true if the peer is not talking TLS, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    desynced: bool,

    /// A fixed-size buffer containing the currently-accumulating
    /// TLS message.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,
}

impl MessageDeframer {
    /// Return any decrypted messages that the deframer has been able to parse.
    ///
    /// Returns an `Error` if the deframer failed to parse some message contents or if decryption
    /// failed, `Ok(None)` if no full message is buffered or if trial decryption failed, and
    /// `Ok(Some(_))` if a valid message was found and decrypted successfully.
    pub fn pop(&mut self, record_layer: &mut RecordLayer) -> Result<Option<Decrypted>, Error> {
        if self.desynced {
            return Err(Error::CorruptMessage);
        }

        // Does our `buf` contain a full message?  It does if it is big enough to
        // contain a header, and that header has a length which falls within `buf`.
        // If so, deframe it and place the message onto the frames output queue.
        let mut rd = codec::Reader::init(&self.buf[..self.used]);
        let m = match OpaqueMessage::read(&mut rd) {
            Ok(m) => m,
            Err(MessageError::TooShortForHeader | MessageError::TooShortForLength) => {
                return Ok(None)
            }
            Err(_) => {
                self.desynced = true;
                return Err(Error::CorruptMessage);
            }
        };

        let taken = rd.used();
        #[allow(clippy::comparison_chain)]
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

            self.buf
                .copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken == self.used {
            self.used = 0;
        }

        // Return CCS messages immediately without decrypting.
        if m.typ == ContentType::ChangeCipherSpec {
            // This is unencrypted. We check the contents later.
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: m.into_plain_message(),
            }));
        }

        record_layer.decrypt_incoming(m)
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    #[allow(clippy::comparison_chain)]
    pub fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        if self.used == OpaqueMessage::MAX_WIRE_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "message buffer full"));
        }

        // Try to do the largest reads possible.  Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        debug_assert!(self.used <= OpaqueMessage::MAX_WIRE_SIZE);
        let need_capacity = Ord::min(OpaqueMessage::MAX_WIRE_SIZE, self.used + READ_SIZE);
        self.buf.resize(need_capacity, 0);
        let new_bytes = rd.read(&mut self.buf[self.used..])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller
    /// to process, either whole messages in our output
    /// queue or partial messages in our buffer.
    pub fn has_pending(&self) -> bool {
        self.used > 0
    }
}

const READ_SIZE: usize = 4096;

#[cfg(test)]
mod tests {
    use super::MessageDeframer;
    use crate::msgs::message::{Message, OpaqueMessage};
    use crate::record_layer::RecordLayer;
    use crate::{msgs, Error};

    use std::io;

    const FIRST_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.1.bin");
    const SECOND_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.2.bin");

    const EMPTY_APPLICATIONDATA_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-empty-applicationdata.bin");

    const INVALID_EMPTY_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-empty.bin");
    const INVALID_CONTENTTYPE_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-contenttype.bin");
    const INVALID_VERSION_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-version.bin");
    const INVALID_LENGTH_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-length.bin");

    struct ByteRead<'a> {
        buf: &'a [u8],
        offs: usize,
    }

    impl<'a> ByteRead<'a> {
        fn new(bytes: &'a [u8]) -> Self {
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

    fn input_bytes_concat(
        d: &mut MessageDeframer,
        bytes1: &[u8],
        bytes2: &[u8],
    ) -> io::Result<usize> {
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
        fn new(error: io::Error) -> Self {
            Self { error: Some(error) }
        }
    }

    impl io::Read for ErrorRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }

            let error = self.error.take().unwrap();
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
        let before = d.used;

        for i in 0..bytes.len() {
            assert_len(1, input_bytes(d, &bytes[i..i + 1]));
            assert!(d.has_pending());
        }

        assert_eq!(before + bytes.len(), d.used);
    }

    fn assert_len(want: usize, got: io::Result<usize>) {
        if let Ok(gotval) = got {
            assert_eq!(gotval, want);
        } else {
            panic!("read failed, expected {:?} bytes", want);
        }
    }

    fn pop_first(d: &mut MessageDeframer, rl: &mut RecordLayer) {
        let m = d.pop(rl).unwrap().unwrap().plaintext;
        assert_eq!(m.typ, msgs::enums::ContentType::Handshake);
        Message::try_from(m).unwrap();
    }

    fn pop_second(d: &mut MessageDeframer, rl: &mut RecordLayer) {
        let m = d.pop(rl).unwrap().unwrap().plaintext;
        assert_eq!(m.typ, msgs::enums::ContentType::Alert);
        Message::try_from(m).unwrap();
    }

    #[test]
    fn check_incremental() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn check_incremental_2() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());
        input_whole_incremental(&mut d, SECOND_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(d.has_pending());
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn check_whole() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn check_whole_2() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert_len(SECOND_MESSAGE.len(), input_bytes(&mut d, SECOND_MESSAGE));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn test_two_in_one_read() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            input_bytes_concat(&mut d, FIRST_MESSAGE, SECOND_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn test_two_in_one_read_shortest_first() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            input_bytes_concat(&mut d, SECOND_MESSAGE, FIRST_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_second(&mut d, &mut rl);
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn test_incremental_with_nonfatal_read_error() {
        let mut d = MessageDeframer::default();
        assert_len(3, input_bytes(&mut d, &FIRST_MESSAGE[..3]));
        input_error(&mut d);
        assert_len(
            FIRST_MESSAGE.len() - 3,
            input_bytes(&mut d, &FIRST_MESSAGE[3..]),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn test_invalid_contenttype_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_CONTENTTYPE_MESSAGE.len(),
            input_bytes(&mut d, INVALID_CONTENTTYPE_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(d.pop(&mut rl).unwrap_err(), Error::CorruptMessage);
    }

    #[test]
    fn test_invalid_version_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_VERSION_MESSAGE.len(),
            input_bytes(&mut d, INVALID_VERSION_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(d.pop(&mut rl).unwrap_err(), Error::CorruptMessage);
    }

    #[test]
    fn test_invalid_length_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_LENGTH_MESSAGE.len(),
            input_bytes(&mut d, INVALID_LENGTH_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(d.pop(&mut rl).unwrap_err(), Error::CorruptMessage);
    }

    #[test]
    fn test_empty_applicationdata() {
        let mut d = MessageDeframer::default();
        assert_len(
            EMPTY_APPLICATIONDATA_MESSAGE.len(),
            input_bytes(&mut d, EMPTY_APPLICATIONDATA_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        let m = d.pop(&mut rl).unwrap().unwrap().plaintext;
        assert_eq!(m.typ, msgs::enums::ContentType::ApplicationData);
        assert_eq!(m.payload.0.len(), 0);
        assert!(!d.has_pending());
        assert!(!d.desynced);
    }

    #[test]
    fn test_invalid_empty_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_EMPTY_MESSAGE.len(),
            input_bytes(&mut d, INVALID_EMPTY_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(d.pop(&mut rl).unwrap_err(), Error::CorruptMessage);
        // CorruptMessage has been fused
        assert_eq!(d.pop(&mut rl).unwrap_err(), Error::CorruptMessage);
    }

    #[test]
    fn test_limited_buffer() {
        const PAYLOAD_LEN: usize = 16_384;
        let mut message = Vec::with_capacity(16_389);
        message.push(0x17); // ApplicationData
        message.extend(&[0x03, 0x04]); // ProtocolVersion
        message.extend((PAYLOAD_LEN as u16).to_be_bytes()); // payload length
        message.extend(&[0; PAYLOAD_LEN]);

        let mut d = MessageDeframer::default();
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(
            OpaqueMessage::MAX_WIRE_SIZE - 16_384,
            input_bytes(&mut d, &message),
        );
        assert!(input_bytes(&mut d, &message).is_err());
    }
}
