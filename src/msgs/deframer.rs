
use std::collections::VecDeque;
use std::io;

use msgs::codec;
use msgs::message::Message;

const HEADER_SIZE: usize = 1 + 2 + 2;

/* This is the maximum on-the-wire size of a TLSCiphertext.
 * That's 2^14 payload bytes, a header, and a 2KB allowance
 * for ciphertext overheads. */
const MAX_MESSAGE: usize = 16384 + 2048 + HEADER_SIZE;

/// This deframer works to reconstruct TLS messages
/// from arbitrary-sized reads, buffering as neccessary.
/// The input is `read()`, the output is the `frames` deque.
pub struct MessageDeframer {
  /// Completed frames for output.
  pub frames: VecDeque<Message>,

  /// A variable-size buffer containing the currently-
  /// accumulating TLS message.
  buf: Vec<u8>
}

impl MessageDeframer {
  pub fn new() -> MessageDeframer {
    MessageDeframer {
      frames: VecDeque::new(),
      buf: Vec::with_capacity(MAX_MESSAGE)
    }
  }

  /// Read some bytes from `rd`, and add them to our internal
  /// buffer.  If this means our internal buffer contains
  /// full messages, decode them all.
  pub fn read(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    /* Try to do the largest reads possible.  Note that if
     * we get a message with a length field out of range here,
     * we do a zero length read.  That looks like an EOF to
     * the next layer up, which is fine. */
    let used = self.buf.len();
    self.buf.resize(MAX_MESSAGE, 0u8);
    let rc = rd.read(&mut self.buf[used..MAX_MESSAGE]);

    if rc.is_err() {
      /* Discard indeterminate bytes. */
      self.buf.truncate(used);
      return rc;
    }

    let new_bytes = rc.unwrap();
    self.buf.truncate(used + new_bytes);

    while self.buf_contains_message() {
      self.deframe_one();
    }

    Ok(new_bytes)
  }

  /// Returns true if we have messages for the caller
  /// to process, either whole messages in our output
  /// queue or partial messages in our buffer.
  pub fn has_pending(&self) -> bool {
    self.frames.len() > 0 || self.buf.len() > 0
  }

  /// Does our `buf` contain a full message?  It does if it is big enough to
  /// contain a header, and that header has a length which falls within `buf`.
  fn buf_contains_message(&self) -> bool {
    if self.buf.len() < HEADER_SIZE {
      return false;
    }

    let msg_len = codec::decode_u16(&self.buf[3..5]).unwrap() as usize;
    self.buf.len() >= msg_len + HEADER_SIZE
  }

  /// Take a TLS message off the front of `buf`, and put it onto the back
  /// of our `frames` deque.
  fn deframe_one(&mut self) {
    let used = {
      let mut rd = codec::Reader::init(&self.buf);
      let m = Message::read(&mut rd).unwrap();
      let mut check = Vec::new();
      m.encode(&mut check);
      assert_eq!(check.as_slice(), &self.buf[..rd.used()]);
      self.frames.push_back(m);
      rd.used()
    };
    self.buf = self.buf.split_off(used);
  }
}

#[cfg(test)]
mod tests {
  use super::MessageDeframer;
  use std::io;
  use msgs;

  const FIRST_MESSAGE: &'static [u8] = b"\x16\x03\x01\x01\x49\x01\x00\x01\x45\x03\x03\x37\x84\xff\xb8\x8d\xeb\x79\xcc\x8c\xb8\xd4\x7e\xf7\x99\x75\x1e\x60\x30\x9a\x18\xf9\x90\xa9\xae\x60\x6c\xf7\xa5\xf8\x95\x88\xf6\x00\x00\xb4\xc0\x30\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\x00\xa5\x00\xa3\x00\xa1\x00\x9f\x00\x6b\x00\x6a\x00\x69\x00\x68\x00\x39\x00\x38\x00\x37\x00\x36\x00\x88\x00\x87\x00\x86\x00\x85\xc0\x32\xc0\x2e\xc0\x2a\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d\x00\x35\x00\x84\xc0\x2f\xc0\x2b\xc0\x27\xc0\x23\xc0\x13\xc0\x09\x00\xa4\x00\xa2\x00\xa0\x00\x9e\x00\x67\x00\x40\x00\x3f\x00\x3e\x00\x33\x00\x32\x00\x31\x00\x30\x00\x9a\x00\x99\x00\x98\x00\x97\x00\x45\x00\x44\x00\x43\x00\x42\xc0\x31\xc0\x2d\xc0\x29\xc0\x25\xc0\x0e\xc0\x04\x00\x9c\x00\x3c\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\xc0\x12\xc0\x08\x00\x16\x00\x13\x00\x10\x00\x0d\xc0\x0d\xc0\x03\x00\x0a\x00\x15\x00\x12\x00\x0f\x00\x0c\x00\x09\x00\xff\x01\x00\x00\x68\x00\x00\x00\x0f\x00\x0d\x00\x00\x0a\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x1c\x00\x1a\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\x0d\x00\x0b\x00\x0c\x00\x09\x00\x0a\x00\x23\x00\x00\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x0f\x00\x01\x01";
  const SECOND_MESSAGE: &'static [u8] = b"\x15\x03\x03\x00\x02\x01\x6e";

  struct ByteRead<'a> {
    buf: &'a [u8],
    offs: usize
  }

  impl<'a> ByteRead<'a> {
    fn new(bytes: &'a [u8]) -> ByteRead {
      ByteRead { buf: bytes, offs: 0 }
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

  fn input_whole_incremental(d: &mut MessageDeframer, bytes: &[u8]) {
    let frames_before = d.frames.len();

    for i in 0..bytes.len() {
      assert_len(1, input_bytes(d, &bytes[i..i+1]));
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
}
