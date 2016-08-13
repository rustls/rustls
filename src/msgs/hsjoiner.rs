
use std::collections::VecDeque;

use msgs::codec;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::handshake::HandshakeMessagePayload;

const HEADER_SIZE: usize = 1 + 3;

/// This works to reconstruct TLS handshake messages
/// from individual TLS messages.  It's guaranteed that
/// TLS messages output from this layer contain precisely
/// one handshake payload.
pub struct HandshakeJoiner {
  /// Completed handshake frames for output.
  pub frames: VecDeque<Message>,

  /// The message payload we're currently accumulating.
  buf: Vec<u8>
}

impl HandshakeJoiner {
  pub fn new() -> HandshakeJoiner{
    HandshakeJoiner {
      frames: VecDeque::new(),
      buf: Vec::new()
    }
  }

  /// Do we want to process this message?
  pub fn want_message(&self, msg: &Message) -> bool {
    msg.is_content_type(ContentType::Handshake)
  }

  /// Take the message, and join/split it as needed.
  /// Return the number of new messages added to the
  /// output deque as a result of this message.
  ///
  /// Returns None if msg or a preceding message was corrupt.
  /// You cannot recover from this situation.  Otherwise returns
  /// a count of how many messages we queued.
  pub fn take_message(&mut self, msg: &Message) -> Option<usize> {
    // Input must be opaque, otherwise we might have already
    // lost information!
    let payload = msg.get_opaque_payload().unwrap();

    self.buf.extend_from_slice(&payload.body[..]);

    let mut count = 0;
    while self.buf_contains_message() {
      if !self.deframe_one() {
        return None;
      }

      count += 1;
    }

    Some(count)
  }

  /// Does our `buf` contain a full handshake payload?  It does if it is big
  /// enough to contain a header, and that header has a length which falls
  /// within `buf`.
  fn buf_contains_message(&self) -> bool {
    self.buf.len() >= HEADER_SIZE &&
      self.buf.len() >= (codec::decode_u24(&self.buf[1..4]).unwrap() as usize) + HEADER_SIZE
  }

  /// Take a TLS handshake payload off the front of `buf`, and put it onto
  /// the back of our `frames` deque inside a normal `Message`.
  ///
  /// Returns false if the stream is desynchronised beyond repair.
  fn deframe_one(&mut self) -> bool {
    let used = {
      let mut rd = codec::Reader::init(&self.buf);
      let payload = HandshakeMessagePayload::read(&mut rd);

      if payload.is_none() {
        return false;
      }

      let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(payload.unwrap())
      };

      self.frames.push_back(m);
      rd.used()
    };
    self.buf = self.buf.split_off(used);
    true
  }
}

#[cfg(test)]
mod tests {
  use super::HandshakeJoiner;
  use msgs::enums::{ProtocolVersion, ContentType, HandshakeType};
  use msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
  use msgs::message::{Message, MessagePayload};
  use msgs::base::Payload;

  #[test]
  fn want() {
    let hj = HandshakeJoiner::new();

    let wanted = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"hello world".to_vec())
    };

    let unwanted = Message {
      typ: ContentType::Alert,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"ponytown".to_vec())
    };

    assert_eq!(hj.want_message(&wanted), true);
    assert_eq!(hj.want_message(&unwanted), false);
  }

  fn pop_eq(expect: &Message, hj: &mut HandshakeJoiner) {
    let got = hj.frames.pop_front().unwrap();
    assert_eq!(got.typ, expect.typ);
    assert_eq!(got.version, expect.version);

    let (mut left, mut right) = (Vec::new(), Vec::new());
    got.payload.encode(&mut left);
    expect.payload.encode(&mut right);

    assert_eq!(left, right);
  }

  #[test]
  fn split() {
    /* Check we split two handshake messages within one PDU. */
    let mut hj = HandshakeJoiner::new();

    let msg = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()) /* two HelloRequests. */
    };

    assert_eq!(hj.want_message(&msg), true);
    assert_eq!(hj.take_message(&msg), Some(2));

    let expect = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::Handshake(
        HandshakeMessagePayload {
          typ: HandshakeType::HelloRequest,
          payload: HandshakePayload::HelloRequest
        })
    };

    pop_eq(&expect, &mut hj);
    pop_eq(&expect, &mut hj);
  }

  #[test]
  fn broken() {
    /* Check obvious crap payloads are reported as errors, not panics. */
    let mut hj = HandshakeJoiner::new();

    let msg = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x01\x00\x00\x02\xff\xff".to_vec()) /* short ClientHello. */
    };

    assert_eq!(hj.want_message(&msg), true);
    assert_eq!(hj.take_message(&msg), None);
  }

  #[test]
  fn join() {
    /* Check we join one handshake message split over two PDUs. */
    let mut hj = HandshakeJoiner::new();

    /* Introduce Finished of 16 bytes, providing 4. */
    let mut msg = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x14\x00\x00\x10\x00\x01\x02\x03\x04".to_vec())
    };

    assert_eq!(hj.want_message(&msg), true);
    assert_eq!(hj.take_message(&msg), Some(0));

    /* 11 more bytes. */
    msg = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e".to_vec())
    };

    assert_eq!(hj.want_message(&msg), true);
    assert_eq!(hj.take_message(&msg), Some(0));

    /* Final 1 byte. */
    msg = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x0f".to_vec())
    };

    assert_eq!(hj.want_message(&msg), true);
    assert_eq!(hj.take_message(&msg), Some(1));

    let expect = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::Handshake(
        HandshakeMessagePayload {
          typ: HandshakeType::Finished,
          payload: HandshakePayload::Finished(
            Payload { body: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec().into_boxed_slice() }
          )
        }
      )
    };

    pop_eq(&expect, &mut hj);
  }
}
