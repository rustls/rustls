
use std::collections::VecDeque;
use msgs::message::{Message, MessagePayload};

pub const MAX_FRAGMENT_LEN: usize = 16384;
pub const PACKET_OVERHEAD: usize = 1 + 2 + 2;

pub struct MessageFragmenter {
  max_frag: usize
}

impl MessageFragmenter {
  /// Make a new fragmenter.  `max_fragment_len` is the maximum
  /// fragment size that will be produced -- this does not
  /// include overhead (so a `max_fragment_len` of 5 will produce
  /// 10 byte packets).
  pub fn new(max_fragment_len: usize) -> MessageFragmenter {
    debug_assert!(max_fragment_len <= MAX_FRAGMENT_LEN);
    MessageFragmenter {
      max_frag: max_fragment_len
    }
  }

  /// Take the Message `msg` and re-fragment it into new
  /// messages whose fragment is no more than max_frag.
  /// The new messages are appended to the `out` deque.
  pub fn fragment(&self, msg: Message, out: &mut VecDeque<Message>) {
    // Non-fragment path
    if msg.payload.len() <= self.max_frag {
      out.push_back(msg.into_opaque());
      return;
    }

    let mut payload = Vec::new();
    msg.payload.encode(&mut payload);

    for chunk in payload.chunks(self.max_frag) {
      let cm = Message {
        typ: msg.typ,
        version: msg.version,
        payload: MessagePayload::opaque(chunk.to_vec())
      };
      out.push_back(cm);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{MessageFragmenter, PACKET_OVERHEAD};
  use msgs::message::{MessagePayload, Message};
  use msgs::enums::{ContentType, ProtocolVersion};
  use msgs::codec::Codec;
  use std::collections::VecDeque;

  fn msg_eq(mm: Option<Message>, total_len: usize, typ: &ContentType, version: &ProtocolVersion, bytes: &[u8]) {
    let mut m = mm.unwrap();

    let mut buf = Vec::new();
    m.encode(&mut buf);

    assert_eq!(&m.typ, typ);
    assert_eq!(&m.version, version);
    assert_eq!(m.take_opaque_payload().unwrap().0, bytes.to_vec());

    assert_eq!(total_len, buf.len());
  }

  #[test]
  fn smoke() {
    let typ = ContentType::Handshake;
    let version = ProtocolVersion::TLSv1_2;
    let m = Message {
      typ: typ,
      version: version,
      payload: MessagePayload::opaque(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec())
    };

    let frag = MessageFragmenter::new(3);
    let mut q = VecDeque::new();
    frag.fragment(m, &mut q);
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 3, &typ, &version, b"\x01\x02\x03");
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 3, &typ, &version, b"\x04\x05\x06");
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 2, &typ, &version, b"\x07\x08");
    assert_eq!(q.len(), 0);
  }

  #[test]
  fn non_fragment() {
    let m = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec())
    };

    let frag = MessageFragmenter::new(8);
    let mut q = VecDeque::new();
    frag.fragment(m, &mut q);
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 8,
           &ContentType::Handshake,
           &ProtocolVersion::TLSv1_2,
           b"\x01\x02\x03\x04\x05\x06\x07\x08");
    assert_eq!(q.len(), 0);
  }
}
