
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
    assert!(max_fragment_len <= MAX_FRAGMENT_LEN);
    MessageFragmenter {
      max_frag: max_fragment_len
    }
  }

  /// Take the Message `msg` and re-fragment it into new
  /// messages whose fragment is no more than max_frag.
  /// The new messages are appended to the `out` deque.
  pub fn fragment(&self, msg: &Message, out: &mut VecDeque<Message>) {
    let mut payload = Vec::new();
    msg.payload.encode(&mut payload);

    for chunk in payload.chunks(self.max_frag) {
      let cm = Message {
        typ: msg.typ.clone(),
        version: msg.version.clone(),
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
  use std::collections::VecDeque;

  fn msg_eq(mm: Option<Message>, total_len: usize, typ: &ContentType, version: &ProtocolVersion, bytes: &[u8]) {
    let m = mm.unwrap();

    assert_eq!(&m.typ, typ);
    assert_eq!(&m.version, version);
    assert_eq!(m.get_opaque_payload().unwrap().body.to_vec(), bytes.to_vec());

    let mut buf = Vec::new();
    m.encode(&mut buf);
    assert_eq!(total_len, buf.len());
  }

  #[test]
  fn smoke() {
    let m = Message {
      typ: ContentType::Handshake,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec())
    };

    let frag = MessageFragmenter::new(3);
    let mut q = VecDeque::new();
    frag.fragment(&m, &mut q);
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 3, &m.typ, &m.version, b"\x01\x02\x03");
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 3, &m.typ, &m.version, b"\x04\x05\x06");
    msg_eq(q.pop_front(), PACKET_OVERHEAD + 2, &m.typ, &m.version, b"\x07\x08");
    assert_eq!(q.len(), 0);
  }
}
