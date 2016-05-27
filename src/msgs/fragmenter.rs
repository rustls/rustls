
use std::collections::VecDeque;
use msgs::message::{Message, MessagePayload};

pub const MAX_FRAGMENT_LEN: usize = 16384;

pub struct MessageFragmenter {
  max_frag: usize
}

impl MessageFragmenter {
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
  use super::MessageFragmenter;
  use msgs::message::{MessagePayload, Message};
  use msgs::enums::{ContentType, ProtocolVersion};
  use std::collections::VecDeque;

  fn msg_eq(mm: Option<Message>, typ: &ContentType, version: &ProtocolVersion, bytes: &[u8]) {
    let m = mm.unwrap();

    assert_eq!(&m.typ, typ);
    assert_eq!(&m.version, version);
    match m.payload {
      MessagePayload::Unknown(ref pl) => assert_eq!(pl.body.to_vec(), bytes.to_vec()),
      _ => unreachable!()
    };
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
    msg_eq(q.pop_front(), &m.typ, &m.version, b"\x01\x02\x03");
    msg_eq(q.pop_front(), &m.typ, &m.version, b"\x04\x05\x06");
    msg_eq(q.pop_front(), &m.typ, &m.version, b"\x07\x08");
    assert_eq!(q.len(), 0);
  }
}
