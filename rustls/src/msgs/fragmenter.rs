use crate::msgs::base::Payload;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{BorrowedOpaqueMessage, OpaqueMessage};
use std::collections::VecDeque;

pub const MAX_FRAGMENT_LEN: usize = 16384;
pub const PACKET_OVERHEAD: usize = 1 + 2 + 2;

pub struct MessageFragmenter {
    max_frag: usize,
}

impl MessageFragmenter {
    /// Make a new fragmenter.  `max_fragment_len` is the maximum
    /// fragment size that will be produced -- this does not
    /// include overhead (so a `max_fragment_len` of 5 will produce
    /// 10 byte packets).
    pub fn new(max_fragment_len: usize) -> MessageFragmenter {
        debug_assert!(max_fragment_len <= MAX_FRAGMENT_LEN);
        MessageFragmenter {
            max_frag: max_fragment_len,
        }
    }

    /// Take the Message `msg` and re-fragment it into new
    /// messages whose fragment is no more than max_frag.
    /// The new messages are appended to the `out` deque.
    /// Payloads are copied.
    pub fn fragment(&self, msg: OpaqueMessage, out: &mut VecDeque<OpaqueMessage>) {
        // Non-fragment path
        if msg.payload.0.len() <= self.max_frag {
            out.push_back(msg);
            return;
        }

        for chunk in msg.payload.0.chunks(self.max_frag) {
            out.push_back(OpaqueMessage {
                typ: msg.typ,
                version: msg.version,
                payload: Payload(chunk.to_vec()),
            });
        }
    }

    /// Enqueue borrowed fragments of (version, typ, payload) which
    /// are no longer than max_frag onto the `out` deque.
    pub fn fragment_borrow<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: &'a [u8],
        out: &mut VecDeque<BorrowedOpaqueMessage<'a>>,
    ) {
        for chunk in payload.chunks(self.max_frag) {
            let cm = BorrowedOpaqueMessage {
                typ,
                version,
                payload: chunk,
            };
            out.push_back(cm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::msgs::base::Payload;
    use crate::msgs::enums::{ContentType, ProtocolVersion};
    use crate::msgs::message::OpaqueMessage;
    use std::collections::VecDeque;

    fn msg_eq(
        mm: Option<OpaqueMessage>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        let m = mm.unwrap();
        let buf = m.clone().encode();

        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.0, bytes.to_vec());

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let m = OpaqueMessage {
            typ,
            version,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let frag = MessageFragmenter::new(3);
        let mut q = VecDeque::new();
        frag.fragment(m, &mut q);
        msg_eq(
            q.pop_front(),
            PACKET_OVERHEAD + 3,
            &typ,
            &version,
            b"\x01\x02\x03",
        );
        msg_eq(
            q.pop_front(),
            PACKET_OVERHEAD + 3,
            &typ,
            &version,
            b"\x04\x05\x06",
        );
        msg_eq(
            q.pop_front(),
            PACKET_OVERHEAD + 2,
            &typ,
            &version,
            b"\x07\x08",
        );
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn non_fragment() {
        let m = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let frag = MessageFragmenter::new(8);
        let mut q = VecDeque::new();
        frag.fragment(m, &mut q);
        msg_eq(
            q.pop_front(),
            PACKET_OVERHEAD + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
        assert_eq!(q.len(), 0);
    }
}
