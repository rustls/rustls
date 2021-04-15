use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{BorrowMessage, Message, MessagePayload};
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
    pub fn fragment(&self, msg: Message, out: &mut VecDeque<Message>) {
        // Non-fragment path
        if msg.payload.length() <= self.max_frag {
            out.push_back(msg.into_opaque());
            return;
        }

        let typ = msg.typ;
        let version = msg.version;
        let payload = msg.take_payload();

        for chunk in payload.chunks(self.max_frag) {
            let m = Message {
                typ,
                version,
                payload: MessagePayload::new_opaque(chunk.to_vec()),
            };
            out.push_back(m);
        }
    }

    /// Enqueue borrowed fragments of (version, typ, payload) which
    /// are no longer than max_frag onto the `out` deque.
    pub fn fragment_borrow<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: &'a [u8],
        out: &mut VecDeque<BorrowMessage<'a>>,
    ) {
        for chunk in payload.chunks(self.max_frag) {
            let cm = BorrowMessage {
                typ,
                version,
                payload: chunk,
            };
            out.push_back(cm);
        }
    }
}
