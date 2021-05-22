use crate::msgs::codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload, OpaqueMessage};

const HEADER_SIZE: usize = 1 + 3;

/// This works to reconstruct TLS handshake messages
/// from individual TLS messages.  It's guaranteed that
/// TLS messages output from this layer contain precisely
/// one handshake payload.
pub struct HandshakeJoiner {
    /// The message payload we're currently accumulating.
    buf: Vec<u8>,
    version: ProtocolVersion,
}

impl HandshakeJoiner {
    pub fn new() -> Self {
        HandshakeJoiner {
            buf: Vec::new(),
            version: ProtocolVersion::TLSv1_2,
        }
    }

    /// Do we want to process this message?
    pub fn want_message(&self, msg: &OpaqueMessage) -> bool {
        msg.typ == ContentType::Handshake
    }

    /// Do we have any buffered data?
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Take the message, and join/split it as needed
    pub fn take_message(&mut self, msg: OpaqueMessage) {
        // The vast majority of the time `self.buf` will be empty since most
        // handshake messages arrive in a single fragment. Avoid allocating and
        // copying in that common case.
        if self.buf.is_empty() {
            self.buf = msg.payload;
        } else {
            self.buf
                .extend_from_slice(&msg.payload[..]);
        }

        if msg.version == ProtocolVersion::TLSv1_3 {
            self.version = ProtocolVersion::TLSv1_3;
        }
    }

    pub fn iter(&mut self) -> (HandshakeMessageIter<'_>, bool) {
        let mut buf = &self.buf[..];
        while let Some(len) = contains_message(buf) {
            buf = &buf[len..];
        }
        let aligned = buf.is_empty();

        (
            HandshakeMessageIter {
                buf: &mut self.buf,
                offset: 0,
                version: self.version,
            },
            aligned,
        )
    }
}

pub struct HandshakeMessageIter<'a> {
    buf: &'a mut Vec<u8>,
    offset: usize,
    version: ProtocolVersion,
}

impl<'a> HandshakeMessageIter<'a> {
    pub fn pop(&mut self) -> Option<Result<Message<'_>, DecodeError>> {
        let buf = self.buf.split_at(self.offset).1;
        contains_message(buf)?;

        let mut rd = codec::Reader::init(buf);
        let payload = match HandshakeMessagePayload::read_version(&mut rd, self.version) {
            Some(p) => p,
            None => return Some(Err(DecodeError(()))),
        };

        self.offset += rd.used();
        Some(Ok(Message {
            version: self.version,
            payload: MessagePayload::Handshake(payload),
        }))
    }
}

impl<'a> Drop for HandshakeMessageIter<'a> {
    fn drop(&mut self) {
        match self.offset == self.buf.len() {
            true => self.buf.clear(),
            false => {
                let new_len = self.buf.len() - self.offset;
                self.buf.copy_within(self.offset.., 0);
                self.buf.truncate(new_len);
            }
        }
    }
}

/// Does our `buf` contain a full handshake payload?  It does if it is big
/// enough to contain a header, and that header has a length which falls
/// within `buf`.
fn contains_message(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_SIZE {
        return None;
    }

    let (header, rest) = buf.split_at(HEADER_SIZE);
    codec::u24::decode(&header[1..]).and_then(|len| {
        let len = usize::from(len);
        rest.get(..len)
            .map(|_| HEADER_SIZE + len)
    })
}

#[derive(Debug)]
pub struct DecodeError(());

#[cfg(test)]
mod tests {
    use super::HandshakeJoiner;
    use crate::msgs::base::Payload;
    use crate::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
    use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
    use crate::msgs::message::{Message, MessagePayload, OpaqueMessage};

    #[test]
    fn want() {
        let hj = HandshakeJoiner::new();
        assert_eq!(hj.is_empty(), true);

        let wanted = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"hello world".to_vec(),
        };

        let unwanted = OpaqueMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: b"ponytown".to_vec(),
        };

        assert_eq!(hj.want_message(&wanted), true);
        assert_eq!(hj.want_message(&unwanted), false);
    }

    fn pop_eq(expect: &OpaqueMessage, hj: &mut HandshakeJoiner) {
        let mut iter = hj.iter().0;
        let got = iter.pop().unwrap().unwrap();
        assert_eq!(got.payload.content_type(), expect.typ);
        assert_eq!(got.version, expect.version);

        let (mut left, mut right) = (Vec::new(), Vec::new());
        got.payload.encode(&mut left);
        right.extend(&expect.payload);

        assert_eq!(left, right);
    }

    fn expect_err(hj: &mut HandshakeJoiner) {
        let mut iter = hj.iter().0;
        assert!(iter.pop().unwrap().is_err());
    }

    #[test]
    fn split() {
        // Check we split two handshake messages within one PDU.
        let mut hj = HandshakeJoiner::new();

        // two HelloRequests
        let msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        assert_eq!(hj.is_empty(), false);

        let expect = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::HelloRequest,
                payload: HandshakePayload::HelloRequest,
            }),
        }
        .into();

        pop_eq(&expect, &mut hj);
        pop_eq(&expect, &mut hj);
    }

    #[test]
    fn broken() {
        // Check obvious crap payloads are reported as errors, not panics.
        let mut hj = HandshakeJoiner::new();

        // short ClientHello
        let msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x01\x00\x00\x02\xff\xff".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        expect_err(&mut hj);
    }

    #[test]
    fn join() {
        // Check we join one handshake message split over two PDUs.
        let mut hj = HandshakeJoiner::new();
        assert_eq!(hj.is_empty(), true);

        // Introduce Finished of 16 bytes, providing 4.
        let mut msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x14\x00\x00\x10\x00\x01\x02\x03\x04".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        assert_eq!(hj.is_empty(), false);

        // 11 more bytes.
        msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        assert_eq!(hj.is_empty(), false);

        // Final 1 byte.
        msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x0f".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        assert_eq!(hj.is_empty(), false);

        let payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec();
        let expect = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(Payload::new(payload)),
            }),
        }
        .into();

        pop_eq(&expect, &mut hj);
    }

    #[test]
    fn test_rejoins_then_rejects_giant_certs() {
        let mut hj = HandshakeJoiner::new();
        let msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x0b\x01\x00\x04\x01\x00\x01\x00\xff\xfe".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        assert_eq!(hj.is_empty(), false);

        for _i in 0..8191 {
            let msg = OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec(),
            };

            assert_eq!(hj.want_message(&msg), true);
            hj.take_message(msg);
            assert_eq!(hj.is_empty(), false);
        }

        // final 6 bytes
        let msg = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: b"\x01\x02\x03\x04\x05\x06".to_vec(),
        };

        assert_eq!(hj.want_message(&msg), true);
        hj.take_message(msg);
        expect_err(&mut hj);
    }
}
