use std::collections::VecDeque;

use crate::enums::ProtocolVersion;
use crate::msgs::base::Payload;
use crate::msgs::codec;
use crate::msgs::enums::ContentType;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload, PlainMessage};

const HEADER_SIZE: usize = 1 + 3;

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

/// This works to reconstruct TLS handshake messages
/// from individual TLS messages.  It's guaranteed that
/// TLS messages output from this layer contain precisely
/// one handshake payload.
pub struct HandshakeJoiner {
    /// The message payload(s) we're currently accumulating.
    buf: Vec<u8>,

    /// Sizes of messages currently in the buffer.
    ///
    /// The buffer can be larger than the sum of the sizes in this queue, because it might contain
    /// the start of a message that hasn't fully been received yet as its suffix.
    sizes: VecDeque<usize>,

    /// Version of the protocol we're currently parsing.
    version: ProtocolVersion,
}

impl HandshakeJoiner {
    /// Make a new HandshakeJoiner.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            sizes: VecDeque::new(),
            version: ProtocolVersion::TLSv1_2,
        }
    }

    /// Take the message, and join/split it as needed.
    ///
    /// Returns `Err(JoinerError::Unwanted(msg))` if `msg`'s type is not `ContentType::Handshake` or
    /// `JoinerError::Decode` if a received payload has an advertised size larger than we accept.
    ///
    /// Otherwise, yields a `bool` to indicate whether the handshake is "aligned": if the buffer currently
    /// only contains complete payloads (that is, no incomplete message in the suffix).
    pub fn push(&mut self, msg: PlainMessage) -> Result<bool, JoinerError> {
        if msg.typ != ContentType::Handshake {
            return Err(JoinerError::Unwanted(msg));
        }

        // The vast majority of the time `self.buf` will be empty since most
        // handshake messages arrive in a single fragment. Avoid allocating and
        // copying in that common case.
        if self.buf.is_empty() {
            self.buf = msg.payload.0;
        } else {
            self.buf
                .extend_from_slice(&msg.payload.0[..]);
        }

        if msg.version == ProtocolVersion::TLSv1_3 {
            self.version = msg.version;
        }

        // Check the suffix of the buffer that hasn't been covered by `sizes` so far
        // for complete messages. If we find any, update `self.sizes` and `complete`.
        let mut complete = self.sizes.iter().copied().sum();
        while let Some(size) = payload_size(&self.buf[complete..])? {
            self.sizes.push_back(size);
            complete += size;
        }

        // Use the value of `complete` to determine if the buffer currently contains any
        // incomplete messages. If not, an incoming message is said to be "aligned".
        Ok(complete == self.buf.len())
    }

    /// Parse the first received message out of the buffer.
    ///
    /// Returns `Ok(None)` if we don't have a complete message in the buffer, or `Err` if we
    /// fail to parse the first message in the buffer.
    pub fn pop(&mut self) -> Result<Option<Message>, JoinerError> {
        let len = match self.sizes.pop_front() {
            Some(len) => len,
            None => return Ok(None),
        };

        // Parse the first part of the buffer as a handshake buffer.
        // If we get `None` back, we've failed to parse the message.
        // If we succeed, drain the relevant bytes from the buffer.

        let buf = &self.buf[..len];
        let mut rd = codec::Reader::init(buf);
        let parsed = match HandshakeMessagePayload::read_version(&mut rd, self.version) {
            Some(p) => p,
            None => return Err(JoinerError::Decode),
        };

        let message = Message {
            version: self.version,
            payload: MessagePayload::Handshake {
                parsed,
                encoded: Payload::new(buf),
            },
        };

        self.buf.drain(..len);
        Ok(Some(message))
    }
}

/// Does `buf` contain a full handshake payload?
///
/// Returns `Ok(Some(_))` with the length of the payload (including header) if it does,
/// `Ok(None)` if the buffer is too small to contain a message with the length advertised in the
/// header, or `Err` if the advertised length is larger than what we want to accept
/// (`MAX_HANDSHAKE_SIZE`).
fn payload_size(buf: &[u8]) -> Result<Option<usize>, JoinerError> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    let (header, rest) = buf.split_at(HEADER_SIZE);
    match codec::u24::decode(&header[1..]) {
        Some(len) if len.0 > MAX_HANDSHAKE_SIZE => Err(JoinerError::Decode),
        Some(len) if rest.get(..len.into()).is_some() => Ok(Some(HEADER_SIZE + usize::from(len))),
        _ => Ok(None),
    }
}

#[derive(Debug)]
pub enum JoinerError {
    Unwanted(PlainMessage),
    Decode,
}

#[cfg(test)]
mod tests {
    use super::HandshakeJoiner;
    use crate::enums::ProtocolVersion;
    use crate::msgs::base::Payload;
    use crate::msgs::codec::Codec;
    use crate::msgs::enums::{ContentType, HandshakeType};
    use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
    use crate::msgs::message::{Message, MessagePayload, PlainMessage};

    #[test]
    fn want() {
        let mut hj = HandshakeJoiner::new();
        let wanted = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x00\x00\x00\x00".to_vec()),
        };

        let unwanted = PlainMessage {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"ponytown".to_vec()),
        };

        hj.push(wanted).unwrap();
        hj.push(unwanted).unwrap_err();
    }

    fn pop_eq(expect: &PlainMessage, hj: &mut HandshakeJoiner) {
        let got = hj.pop().unwrap().unwrap();
        assert_eq!(got.payload.content_type(), expect.typ);
        assert_eq!(got.version, expect.version);

        let (mut left, mut right) = (Vec::new(), Vec::new());
        got.payload.encode(&mut left);
        expect.payload.encode(&mut right);

        assert_eq!(left, right);
    }

    #[test]
    fn split() {
        // Check we split two handshake messages within one PDU.
        let mut hj = HandshakeJoiner::new();

        // two HelloRequests
        assert!(hj
            .push(PlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()),
            })
            .unwrap());

        let expect = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
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
        hj.push(PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x00\x00\x02\xff\xff".to_vec()),
        })
        .unwrap();

        hj.pop().unwrap_err();
    }

    #[test]
    fn join() {
        // Check we join one handshake message split over two PDUs.
        let mut hj = HandshakeJoiner::new();

        // Introduce Finished of 16 bytes, providing 4.
        hj.push(PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x14\x00\x00\x10\x00\x01\x02\x03\x04".to_vec()),
        })
        .unwrap();

        // 11 more bytes.
        assert!(!hj
            .push(PlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(b"\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e".to_vec()),
            })
            .unwrap());

        // Final 1 byte.
        assert!(hj
            .push(PlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(b"\x0f".to_vec()),
            })
            .unwrap());

        let payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec();
        let expect = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::Finished,
                payload: HandshakePayload::Finished(Payload::new(payload)),
            }),
        }
        .into();

        pop_eq(&expect, &mut hj);
    }

    #[test]
    fn test_rejects_giant_certs() {
        let mut hj = HandshakeJoiner::new();
        hj.push(PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x0b\x01\x00\x04\x01\x00\x01\x00\xff\xfe".to_vec()),
        })
        .unwrap_err();
    }
}
