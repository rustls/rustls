use super::fragmenter::{MessageFragmenter, PACKET_OVERHEAD};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{Message, MessagePayload};
use std::collections::VecDeque;

fn msg_eq(
    mm: Option<Message>,
    total_len: usize,
    typ: &ContentType,
    version: &ProtocolVersion,
    bytes: &[u8],
) {
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
        typ,
        version,
        payload: MessagePayload::new_opaque(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
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
    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::new_opaque(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
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
