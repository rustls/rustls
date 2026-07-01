use alloc::vec::Vec;
use std::vec;

use super::MessageFragmenter;
use crate::crypto::cipher::{EncodedMessage, Payload};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::codec::Codec;
use crate::msgs::{
    DTLS_12_HEADER_SIZE, DTLS_HANDSHAKE_HEADER_SIZE, DtlsHandshakeFragment, EpochAndSequence,
    HandshakeMessagePayload, HandshakePayload, Reader, U24, UnifiedHeader,
};

fn handshake_fragments_flush_with_record(version: ProtocolVersion) {
    // Message size and fragment size are chosen so that we'll get 4 fragments. Where r indicates
    // record header bytes (length depends on DTLS 1.2 vs 1.3), h indicates 12 bytes of
    // handshake header and H[x] indicates x bytes of handshake payload, we will get records:
    //
    // rhH[32]
    // rhH[32]
    // rhH[32]
    // rhH[4] <-- last record is smaller than fragment size
    let encoded_handshake = &[b'a'; 104];
    let mut fragmenter = MessageFragmenter::default();
    fragmenter
        .set_max_fragment_size(Some(
            32 + if version == ProtocolVersion::DTLSv1_2 {
                DTLS_12_HEADER_SIZE
            } else {
                UnifiedHeader::header_length(101)
            } + DTLS_HANDSHAKE_HEADER_SIZE,
        ))
        .unwrap();

    let fragments: Vec<_> = fragmenter
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(1, 101),
            HandshakeType::ClientHello,
            11,
            encoded_handshake,
        )
        .collect();
    assert_eq!(fragments.len(), 4);

    for (
        idx,
        (
            EncodedMessage {
                typ,
                version: encoded_version,
                payload:
                    DtlsHandshakeFragment {
                        msg_type,
                        length,
                        message_seq,
                        fragment_offset,
                        fragment_length,
                        fragment,
                    },
            },
            (expected_fragment_offset, expected_fragment_length),
        ),
    ) in fragments
        .into_iter()
        .zip([(0, 32), (32, 32), (64, 32), (96, 4)])
        .enumerate()
    {
        assert_eq!(typ, ContentType::Handshake, "fragment {idx}");
        assert_eq!(encoded_version, version, "fragment {idx}");
        assert_eq!(msg_type, HandshakeType::ClientHello, "fragment {idx}");
        assert_eq!(length, U24(100), "fragment {idx}");
        assert_eq!(message_seq, 11, "fragment {idx}");
        assert_eq!(
            fragment_offset,
            U24(expected_fragment_offset),
            "fragment {idx}"
        );
        assert_eq!(
            fragment_length,
            U24(expected_fragment_length),
            "fragment {idx}"
        );
        assert_eq!(
            fragment.bytes(),
            vec![b'a'; expected_fragment_length as usize].as_slice(),
            "fragment {idx}"
        );
    }
}

#[test]
fn handshake_fragments_flush_with_record_dtls_12() {
    handshake_fragments_flush_with_record(ProtocolVersion::DTLSv1_2);
}

#[test]
fn handshake_fragments_flush_with_record_dtls_13() {
    handshake_fragments_flush_with_record(ProtocolVersion::DTLSv1_3);
}

fn check_handshake_fragment(
    idx: usize,
    got: &DtlsHandshakeFragment<'_>,
    expected: &DtlsHandshakeFragment<'_>,
) {
    // Payload::Owned and Payload::Borrowed are not equal even if the contained bytes are
    // identical so we provide this helper
    assert_eq!(got.msg_type, expected.msg_type, "idx {idx}");
    assert_eq!(got.length, expected.length, "idx {idx}");
    assert_eq!(got.message_seq, expected.message_seq, "idx {idx}");
    assert_eq!(got.fragment_offset, expected.fragment_offset, "idx {idx}");
    assert_eq!(got.fragment_length, expected.fragment_length, "idx {idx}");
    assert_eq!(got.fragment.bytes(), expected.fragment.bytes(), "idx {idx}");
}

fn flight_handshake_fragments_flush_with_record(version: ProtocolVersion) {
    // Message lengths are chosen so that the first two each occupy an entire record and the
    // last partially. Where r indicates record header bytes (length varies based on protocol), h
    // indicates 12 bytes of handshake header and H[x] indicates x bytes of handshake payload, we
    // will get records:
    //
    // rhH[32]
    // rhH[32]
    // rhH[16] <-- last record is smaller than fragment size
    let messages = [vec![6u8; 32], vec![7; 32], vec![8; 16]];
    let message_flight: Vec<_> = messages
        .iter()
        .map(|m| {
            (
                HandshakeType::Finished,
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = MessageFragmenter::default();
    fragmenter
        .set_max_fragment_size(Some(
            32 + if version == ProtocolVersion::DTLSv1_2 {
                DTLS_12_HEADER_SIZE
            } else {
                UnifiedHeader::header_length(101)
            } + DTLS_HANDSHAKE_HEADER_SIZE,
        ))
        .unwrap();

    let records = fragmenter.fragment_dtls_handshake_message_flight(
        version,
        EpochAndSequence::new(11, 255),
        17,
        &message_flight,
    );
    assert_eq!(records.len(), 3);

    for (idx, (record, message)) in records.iter().zip(messages).enumerate() {
        assert_eq!(record.typ, ContentType::Handshake);
        assert_eq!(record.version, version);
        assert_eq!(
            record.payload.bytes().len(),
            message.len() + DTLS_HANDSHAKE_HEADER_SIZE
        );
        // read_bytes ensures that there are no trailing bytes in the payload, i.e. that each
        // record contains exactly one handshake fragment.
        let handshake_fragment = DtlsHandshakeFragment::read_bytes(record.payload.bytes()).unwrap();
        check_handshake_fragment(
            idx,
            &handshake_fragment,
            &DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(message.len().try_into().unwrap()),
                message_seq: 17 + idx as u16,
                fragment_offset: U24(0),
                fragment_length: U24(message.len().try_into().unwrap()),
                fragment: Payload::Borrowed(message.as_slice()),
            },
        );
    }
}

#[test]
fn flight_handshake_fragments_flush_with_record_dtls_12() {
    flight_handshake_fragments_flush_with_record(ProtocolVersion::DTLSv1_2);
}

#[test]
fn flight_handshake_fragments_flush_with_record_dtls_13() {
    flight_handshake_fragments_flush_with_record(ProtocolVersion::DTLSv1_3);
}

fn flight_handshake_fragments_span_record(version: ProtocolVersion) {
    // Message lengths are chosen so that the first occupies the entire first record and part of
    // the second, and the second occupies part of the second record and part of the third.
    // Using notation from dtls_flight_handshake_fragments_flush_with_record, we will get
    // records:
    //
    // rhH[32]      <-- first 32 bytes of first message
    // rhH[4]hH[16] <-- last 4 bytes of first message plus first 16 bytes of second message
    // rhH[16]      <-- last 16 bytes of second message; last record is smaller than fragment
    //                  size
    let messages = [vec![6u8; 36], vec![7; 32]];
    let message_flight: Vec<_> = messages
        .iter()
        .map(|m| {
            (
                HandshakeType::Finished,
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = MessageFragmenter::default();
    fragmenter
        .set_max_fragment_size(Some(
            32 + if version == ProtocolVersion::DTLSv1_2 {
                DTLS_12_HEADER_SIZE
            } else {
                UnifiedHeader::header_length(101)
            } + DTLS_HANDSHAKE_HEADER_SIZE,
        ))
        .unwrap();

    let records = fragmenter.fragment_dtls_handshake_message_flight(
        version,
        EpochAndSequence::new(11, 255),
        17,
        &message_flight,
    );
    assert_eq!(records.len(), 3);

    let mut handshake_fragments = Vec::new();

    for (idx, record) in records.iter().enumerate() {
        assert_eq!(record.typ, ContentType::Handshake);
        assert_eq!(record.version, version);
        if idx < 2 {
            assert_eq!(
                record.payload.bytes().len(),
                32 + DTLS_HANDSHAKE_HEADER_SIZE
            );
        } else {
            assert_eq!(
                record.payload.bytes().len(),
                16 + DTLS_HANDSHAKE_HEADER_SIZE
            );
        }

        let mut reader = Reader::new(record.payload.bytes());
        while reader.any_left() {
            handshake_fragments.push(DtlsHandshakeFragment::read(&mut reader).unwrap());
        }
    }

    let expected_fragments = [
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(36),
            message_seq: 17,
            fragment_offset: U24(0),
            fragment_length: U24(32),
            fragment: Payload::new([6; 32]),
        },
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(36),
            message_seq: 17,
            fragment_offset: U24(32),
            fragment_length: U24(4),
            fragment: Payload::new([6; 4]),
        },
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(32),
            message_seq: 18,
            fragment_offset: U24(0),
            fragment_length: U24(16),
            fragment: Payload::new([7; 16]),
        },
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(32),
            message_seq: 18,
            fragment_offset: U24(16),
            fragment_length: U24(16),
            fragment: Payload::new([7; 16]),
        },
    ];
    assert_eq!(handshake_fragments.len(), expected_fragments.len());

    for (idx, (handshake_fragment, expected_fragment)) in handshake_fragments
        .iter()
        .zip(expected_fragments)
        .enumerate()
    {
        check_handshake_fragment(idx, handshake_fragment, &expected_fragment);
    }
}

#[test]
fn flight_handshake_fragments_span_record_dtls_12() {
    flight_handshake_fragments_span_record(ProtocolVersion::DTLSv1_2);
}

#[test]
fn flight_handshake_fragments_span_record_dtls_13() {
    flight_handshake_fragments_span_record(ProtocolVersion::DTLSv1_3);
}

fn flight_partially_filled_record(version: ProtocolVersion) {
    // Message lengths are chosen so that the first occupies most of the first record, but
    // leaves less than DTLS_HANDSHAKE_HEADER_SIZE bytes remaining, such that the second message
    // gets pushed out to the second record.
    // Using notation from dtls_flight_handshake_fragments_flush_with_record, we will get
    // records:
    //
    // rhH[28]      <-- all 28 bytes of first message
    // rhH[4]hH[16] <-- 4 bytes of second message plus 16 bytes of third message
    let messages = [vec![6u8; 28], vec![7; 4], vec![8; 16]];
    let record_lens = [
        28 + DTLS_HANDSHAKE_HEADER_SIZE,
        4 + DTLS_HANDSHAKE_HEADER_SIZE + 16 + DTLS_HANDSHAKE_HEADER_SIZE,
    ];
    let message_flight: Vec<_> = messages
        .iter()
        .map(|m| {
            (
                HandshakeType::Finished,
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = MessageFragmenter::default();
    fragmenter
        .set_max_fragment_size(Some(
            32 + if version == ProtocolVersion::DTLSv1_2 {
                DTLS_12_HEADER_SIZE
            } else {
                UnifiedHeader::header_length(101)
            } + DTLS_HANDSHAKE_HEADER_SIZE,
        ))
        .unwrap();

    let records = fragmenter.fragment_dtls_handshake_message_flight(
        version,
        EpochAndSequence::new(11, 255),
        17,
        &message_flight,
    );
    assert_eq!(records.len(), 2);

    let mut handshake_fragments = Vec::new();

    for (record, expected_record_len) in records.iter().zip(record_lens) {
        assert_eq!(record.typ, ContentType::Handshake);
        assert_eq!(record.version, version);
        assert_eq!(record.payload.bytes().len(), expected_record_len);

        let mut reader = Reader::new(record.payload.bytes());
        while reader.any_left() {
            handshake_fragments.push(DtlsHandshakeFragment::read(&mut reader).unwrap());
        }
    }

    let expected_fragments = [
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(28),
            message_seq: 17,
            fragment_offset: U24(0),
            fragment_length: U24(28),
            fragment: Payload::new([6; 28]),
        },
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(4),
            message_seq: 18,
            fragment_offset: U24(0),
            fragment_length: U24(4),
            fragment: Payload::new([7; 4]),
        },
        DtlsHandshakeFragment {
            msg_type: HandshakeType::Finished,
            length: U24(16),
            message_seq: 19,
            fragment_offset: U24(0),
            fragment_length: U24(16),
            fragment: Payload::new([8; 16]),
        },
    ];
    assert_eq!(handshake_fragments.len(), expected_fragments.len());

    for (idx, (handshake_fragment, expected_fragment)) in handshake_fragments
        .iter()
        .zip(expected_fragments)
        .enumerate()
    {
        check_handshake_fragment(idx, handshake_fragment, &expected_fragment);
    }
}

#[test]
fn flight_partially_filled_record_dtls_12() {
    flight_partially_filled_record(ProtocolVersion::DTLSv1_2);
}

#[test]
fn flight_partially_filled_record_dtls_13() {
    flight_partially_filled_record(ProtocolVersion::DTLSv1_3);
}
