use crate::EpochAndSequence;
use crate::crypto::CipherSuite;
use crate::crypto::cipher::EncodingContext;
use crate::enums::HandshakeType;
use crate::msgs::{
    ClientExtensions, ClientHelloPayload, Codec, Compression, DTLS_12_HEADER_SIZE,
    DTLS_HANDSHAKE_HEADER_EXTRA, DTLS_HANDSHAKE_HEADER_SIZE, HANDSHAKE_HEADER_SIZE,
    HandshakeMessagePayload, HandshakePayload, Message, MessageFragmenter, MessagePayload, Payload,
    Random, ServerNamePayload, SessionId,
};

use pki_types::DnsName;

use super::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

fn test_handshake_message<'a>(version: ProtocolVersion) -> Message<'a> {
    Message {
        version: version,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ClientHelloPayload {
                client_version: version,
                random: Random::from([1; 32]),
                session_id: SessionId::from([2; 32]),
                cipher_suites: vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: Box::new(ClientExtensions {
                    server_name: Some(ServerNamePayload::from(
                        &DnsName::try_from("hello").unwrap(),
                    )),
                    ..Default::default()
                }),
            },
        ))),
    }
}

fn check_reassembled_message(
    idx: usize,
    original_message: &EncodedMessage<Payload<'_>>,
    reassembled_message: &EncodedMessage<&[u8]>,
    encrypted_dtls13: bool,
) {
    assert_eq!(reassembled_message.typ, original_message.typ, "idx: {idx}");
    // Encrypted DTLS 1.3 messages will have a unified header on the wire and
    // will be interpreted as having ProtocolVersion::DTLSv1_3. For other
    // messages, regardless of the original message's protocol version, the
    // message on the wire will have version 1.2.
    assert_eq!(
        reassembled_message.version,
        if encrypted_dtls13 {
            ProtocolVersion::DTLSv1_3
        } else {
            ProtocolVersion::DTLSv1_2
        },
        "idx: {idx}"
    );
    assert_eq!(
        reassembled_message.payload.len(),
        original_message.payload.bytes().len() + DTLS_HANDSHAKE_HEADER_EXTRA,
        "idx: {idx}",
    );
    // The record we encoded had a TLS handshake header on it, but the one we get back has a *DTLS*
    // handshake header. Check that the payloads are equal.
    assert_eq!(
        &original_message.payload.bytes()[HANDSHAKE_HEADER_SIZE..],
        &reassembled_message.payload[DTLS_HANDSHAKE_HEADER_SIZE..],
        "idx: {idx}",
    );

    // Make sure we can parse the handshake message, but we already checked that the bytes are as
    // expected so no need to examine the fields of the message.
    Message::try_from(reassembled_message.clone()).unwrap();
}

fn single_handshake_fragment(version: ProtocolVersion, encrypted: bool) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 || !encrypted {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    let record = EncodedMessage::from(test_handshake_message(version));

    let records: Vec<_> = MessageFragmenter::default()
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(0, 0),
            HandshakeType::ClientHello,
            0,
            record.payload.bytes(),
        )
        .collect();
    assert_eq!(records.len(), 1);

    let mut record_wire_bytes = EncodedMessage {
        typ: records[0].typ,
        version: records[0].version,
        payload: records[0]
            .payload
            .get_encoding()
            .as_slice()
            .into(),
    }
    .to_unencrypted_opaque(EncodingContext {
        payload_is_encrypted: encrypted,
        epoch_and_sequence: Some(EpochAndSequence::new(0, 0)),
        ..Default::default()
    })
    .encode();
    let record_wire_bytes_len = record_wire_bytes.len();

    // Deframe the record to parse its header and get the body as an InboundOpaque
    let mut deframer = Deframer::default();

    let Deframed {
        message,
        bounds,
        epoch_and_sequence,
    } = deframer
        .deframe(&mut record_wire_bytes)
        .unwrap()
        .unwrap();

    // The bounds of the deframed message should span the entire encoded message
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, record_wire_bytes_len);

    assert_eq!(epoch_and_sequence, Some(EpochAndSequence::new(0, 0)));

    // Simulate decryption
    let mut message = message.into_plain_message();
    message.typ = ContentType::Handshake;
    let bounds = bounds.start + header_size..bounds.end;

    // Feed the record payload into the deframer. It should be a complete span.
    deframer
        .input_message_dtls(message, bounds)
        .unwrap();

    // Coalescing should be a no-op with only one span
    deframer.coalesce_dtls(&mut record_wire_bytes);
    let message_span = deframer.complete_span().unwrap();

    // We should get the whole handshake message out of the deframer
    let reassembled_message = deframer.message(message_span, &record_wire_bytes);
    check_reassembled_message(
        0,
        &record,
        &reassembled_message,
        encrypted && version == ProtocolVersion::DTLSv1_3,
    );
}

#[test]
fn single_handshake_fragment_dtls_12_unencrypted() {
    single_handshake_fragment(ProtocolVersion::DTLSv1_2, false);
}

#[test]
fn single_handshake_fragment_dtls_12_encrypted() {
    single_handshake_fragment(ProtocolVersion::DTLSv1_2, true);
}

#[test]
fn single_handshake_fragment_dtls_13_unencrypted() {
    // Sending unencrypted handshake messages means no unified header
    single_handshake_fragment(ProtocolVersion::DTLSv1_3, false);
}

#[test]
fn single_handshake_fragment_dtls_13_encrypted() {
    // Encrypted handshake messages means a unified header
    single_handshake_fragment(ProtocolVersion::DTLSv1_3, true);
}

fn multiple_handshake_fragment_in_order(
    version: ProtocolVersion,
    start_epoch: u16,
    start_sequence: u64,
    encrypted: bool,
) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 || !encrypted {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(start_sequence)
    };
    let record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(32 + header_size + DTLS_HANDSHAKE_HEADER_SIZE))
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(start_epoch, start_sequence),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(records.len(), 3);

    let mut encoded_records = Vec::new();

    for (seq, record) in records.iter().enumerate() {
        encoded_records.extend_from_slice(
            EncodedMessage {
                typ: record.typ,
                version: record.version,
                payload: record
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_opaque(EncodingContext {
                payload_is_encrypted: encrypted,
                epoch_and_sequence: Some(EpochAndSequence::new(
                    start_epoch,
                    start_sequence + seq as u64,
                )),
                ..Default::default()
            })
            .encode()
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();
    deframer.set_epoch(start_epoch);
    deframer.set_sequence(start_sequence);

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all records are fed in.
    for record_idx in 0..records.len() {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut encoded_records)
            .unwrap()
            .unwrap();

        // For DTLS 1.3, the unified header carries only the truncated epoch and sequence so check
        // that we reassembled them properly.
        assert_eq!(
            epoch_and_sequence,
            Some(EpochAndSequence::new(
                start_epoch,
                start_sequence + record_idx as u64
            )),
            "{record_idx}"
        );

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let bounds = bounds.start + header_size..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_records);

        if record_idx < records.len() - 1 {
            assert!(deframer.complete_span().is_none());
        } else {
            let message_span = deframer.complete_span().unwrap();

            // We should get the whole handshake message out of the deframer
            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_message(
                record_idx,
                &record,
                &reassembled_handshake_message,
                version == ProtocolVersion::DTLSv1_3 && encrypted,
            );
        }
    }
}

#[test]
fn multiple_handshake_fragment_in_order_unencrypted_dtls_12() {
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_2, 3, 11, false);
}

#[test]
fn multiple_handshake_fragment_in_order_encrypted_dtls_12() {
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_2, 3, 11, true);
}

#[test]
fn multiple_handshake_fragment_in_order_unencrypted_dtls_13() {
    // Send an unencrypted handshake message, as would be the case for a ClientHello, so that a full
    // DTLS record header is written and not a unified header
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_3, 3, 11, false);
}

#[test]
fn multiple_handshake_fragment_in_order_encrypted_dtls_13() {
    // Send an encrypted handshake message, as would be the case once keys are negotiated, so that a
    // unified header is written
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_3, 3, 11, true);
}

#[test]
fn multiple_handshake_fragment_in_order_large_epoch_and_sequence_dtls_12() {
    // Use epoch and sequence values too large to fit in 2 or 16 bits, respectively. This shouldn't
    // make a difference in DTLS 1.2
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_2, 11, 70000, false);
}

#[test]
fn multiple_handshake_fragment_in_order_large_epoch_and_sequence_dtls_13() {
    // Use epoch and sequence values too large to fit in 2 or 16 bits, respectively. This makes the
    // values too big to fit into their respective fields in the DTLS 1.3 unified header, forcing
    // "Reconstructing the Sequence Number and Epoch".
    // <https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.2>
    multiple_handshake_fragment_in_order(ProtocolVersion::DTLSv1_3, 11, 70000, false);
}

fn multiple_handshake_fragment_overlapping(version: ProtocolVersion) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    let record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(24 + header_size + DTLS_HANDSHAKE_HEADER_SIZE))
        .unwrap();
    let mut records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(records.len(), 4);

    // Grow one of the fragments so that it overlaps with part of the fragment before it and then
    // all of the fragment after it.
    let fragment_0_portion = 11;
    assert!(
        fragment_0_portion as usize
            <= records[0]
                .payload
                .fragment
                .bytes()
                .len()
    );
    let fragment_2_portion = records[2].payload.fragment_length.0;
    records[1].payload.fragment_length =
        U24(records[1].payload.fragment_length.0 + fragment_0_portion + fragment_2_portion);
    records[1].payload.fragment_offset =
        U24(records[1].payload.fragment_offset.0 - fragment_0_portion);
    let mut grown_payload = records[0]
        .payload
        .fragment
        .bytes()
        .last_chunk::<11>()
        .unwrap()
        .to_vec();
    grown_payload.extend(records[1].payload.fragment.bytes());
    grown_payload.extend(records[2].payload.fragment.bytes());
    records[1].payload.fragment = Payload::new(grown_payload);

    let mut encoded_records = Vec::new();

    for record in &records {
        encoded_records.extend_from_slice(
            EncodedMessage {
                typ: record.typ,
                version: record.version,
                payload: record
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_opaque(EncodingContext {
                payload_is_encrypted: true,
                epoch_and_sequence: Some(EpochAndSequence::new(5, 222)),
                ..Default::default()
            })
            .encode()
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();
    deframer.set_epoch(5);

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all records are fed in.
    for record_idx in 0..records.len() {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut encoded_records)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let bounds = bounds.start + header_size..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_records);

        if record_idx < records.len() - 1 {
            assert!(
                deframer.complete_span().is_none(),
                "record_idx {record_idx}"
            );
        } else {
            let message_span = deframer.complete_span().unwrap();

            // We should get the whole handshake message out of the deframer
            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_message(
                record_idx,
                &record,
                &reassembled_handshake_message,
                version == ProtocolVersion::DTLSv1_3,
            );
        }
    }
}

#[test]
fn multiple_handshake_fragment_overlapping_dtls_12() {
    multiple_handshake_fragment_overlapping(ProtocolVersion::DTLSv1_2);
}

#[test]
fn multiple_handshake_fragment_overlapping_dtls_13() {
    multiple_handshake_fragment_overlapping(ProtocolVersion::DTLSv1_3);
}

fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1(version: ProtocolVersion) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    let first_record = EncodedMessage::from(test_handshake_message(version));
    let second_record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(24 + header_size + DTLS_HANDSHAKE_HEADER_SIZE))
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            666, // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(5, 223),
            HandshakeType::ClientHello,
            667, // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(records.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. Even though we receive all the fragments of the second message at index 5, we can't
    // get any messages out of the deframer until all fragments of the first message arrive.
    let mut encoded_records = Vec::new();
    for index in [4, 2, 7, 3, 6, 5, 1, 0] {
        encoded_records.extend_from_slice(
            EncodedMessage {
                typ: records[index].typ,
                version: records[index].version,
                payload: records[index]
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_opaque(EncodingContext {
                payload_is_encrypted: true,
                epoch_and_sequence: Some(EpochAndSequence::new(5, 222)),
                ..Default::default()
            })
            .encode()
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();
    deframer.set_epoch(5);

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    for record_idx in 0..records.len() {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut encoded_records)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let bounds = bounds.start + header_size..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_records);

        if let Some(span) = deframer.complete_span() {
            // Because of how we laid out encoded_fragments, no message will be available until the
            // last iteration of this loop, at which point both will be in the buffer, ordered by
            // handshake seq.
            let reassembled_handshake_message = deframer.message(span, &encoded_records);
            check_reassembled_message(
                record_idx,
                &first_record,
                &reassembled_handshake_message,
                version == ProtocolVersion::DTLSv1_3,
            );

            saw_first_message = true;

            let span = deframer.complete_span().unwrap();
            let reassembled_handshake_message = deframer.message(span, &encoded_records);
            check_reassembled_message(
                record_idx,
                &second_record,
                &reassembled_handshake_message,
                version == ProtocolVersion::DTLSv1_3,
            );
        }
    }

    assert!(saw_first_message);
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1_dtls_12() {
    multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1(ProtocolVersion::DTLSv1_2);
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1_dtls_13() {
    multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1(ProtocolVersion::DTLSv1_3);
}

fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2(version: ProtocolVersion) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    let first_record = EncodedMessage::from(test_handshake_message(version));
    let second_record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(24 + header_size + DTLS_HANDSHAKE_HEADER_SIZE))
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            666, // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            version,
            EpochAndSequence::new(5, 223),
            HandshakeType::ClientHello,
            667, // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(records.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. We receive all fragments of the first message at index 5, so the deframer should
    // yield that message then, but the second message has to wait until all 8 fragments arrive.
    let mut encoded_records = Vec::new();
    for index in [4, 2, 7, 3, 1, 0, 6, 5] {
        encoded_records.extend_from_slice(
            EncodedMessage {
                typ: records[index].typ,
                version: records[index].version,
                payload: records[index]
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_opaque(EncodingContext {
                payload_is_encrypted: true,
                epoch_and_sequence: Some(EpochAndSequence::new(5, 222)),
                ..Default::default()
            })
            .encode()
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();
    deframer.set_epoch(5);

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    let mut saw_second_message = false;
    for record_idx in 0..records.len() {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut encoded_records)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let bounds = bounds.start + header_size..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_records);

        if let Some(span) = deframer.complete_span() {
            let reassembled_handshake_message = deframer.message(span, &encoded_records);
            if !saw_first_message {
                check_reassembled_message(
                    record_idx,
                    &first_record,
                    &reassembled_handshake_message,
                    version == ProtocolVersion::DTLSv1_3,
                );
                saw_first_message = true;
            } else {
                check_reassembled_message(
                    record_idx,
                    &second_record,
                    &reassembled_handshake_message,
                    version == ProtocolVersion::DTLSv1_3,
                );
                saw_second_message = true;
            }
        }
    }

    assert!(saw_first_message);
    assert!(saw_second_message);
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2_dtls_12() {
    multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2(ProtocolVersion::DTLSv1_2);
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2_dtls_13() {
    multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2(ProtocolVersion::DTLSv1_3);
}

fn check_reassembled_handshake(
    record_idx: usize,
    version: ProtocolVersion,
    original_message: &[u8],
    reassembled_message: &EncodedMessage<&[u8]>,
) {
    assert_eq!(
        reassembled_message.typ,
        ContentType::Handshake,
        "record_idx: {record_idx}",
    );
    assert_eq!(
        reassembled_message.version, version,
        "record_idx: {record_idx}",
    );
    assert_eq!(
        &reassembled_message.payload[DTLS_HANDSHAKE_HEADER_SIZE..],
        original_message,
        "record_idx: {record_idx}",
    );
}

fn single_record_multiple_handshake_messages(version: ProtocolVersion) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    // "Note that as with TLS, multiple handshake messages may be placed in the same DTLS record,
    // provided that there is room and that they are part of the same flight."
    // https://datatracker.ietf.org/doc/html/rfc9147#section-5.5-5
    // Message lengths and fragment size are chosen so that multiple complete handshake messages get
    // packed into a single record.
    // Where r indicates 13 bytes of record header, h indicates 12 bytes of handshake header and
    // H[x] indicates x bytes of handshake payload, we will get a record:
    //
    // rhH[36]hH[32]hH[4]
    let messages = [vec![6u8; 36], vec![7; 32], vec![8; 4]];
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
            36 + 32 + 4 + header_size + 3 * DTLS_HANDSHAKE_HEADER_SIZE,
        ))
        .unwrap();

    let records = fragmenter.fragment_dtls_handshake_message_flight(
        version,
        EpochAndSequence::new(11, 255),
        17,
        &message_flight,
    );
    assert_eq!(records.len(), 1);

    let mut encoded_record = EncodedMessage {
        typ: records[0].typ,
        version: records[0].version,
        payload: records[0]
            .payload
            .get_encoding()
            .as_slice()
            .into(),
    }
    .to_unencrypted_opaque(EncodingContext {
        payload_is_encrypted: true,
        epoch_and_sequence: Some(EpochAndSequence::new(11, 255)),
        ..Default::default()
    })
    .encode();

    let mut deframer = Deframer::default();
    deframer.set_epoch(11);

    // Deframe the record and feed it into the deframer to be coalesced.
    let Deframed {
        message,
        bounds,
        epoch_and_sequence,
    } = deframer
        .deframe(&mut encoded_record)
        .unwrap()
        .unwrap();

    // Simulate in-place decryption
    let mut message = message.into_plain_message();
    message.typ = ContentType::Handshake;
    let bounds = bounds.start + header_size..bounds.end;

    deframer
        .input_message_dtls(message, bounds)
        .unwrap();
    deframer.coalesce_dtls(&mut encoded_record);

    // The first and only record contains three complete handshake messages which should now be
    // available.
    for message in messages {
        let message_span = deframer.complete_span().unwrap();

        let reassembled_handshake_message = deframer.message(message_span, &encoded_record);
        check_reassembled_handshake(
            1,
            version,
            message.as_slice(),
            &reassembled_handshake_message,
        );
    }

    // No more messages
    assert!(deframer.complete_span().is_none());
}

#[test]
fn single_record_multiple_handshake_messages_dtls_12() {
    single_record_multiple_handshake_messages(ProtocolVersion::DTLSv1_2);
}

#[test]
fn single_record_multiple_handshake_messages_dtls_13() {
    single_record_multiple_handshake_messages(ProtocolVersion::DTLSv1_3);
}

fn handshake_messages_span_records(version: ProtocolVersion) {
    let header_size = if version == ProtocolVersion::DTLSv1_2 {
        DTLS_12_HEADER_SIZE
    } else {
        UnifiedHeader::header_length(0)
    };
    // "Note that as with TLS, multiple handshake messages may be placed in the same DTLS record,
    // provided that there is room and that they are part of the same flight."
    // https://datatracker.ietf.org/doc/html/rfc9147#section-5.5-5
    // Message lengths are chosen so that the first occupies the entire first record and part of
    // the second, and the second occupies part of the second record and part of the third, and then
    // the third message occupies the remainder of the third record.
    // Where r indicates 13 bytes of record header, h indicates 12 bytes of handshake header and
    // H[x] indicates x bytes of handshake payload, we will get records:
    //
    // rhH[32]      <-- first 32 bytes of first message
    // rhH[4]hH[16] <-- last 4 bytes of first message plus first 16 bytes of second message
    // rhH[16]hH[4] <-- last 16 bytes of second message plus 14 bytes of third message
    let messages = [vec![6u8; 36], vec![7; 32], vec![8; 4]];
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
        .set_max_fragment_size(Some(32 + header_size + DTLS_HANDSHAKE_HEADER_SIZE))
        .unwrap();

    let records = fragmenter.fragment_dtls_handshake_message_flight(
        version,
        // It's important that the sequence number be 255 here: we want the sequence number to be
        // big enough to require 2 bytes to be encoded in the unfiied header.
        EpochAndSequence::new(11, 255),
        17,
        &message_flight,
    );
    assert_eq!(records.len(), 3);

    let mut encoded_records = Vec::new();

    for record in &records {
        let encoded_record = EncodedMessage {
            typ: record.typ,
            version: record.version,
            payload: record
                .payload
                .get_encoding()
                .as_slice()
                .into(),
        }
        .to_unencrypted_opaque(EncodingContext {
            payload_is_encrypted: true,
            epoch_and_sequence: Some(EpochAndSequence::new(11, 255)),
            ..Default::default()
        })
        .encode();
        encoded_records.extend_from_slice(&encoded_record.as_slice());
    }

    let mut deframer = Deframer::default();
    deframer.set_epoch(11);

    // Deframe records and feed messages into the deframer to be coalesced.
    for record_idx in 0..records.len() {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut encoded_records)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let header_size = if version == ProtocolVersion::DTLSv1_2 {
            DTLS_12_HEADER_SIZE
        } else {
            UnifiedHeader::header_length(
                epoch_and_sequence
                    .unwrap()
                    .sequence_number
                    .0,
            )
        };
        let bounds = bounds.start + header_size..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_records);

        if record_idx == 0 {
            // First record contains incomplete handshake message
            assert!(deframer.complete_span().is_none());
        } else if record_idx == 1 {
            // Second record contains rest of first message and part of second; one complete span
            // should be available
            let message_span = deframer.complete_span().unwrap();

            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_handshake(
                record_idx,
                version,
                messages[0].as_slice(),
                &reassembled_handshake_message,
            );

            assert!(deframer.complete_span().is_none());
        } else if record_idx == 2 {
            // Third record contains rest of second message and entire third message; two complete
            // spans should be available
            let message_span = deframer.complete_span().unwrap();

            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_handshake(
                record_idx,
                version,
                messages[1].as_slice(),
                &reassembled_handshake_message,
            );

            let message_span = deframer.complete_span().unwrap();

            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_handshake(
                record_idx,
                version,
                messages[2].as_slice(),
                &reassembled_handshake_message,
            );
        } else {
            panic!("record_idx > 2");
        }
    }
}

#[test]
fn handshake_messages_span_records_dtls_12() {
    handshake_messages_span_records(ProtocolVersion::DTLSv1_2);
}

#[test]
fn handshake_messages_span_records_dtls_13() {
    handshake_messages_span_records(ProtocolVersion::DTLSv1_3);
}

fn multiple_fragments_application_data(version: ProtocolVersion) {
    let first_record = EncodedMessage::from(Message {
        version: version,
        payload: MessagePayload::new(ContentType::ApplicationData, version, &[1; 32]).unwrap(),
    })
    .into_unencrypted_opaque(EncodingContext {
        payload_is_encrypted: true,
        epoch_and_sequence: Some(EpochAndSequence::new(3, 11)),
        ..Default::default()
    });

    let encoded_first_record = first_record.clone().encode();
    let encoded_first_record_len = encoded_first_record.len();

    let second_record = EncodedMessage::from(Message {
        version: version,
        payload: MessagePayload::new(ContentType::ApplicationData, version, &[4; 92]).unwrap(),
    })
    .into_unencrypted_opaque(EncodingContext {
        payload_is_encrypted: true,
        epoch_and_sequence: Some(EpochAndSequence::new(3, 12)),
        ..Default::default()
    });

    let encoded_second_record = second_record.clone().encode();
    let encoded_second_record_len = encoded_second_record.len();

    let mut wire_bytes = Vec::new();
    wire_bytes.extend(encoded_first_record);
    wire_bytes.extend(encoded_second_record);

    let mut deframer = Deframer::default();
    deframer.set_epoch(3);

    for (record, expect_start, expect_end, expect_epoch_and_sequence) in [
        (
            first_record,
            0,
            encoded_first_record_len,
            Some(EpochAndSequence::new(3, 11)),
        ),
        (
            second_record,
            encoded_first_record_len,
            encoded_first_record_len + encoded_second_record_len,
            Some(EpochAndSequence::new(3, 12)),
        ),
    ] {
        let Deframed {
            message,
            bounds,
            epoch_and_sequence,
        } = deframer
            .deframe(&mut wire_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(bounds.start, expect_start);
        assert_eq!(bounds.end, expect_end);

        let mut message = message.into_plain_message();
        if message.typ == ContentType::Dtls13Ciphertext {
            message.typ = ContentType::ApplicationData;
        }
        assert_eq!(message.typ, record.typ);
        assert_eq!(message.version, version);
        assert_eq!(epoch_and_sequence, expect_epoch_and_sequence);
        assert_eq!(message.payload, record.payload.as_ref());
    }
}

#[test]
fn multiple_fragments_application_data_dtls_12() {
    multiple_fragments_application_data(ProtocolVersion::DTLSv1_2);
}

#[test]
fn multiple_fragments_application_data_dtls_13() {
    multiple_fragments_application_data(ProtocolVersion::DTLSv1_3);
}
