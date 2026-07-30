use crate::common_state::Protocol;
use crate::crypto::CipherSuite;
use crate::crypto::cipher::{EncodableVersion, EncodingContext};
use crate::enums::HandshakeType;
use crate::msgs::{
    ClientExtensions, ClientHelloPayload, Codec, Compression, DTLS_HANDSHAKE_HEADER_EXTRA,
    DTLS_HANDSHAKE_HEADER_SIZE, Fragmenter, HANDSHAKE_HEADER_SIZE, HandshakeMessagePayload,
    HandshakePayload, Message, MessagePayload, Payload, Random, ServerNamePayload, SessionId,
};

use pki_types::DnsName;

use super::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

fn test_handshake_message<'a>(version: ProtocolVersion) -> Message<'a> {
    Message {
        version: EncodableVersion::Legacy(version),
        payload: MessagePayload::handshake(
            HandshakeMessagePayload(HandshakePayload::ClientHello(ClientHelloPayload {
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
            })),
            0.into(),
        ),
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
        reassembled_message.version.version(),
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
    let header_size = if encrypted {
        version.encrypted_header_len()
    } else {
        version.unencrypted_header_len()
    };
    let record = EncodedMessage::from(test_handshake_message(version));

    let records: Vec<_> = Fragmenter::default()
        .fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            0.into(),
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
    .to_unencrypted_bytes(EncodingContext {
        payload_is_encrypted: encrypted,
        epoch: Epoch::Unencrypted,
        record_seq: 6,
    });
    let record_wire_bytes_len = record_wire_bytes.len();

    // Deframe the record to parse its header and get the body as an InboundOpaque
    let mut deframer = Deframer::default();

    let Deframed {
        message,
        bounds,
        epoch,
        record_seq,
    } = deframer
        .deframe(&mut record_wire_bytes, Epoch::Unencrypted, 5)
        .unwrap()
        .unwrap();

    // The bounds of the deframed message should span the entire encoded message
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, record_wire_bytes_len);

    assert_eq!(epoch, Epoch::Unencrypted);
    assert_eq!(record_seq, 6);

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
    start_epoch: Epoch,
    start_seq: u64,
    encrypted: bool,
) {
    let header_size = if encrypted {
        version.encrypted_header_len()
    } else {
        version.unencrypted_header_len()
    };
    let record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = Fragmenter::default();
    message_fragmenter
        .set_max_fragment_size(
            Some(32 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            0.into(),
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
            .to_unencrypted_bytes(EncodingContext {
                payload_is_encrypted: encrypted,
                epoch: start_epoch,
                record_seq: start_seq + seq as u64,
            })
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all records are fed in.
    for record_idx in 0..records.len() {
        std::println!("record {record_idx}");
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(&mut encoded_records, start_epoch, start_seq)
            .unwrap()
            .unwrap();

        // For DTLS 1.3, the unified header carries only the truncated epoch and sequence so check
        // that we reassembled them properly.
        assert_eq!(epoch, start_epoch);
        assert_eq!(record_seq, start_seq + record_idx as u64);

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
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_2,
        Epoch::ApplicationData(3),
        11,
        false,
    );
}

#[test]
fn multiple_handshake_fragment_in_order_encrypted_dtls_12() {
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_2,
        Epoch::ApplicationData(3),
        11,
        true,
    );
}

#[test]
fn multiple_handshake_fragment_in_order_unencrypted_dtls_13() {
    // Send an unencrypted handshake message, as would be the case for a ClientHello, so that a full
    // DTLS record header is written and not a unified header
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_3,
        Epoch::ApplicationData(3),
        11,
        false,
    );
}

#[test]
fn multiple_handshake_fragment_in_order_encrypted_dtls_13() {
    // Send an encrypted handshake message, as would be the case once keys are negotiated, so that a
    // unified header is written
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_3,
        Epoch::ApplicationData(3),
        11,
        true,
    );
}

#[test]
fn multiple_handshake_fragment_in_order_large_epoch_and_sequence_dtls_12() {
    // Use epoch and sequence values too large to fit in 2 or 16 bits, respectively. This shouldn't
    // make a difference in DTLS 1.2
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_2,
        Epoch::ApplicationData(11),
        70000,
        false,
    );
}

#[test]
fn multiple_handshake_fragment_in_order_large_epoch_and_sequence_dtls_13() {
    // Use epoch and sequence values too large to fit in 2 or 16 bits, respectively. This makes the
    // values too big to fit into their respective fields in the DTLS 1.3 unified header, forcing
    // "Reconstructing the Sequence Number and Epoch".
    // <https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.2>
    multiple_handshake_fragment_in_order(
        ProtocolVersion::DTLSv1_3,
        Epoch::ApplicationData(11),
        70000,
        false,
    );
}

fn multiple_handshake_fragment_overlapping(version: ProtocolVersion) {
    let header_size = version.encrypted_header_len();
    let record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = Fragmenter::default();
    message_fragmenter
        .set_max_fragment_size(
            Some(24 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();
    let mut records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            0.into(),
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

    for (idx, record) in records.iter().enumerate() {
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
            .to_unencrypted_bytes(EncodingContext {
                payload_is_encrypted: true,
                epoch: Epoch::ApplicationData(5),
                record_seq: 222 + idx as u64,
            })
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all records are fed in.
    for record_idx in 0..records.len() {
        std::println!("record_idx {record_idx}");
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(
                &mut encoded_records,
                Epoch::ApplicationData(5),
                221 + record_idx as u64,
            )
            .unwrap()
            .unwrap();

        assert_eq!(epoch, Epoch::ApplicationData(5));
        assert_eq!(record_seq, 222 + record_idx as u64);

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
    let header_size = version.encrypted_header_len();
    let first_record = EncodedMessage::from(test_handshake_message(version));
    let second_record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = Fragmenter::default();
    message_fragmenter
        .set_max_fragment_size(
            Some(24 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            666.into(), // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            667.into(), // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(records.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. Even though we receive all the fragments of the second message at index 5, we can't
    // get any messages out of the deframer until all fragments of the first message arrive.
    let records_order = [4, 2, 7, 3, 6, 5, 1, 0];
    let mut encoded_records = Vec::new();
    for index in records_order {
        encoded_records.extend_from_slice(
            &EncodedMessage {
                typ: records[index].typ,
                version: records[index].version,
                payload: records[index]
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_bytes(EncodingContext {
                payload_is_encrypted: true,
                epoch: Epoch::ApplicationData(5),
                record_seq: 222 + index as u64,
            })
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    let mut highest_observed_seq = 0;
    for record_idx in 0..records.len() {
        std::println!("record_idx {record_idx}");
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(
                &mut encoded_records,
                Epoch::ApplicationData(5),
                highest_observed_seq,
            )
            .unwrap()
            .unwrap();

        assert_eq!(epoch, Epoch::ApplicationData(5));
        assert_eq!(record_seq, 222 + records_order[record_idx] as u64);

        if record_seq > highest_observed_seq {
            highest_observed_seq = record_seq;
        }

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
    let header_size = version.encrypted_header_len();
    let first_record = EncodedMessage::from(test_handshake_message(version));
    let second_record = EncodedMessage::from(test_handshake_message(version));

    let mut message_fragmenter = Fragmenter::default();
    message_fragmenter
        .set_max_fragment_size(
            Some(24 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();
    let records: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            666.into(), // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            EncodableVersion::Legacy(version),
            HandshakeType::ClientHello,
            667.into(), // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(records.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. We receive all fragments of the first message at index 5, so the deframer should
    // yield that message then, but the second message has to wait until all 8 fragments arrive.
    let mut encoded_records = Vec::new();
    let records_order = [4, 2, 7, 3, 1, 0, 6, 5];
    for index in records_order {
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
            .to_unencrypted_bytes(EncodingContext {
                payload_is_encrypted: true,
                epoch: Epoch::ApplicationData(5),
                record_seq: 222 + index as u64,
            })
            .as_slice(),
        );
    }

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    let mut saw_second_message = false;
    let mut highest_observed_seq = 0;
    for record_idx in 0..records.len() {
        std::println!("record_idx {record_idx}");
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(
                &mut encoded_records,
                Epoch::ApplicationData(5),
                221 + record_idx as u64,
            )
            .unwrap()
            .unwrap();

        assert_eq!(epoch, Epoch::ApplicationData(5));
        assert_eq!(record_seq, 222 + records_order[record_idx] as u64);

        if record_seq > highest_observed_seq {
            highest_observed_seq = record_seq;
        }

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
        reassembled_message.version.version(),
        version,
        "record_idx: {record_idx}",
    );
    assert_eq!(
        &reassembled_message.payload[DTLS_HANDSHAKE_HEADER_SIZE..],
        original_message,
        "record_idx: {record_idx}",
    );
}

fn single_record_multiple_handshake_messages(version: ProtocolVersion) {
    let header_size = version.encrypted_header_len();
    // "Note that as with TLS, multiple handshake messages may be placed in the same DTLS record,
    // provided that there is room and that they are part of the same flight."
    // https://datatracker.ietf.org/doc/html/rfc9147#section-5.5-5
    // Message lengths and fragment size are chosen so that multiple complete handshake messages get
    // packed into a single record.
    // Where r indicates 13 bytes of record header, h indicates 12 bytes of handshake header and
    // H[x] indicates x bytes of handshake payload, we will get a record:
    //
    // rhH[36]hH[32]hH[4]
    let messages = [(vec![6u8; 36], 17), (vec![7; 32], 18), (vec![8; 4], 19)];
    let message_flight: Vec<_> = messages
        .iter()
        .map(|(m, handshake_seq)| {
            (
                HandshakeType::Finished,
                (*handshake_seq).into(),
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = Fragmenter::default();
    fragmenter
        .set_max_fragment_size(
            Some(36 + 32 + 4 + DTLS_12_HEADER_SIZE + 3 * DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();

    let records = fragmenter
        .fragment_dtls_handshake_message_flight(EncodableVersion::Legacy(version), &message_flight);
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
    .to_unencrypted_bytes(EncodingContext {
        payload_is_encrypted: true,
        epoch: Epoch::ApplicationData(11),
        record_seq: 255,
    });

    let mut deframer = Deframer::default();

    // Deframe the record and feed it into the deframer to be coalesced.
    let Deframed {
        message,
        bounds,
        epoch,
        record_seq,
    } = deframer
        .deframe(&mut encoded_record, Epoch::ApplicationData(11), 254)
        .unwrap()
        .unwrap();

    assert_eq!(epoch, Epoch::ApplicationData(11));
    assert_eq!(record_seq, 255);

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
    for (message, expected_handshake_seq) in messages {
        let message_span = deframer.complete_span().unwrap();
        let (handshake_seq, fragment_offset, fragment_len) = message_span
            .dtls_fragment_fields
            .unwrap();

        assert_eq!(handshake_seq, expected_handshake_seq.into());
        assert_eq!(fragment_offset, U24(0));

        let reassembled_handshake_message = deframer.message(message_span, &encoded_record);
        assert_eq!(
            usize::from(fragment_len) + DTLS_HANDSHAKE_HEADER_SIZE,
            reassembled_handshake_message
                .payload
                .len()
        );
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
    let messages = [(vec![6u8; 36], 17), (vec![7; 32], 18), (vec![8; 4], 19)];
    let message_flight: Vec<_> = messages
        .iter()
        .map(|(m, seq)| {
            (
                HandshakeType::Finished,
                (*seq).into(),
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = Fragmenter::default();
    fragmenter
        .set_max_fragment_size(
            Some(32 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();

    let records = fragmenter
        .fragment_dtls_handshake_message_flight(EncodableVersion::Legacy(version), &message_flight);
    assert_eq!(records.len(), 3);

    let mut encoded_records = Vec::new();

    for (idx, record) in records.iter().enumerate() {
        let encoded_record = EncodedMessage {
            typ: record.typ,
            version: record.version,
            payload: record
                .payload
                .get_encoding()
                .as_slice()
                .into(),
        }
        .to_unencrypted_bytes(EncodingContext {
            payload_is_encrypted: true,
            epoch: Epoch::ApplicationData(11),
            // It's important that the sequence number be 255 or more here: we want the sequence
            // number to be big enough to require 2 bytes to be encoded in the unified header.
            record_seq: 255 + idx as u64,
        });
        encoded_records.extend_from_slice(&encoded_record.as_slice());
    }

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced.
    for record_idx in 0..records.len() {
        std::println!("record_idx {record_idx}");
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(
                &mut encoded_records,
                Epoch::ApplicationData(11),
                254 + record_idx as u64,
            )
            .unwrap()
            .unwrap();

        assert_eq!(epoch, Epoch::ApplicationData(11));
        assert_eq!(record_seq, 255 + record_idx as u64);

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = ContentType::Handshake;
        let header_size = version.encrypted_header_len();
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
                messages[0].0.as_slice(),
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
                messages[1].0.as_slice(),
                &reassembled_handshake_message,
            );

            let message_span = deframer.complete_span().unwrap();

            let reassembled_handshake_message = deframer.message(message_span, &encoded_records);
            check_reassembled_handshake(
                record_idx,
                version,
                messages[2].0.as_slice(),
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
    let encoded_first_record = EncodedMessage::<Payload<'_>>::from(Message {
        version: EncodableVersion::Legacy(version),
        payload: MessagePayload::new(ContentType::ApplicationData, version, &[1; 32]).unwrap(),
    })
    .borrow_outbound()
    .to_unencrypted_bytes(EncodingContext {
        payload_is_encrypted: true,
        epoch: Epoch::ApplicationData(3),
        record_seq: 11,
    });

    let encoded_first_record_len = encoded_first_record.len();

    let encoded_second_record = EncodedMessage::<Payload<'_>>::from(Message {
        version: EncodableVersion::Legacy(version),
        payload: MessagePayload::new(ContentType::ApplicationData, version, &[4; 92]).unwrap(),
    })
    .borrow_outbound()
    .to_unencrypted_bytes(EncodingContext {
        payload_is_encrypted: true,
        epoch: Epoch::ApplicationData(3),
        record_seq: 12,
    });

    let encoded_second_record_len = encoded_second_record.len();

    let mut wire_bytes = Vec::new();
    wire_bytes.extend(&encoded_first_record);
    wire_bytes.extend(&encoded_second_record);

    let mut deframer = Deframer::default();

    for (encoded_record, expect_start, expect_end, expect_epoch, expect_record_seq) in [
        (
            encoded_first_record,
            0,
            encoded_first_record_len,
            Epoch::ApplicationData(3),
            11,
        ),
        (
            encoded_second_record,
            encoded_first_record_len,
            encoded_first_record_len + encoded_second_record_len,
            Epoch::ApplicationData(3),
            12,
        ),
    ] {
        let Deframed {
            message,
            bounds,
            epoch,
            record_seq,
        } = deframer
            .deframe(&mut wire_bytes, expect_epoch, expect_record_seq - 1)
            .unwrap()
            .unwrap();

        assert_eq!(bounds.start, expect_start);
        assert_eq!(bounds.end, expect_end);

        let mut message = message.into_plain_message();
        if message.typ == ContentType::Dtls13Ciphertext {
            message.typ = ContentType::ApplicationData;
        }
        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(message.version.version(), version);
        assert_eq!(epoch, expect_epoch);
        assert_eq!(record_seq, expect_record_seq);
        assert_eq!(
            message.payload,
            &encoded_record[version.encrypted_header_len()..]
        );
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

fn multiple_epochs_interleave_application_data_and_handshakes(version: ProtocolVersion) {
    let prev_epoch = Epoch::ApplicationData(3);
    let curr_epoch = Epoch::ApplicationData(4);
    let next_epoch = Epoch::ApplicationData(5);
    let future_epoch = Epoch::ApplicationData(6);

    // Construct a few handshake messages and fragment them.
    let handshake_messages = [(vec![6u8; 36], 17), (vec![7; 32], 18), (vec![8; 4], 19)];
    let handshake_message_flight: Vec<_> = handshake_messages
        .iter()
        .map(|(m, seq)| {
            (
                HandshakeType::Finished,
                (*seq).into(),
                HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                    .get_encoding(),
            )
        })
        .collect();

    let mut fragmenter = Fragmenter::default();
    fragmenter
        .set_max_fragment_size(
            Some(32 + DTLS_12_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE),
            Protocol::Udp,
        )
        .unwrap();

    let handshake_records = fragmenter.fragment_dtls_handshake_message_flight(
        EncodableVersion::Legacy(version),
        &handshake_message_flight,
    );
    assert_eq!(handshake_records.len(), 3);

    let application_data = |content: usize| -> EncodedMessage<Payload<'_>> {
        EncodedMessage::<Payload<'_>>::from(Message {
            version: EncodableVersion::Legacy(version),
            payload: MessagePayload::new(
                ContentType::ApplicationData,
                version,
                &[content as u8, 32],
            )
            .unwrap(),
        })
    };

    // Interleave handshake and application data messages from multiple epochs.
    //
    // We expect that messages from older epochs and messages from too far in the future will be
    // discarded. We expect that messages from the current epoch are processed normally. We expect
    // that messages from the next epoch are ignored, but become available once we advance to the
    // next epoch.
    //
    // Scrambled with shuf(1)
    let records = vec![
        (curr_epoch, handshake_records[0].clone(), 11),
        (curr_epoch, handshake_records[1].clone(), 12),
        (next_epoch, handshake_records[2].clone(), 13),
        (future_epoch, application_data(1), 27),
        (prev_epoch, handshake_records[1].clone(), 12),
        (next_epoch, application_data(1), 26),
        (next_epoch, application_data(1), 27),
        (future_epoch, handshake_records[0].clone(), 11),
        (next_epoch, handshake_records[1].clone(), 12),
        (curr_epoch, handshake_records[2].clone(), 13),
        (future_epoch, application_data(1), 26),
        (future_epoch, handshake_records[1].clone(), 12),
        (prev_epoch, handshake_records[2].clone(), 13),
        (prev_epoch, application_data(1), 26),
        (curr_epoch, application_data(1), 27),
        (next_epoch, handshake_records[0].clone(), 11),
        (prev_epoch, handshake_records[0].clone(), 11),
        (curr_epoch, application_data(1), 26),
        (future_epoch, handshake_records[2].clone(), 13),
        (prev_epoch, application_data(1), 27),
    ];

    let mut wire_bytes = Vec::new();

    for (epoch, record, record_seq) in records.clone().into_iter() {
        let encoded = record
            .borrow_outbound()
            .to_unencrypted_bytes(EncodingContext {
                payload_is_encrypted: true,
                epoch,
                record_seq,
            });

        wire_bytes.extend(encoded);
    }

    let mut deframer = Deframer::default();

    // First pass: we deframe all the records out of the encoded wire bytes, but we only expect to
    // get back the current epoch's handshake messages (reassembled!) and application data. Records
    // from other epochs are either discarded or buffered.
    let mut highest_record_seq = 0;
    let mut seen_handshake_messages = 0;
    for (record_idx, (expect_epoch, expect_record, expect_record_seq)) in
        records.clone().into_iter().enumerate()
    {
        let deframed = deframer.deframe(&mut wire_bytes, curr_epoch, highest_record_seq);

        if expect_epoch != curr_epoch {
            assert!(deframed.is_none());
            continue;
        }

        let Deframed {
            message,
            bounds,
            epoch: deframed_epoch,
            record_seq,
        } = deframed.unwrap().unwrap();

        assert_eq!(deframed_epoch, curr_epoch);
        assert_eq!(record_seq, expect_record_seq);
        if record_seq > highest_record_seq {
            highest_record_seq = record_seq;
        }

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = expect_record.typ;
        let header_size = version.encrypted_header_len();
        let bounds = bounds.start + header_size..bounds.end;

        assert_eq!(message.payload, expect_record.payload.bytes());

        if message.typ == ContentType::Handshake {
            deframer
                .input_message_dtls(message, bounds)
                .unwrap();
            deframer.coalesce_dtls(&mut wire_bytes);
        }

        if let Some(span) = deframer.complete_span() {
            let reassembled_handshake_message = deframer.message(span, &wire_bytes);
            check_reassembled_handshake(
                record_idx,
                version,
                handshake_messages[seen_handshake_messages]
                    .0
                    .as_slice(),
                &reassembled_handshake_message,
            );
            seen_handshake_messages += 1;
        }
    }
    // Check that we saw all three handshake messages from the epoch
    assert_eq!(seen_handshake_messages, 3);

    // Second pass: description sof the records from next_epoch should be buffered in the deframer
    let mut highest_record_seq = 0;
    let mut seen_handshake_messages = 0;
    for (record_idx, (_, expect_record, expect_record_seq)) in records
        .clone()
        .into_iter()
        .filter(|(epoch, ..)| *epoch == next_epoch)
        .enumerate()
    {
        let Deframed {
            message,
            bounds,
            epoch: deframed_epoch,
            record_seq,
        } = deframer
            .deframe(&mut wire_bytes, next_epoch, highest_record_seq)
            .unwrap()
            .unwrap();

        assert_eq!(deframed_epoch, next_epoch);
        assert_eq!(record_seq, expect_record_seq);
        if record_seq > highest_record_seq {
            highest_record_seq = record_seq;
        }

        // Simulate in-place decryption
        let mut message = message.into_plain_message();
        message.typ = expect_record.typ;
        let header_size = version.encrypted_header_len();
        let bounds = bounds.start + header_size..bounds.end;

        assert_eq!(message.payload, expect_record.payload.bytes());

        if message.typ == ContentType::Handshake {
            deframer
                .input_message_dtls(message, bounds)
                .unwrap();
            deframer.coalesce_dtls(&mut wire_bytes);
        }

        while let Some(span) = deframer.complete_span() {
            let reassembled_handshake_message = deframer.message(span, &wire_bytes);
            check_reassembled_handshake(
                record_idx,
                version,
                handshake_messages[seen_handshake_messages]
                    .0
                    .as_slice(),
                &reassembled_handshake_message,
            );
            seen_handshake_messages += 1;
        }
    }
    // Check that we saw all three handshake messages from the epoch
    assert_eq!(seen_handshake_messages, 3);

    // Try to deframe a message from the other two epochs. We should get nothing.
    assert!(
        deframer
            .deframe(&mut wire_bytes, prev_epoch, 0)
            .is_none()
    );
    assert!(
        deframer
            .deframe(&mut wire_bytes, future_epoch, 0)
            .is_none()
    );
}

#[test]
fn multiple_epochs_interleave_application_data_and_handshakes_dtls_12() {
    multiple_epochs_interleave_application_data_and_handshakes(ProtocolVersion::DTLSv1_2);
}

#[test]
fn multiple_epochs_interleave_application_data_and_handshakes_dtls_13() {
    multiple_epochs_interleave_application_data_and_handshakes(ProtocolVersion::DTLSv1_3);
}
