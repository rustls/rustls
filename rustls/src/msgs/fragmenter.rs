use alloc::vec::Vec;
use core::cmp::min;
use core::mem;

use crate::Error;
use crate::crypto::cipher::{EncodedMessage, OutboundPlain, Payload};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::msgs::{
    Codec, DTLS_12_HEADER_SIZE, DTLS_HANDSHAKE_HEADER_SIZE, DtlsHandshakeFragment,
    EpochAndSequence, HEADER_SIZE, U24, UnifiedHeader,
};

#[cfg(test)]
mod dtls_test;

pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + HEADER_SIZE;

pub(crate) struct MessageFragmenter {
    max_frag: usize,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
        }
    }
}

impl MessageFragmenter {
    /// Take `msg` and fragment it into new messages with the same type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `msg`.
    ///
    /// Should not be used for DTLS messages. See [`Self::fragment_dtls_handshake_message`].
    pub(crate) fn fragment_message<'a>(
        &self,
        msg: &'a EncodedMessage<Payload<'_>>,
    ) -> impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>> + 'a {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes().into())
    }

    /// Take a DTLS handshake message and fragment it into multiple unencrypted outbound messages,
    /// each consisting of a DTLSPlaintext ([1]). Other DTLS messages may not be fragmented.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc9147#appendix-A.1
    // TODO(DTLS): this method should go away, and instead fragmenting a single
    // message should be achieved by passing a slice of one element to
    // Self::fragment_dtls_handshake_message_flight
    pub(crate) fn fragment_dtls_handshake_message<'a>(
        &self,
        version: ProtocolVersion,
        epoch_and_sequence: EpochAndSequence,
        msg_type: HandshakeType,
        handshake_sequence_number: u16,
        handshake_payload: &'a [u8],
    ) -> impl ExactSizeIterator<Item = EncodedMessage<DtlsHandshakeFragment<'a>>> + 'a {
        // handshake_payload will have been encoded as a TLS handshake message, so we discard the
        // front 4 bytes (1 byte of handshake type plus 3 bytes of length) so that we can re-encode
        // as a DTLS handshake fragment.
        let handshake_payload = &handshake_payload[4..];
        assert!(handshake_payload.len() <= U24::MAX as usize);
        let length = U24(handshake_payload.len() as u32);
        let mut fragment_offset = 0;

        Chunker::new(
            handshake_payload.into(),
            self.max_fragment_size(version, Some(epoch_and_sequence.sequence_number.0))
                - DTLS_HANDSHAKE_HEADER_SIZE,
        )
        .map(move |payload| {
            assert!(fragment_offset <= U24::MAX);
            assert!(payload.len() <= U24::MAX as usize);
            let payload_len = payload.len() as u32;

            let fragment = match payload {
                OutboundPlain::Single(buf) => Payload::Borrowed(buf),
                OutboundPlain::Multiple { .. } => {
                    panic!("should never construct OutboundPlain::Multiple from a Payload")
                }
            };

            let fragment = DtlsHandshakeFragment {
                msg_type,
                length,
                message_seq: handshake_sequence_number,
                fragment_offset: U24(fragment_offset),
                fragment_length: U24(payload_len),
                fragment,
            };

            fragment_offset += payload_len;

            EncodedMessage {
                typ: ContentType::Handshake,
                version,
                payload: fragment,
            }
        })
    }

    /// Fragment the provided flight of handshake messages (represented as tuples of the handshake
    /// type and the encoded handshake message payload) as one or more DTLS records.
    ///
    /// Each record may contain more than one handshake message, or just a single handshake
    /// fragment.
    ///
    /// `handshake_sequence_number` is the handshake sequence number for the first message in this
    /// flight.
    pub(crate) fn fragment_dtls_handshake_message_flight<'a>(
        &self,
        version: ProtocolVersion,
        mut epoch_and_sequence: EpochAndSequence,
        mut handshake_sequence_number: u16,
        handshake_messages: &'a [(HandshakeType, Vec<u8>)],
    ) -> Vec<EncodedMessage<Payload<'a>>> {
        let mut records = Vec::new();
        // The current record we are packing with the handshake flight. Does not include record
        // header.
        // TODO(DTLS): this is wrong: the sequence number will increase as we
        // emit records, and could become big enough to require a larger unified
        // header, so we need to recompute record capacity for each record.
        let record_capacity =
            self.max_fragment_size(version, Some(epoch_and_sequence.sequence_number.0));
        let mut curr_record = Vec::with_capacity(record_capacity);

        let mut finish_record = |curr_record: &mut Vec<u8>| {
            let finished_record = mem::replace(curr_record, Vec::with_capacity(record_capacity));
            records.push(EncodedMessage {
                typ: ContentType::Handshake,
                version,
                payload: Payload::new(finished_record),
            });
            epoch_and_sequence = epoch_and_sequence.add_sequence_increment(1);
        };

        for (idx, (handshake_type, handshake_payload)) in handshake_messages.iter().enumerate() {
            // handshake_payload will have been encoded as a TLS handshake message, so we discard the
            // front 4 bytes (1 byte of handshake type plus 3 bytes of length) so that we can re-encode
            // as a DTLS handshake fragment.
            let handshake_payload = &handshake_payload[4..];
            assert!(handshake_payload.len() <= U24::MAX as usize);
            let length = U24(handshake_payload.len() as u32);

            let mut fragment_offset = 0;
            loop {
                if record_capacity - curr_record.len() <= DTLS_HANDSHAKE_HEADER_SIZE {
                    // There's no room left in the current record for a handshake fragment. Start a
                    // new record.
                    finish_record(&mut curr_record);
                }
                // Fill fragment with either remainder of the handshake payload or the remaining
                // capacity of the record.
                let fragment_length = min(
                    record_capacity - curr_record.len() - DTLS_HANDSHAKE_HEADER_SIZE,
                    handshake_payload.len() - fragment_offset,
                );

                let fragment = DtlsHandshakeFragment {
                    msg_type: *handshake_type,
                    length,
                    message_seq: handshake_sequence_number,
                    fragment_offset: U24(fragment_offset.try_into().unwrap()),
                    fragment_length: U24(fragment_length.try_into().unwrap()),
                    fragment: Payload::Borrowed(
                        &handshake_payload[fragment_offset..fragment_offset + fragment_length],
                    ),
                };

                fragment_offset += fragment_length;

                fragment.encode(&mut curr_record);

                // Make sure we didn't accidentally grow the record
                assert_eq!(
                    curr_record.capacity(),
                    record_capacity,
                    "record len: {}",
                    curr_record.len()
                );

                // If we have filled the current record or if this is the last fragment of the last
                // handshake message, construct a record
                if curr_record.len() == curr_record.capacity()
                    || (idx + 1 == handshake_messages.len()
                        && fragment_offset == handshake_payload.len())
                {
                    finish_record(&mut curr_record);
                }

                if fragment_offset == handshake_payload.len() {
                    break;
                }
            }

            handshake_sequence_number += 1;
        }

        records
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundPlain<'a>,
    ) -> impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>> {
        assert!(
            !version.is_datagram_tls(),
            "To fragment a DTLS handshake message, use fragment_dtls_handshake_message. \
            Other DTLS messages may not be fragmented.",
        );
        Chunker::new(payload, self.max_fragment_size(version, None)).map(move |payload| {
            EncodedMessage {
                typ,
                version,
                payload,
            }
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes long.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub(crate) fn set_max_fragment_size(
        &mut self,
        max_fragment_size: Option<usize>,
    ) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }

    fn max_fragment_size(&self, version: ProtocolVersion, sequence: Option<u64>) -> usize {
        self.max_frag
            - match version {
                ProtocolVersion::DTLSv1_2 => DTLS_12_HEADER_SIZE,
                ProtocolVersion::DTLSv1_3 => UnifiedHeader::header_length(sequence.unwrap_or(0)),
                _ => HEADER_SIZE,
            }
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundPlain<'a>,
    limit: usize,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundPlain<'a>, limit: usize) -> Self {
        Self { payload, limit }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundPlain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (before, after) = self.payload.split_at(self.limit);
        self.payload = after;
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        self.payload.len().div_ceil(self.limit)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::vec;

    use super::MessageFragmenter;
    use crate::crypto::cipher::{EncodedMessage, EncodingContext, OutboundPlain, Payload};
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::HEADER_SIZE;

    fn msg_eq(
        m: &EncodedMessage<OutboundPlain<'_>>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m
            .to_unencrypted_opaque(EncodingContext {
                payload_is_encrypted: false,
                ..Default::default()
            })
            .encode();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let data: Vec<u8> = (1..70u8).collect();
        let m = EncodedMessage {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        msg_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let m = EncodedMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            HEADER_SIZE + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundPlain::new(&payload_owner);
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment_payload(typ, version, borrowed_payload)
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        msg_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        msg_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        msg_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }
}
