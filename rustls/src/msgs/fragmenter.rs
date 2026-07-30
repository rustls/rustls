use alloc::vec::Vec;
use core::cmp::min;
use core::mem;
use core::num::NonZeroUsize;

use crate::Error;
use crate::common_state::Protocol;
use crate::crypto::cipher::{EncodableVersion, EncodedMessage, OutboundPlain, Payload};
use crate::enums::{ContentType, HandshakeType};
use crate::msgs::{
    Codec, DTLS_12_HEADER_SIZE, DTLS_HANDSHAKE_HEADER_SIZE, DtlsHandshakeFragment, HEADER_SIZE,
    HandshakeSequenceNumber, U24,
};

#[cfg(test)]
mod dtls_test;

/// Maximum length of a TLSPlaintext payload permitted by TLS.
///
/// <https://www.rfc-editor.org/info/rfc9846/#section-5.1>
pub(crate) const MAX_FRAGMENT_LEN: NonZeroUsize = NonZeroUsize::new(16384).unwrap();

/// Maxium length of a TLSPlaintext payload over streams (TCP or QUIC).
///
/// This includes the record header.
const MAX_STREAM_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN.get() + HEADER_SIZE;

/// Maximum length of a TLSPlaintext payload over UDP.
///
/// This pessimistically includes the full DTLS record header, though a more compact unified header
/// is used for the majority of DTLS 1.3 messages.
const MAX_UDP_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN.get() + DTLS_12_HEADER_SIZE;

pub(crate) struct Fragmenter {
    max_frag: NonZeroUsize,
}

impl Fragmenter {
    /// Take a DTLS handshake message and fragment it into multiple unencrypted outbound messages,
    /// each consisting of a DTLSPlaintext ([1]). Other DTLS messages may not be fragmented.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc9147#appendix-A.1
    // TODO(DTLS): this method should go away, and instead fragmenting a single
    // message should be achieved by passing a slice of one element to
    // Self::fragment_dtls_handshake_message_flight
    pub(crate) fn fragment_dtls_handshake_message<'a>(
        &self,
        version: EncodableVersion,
        msg_type: HandshakeType,
        handshake_sequence_number: HandshakeSequenceNumber,
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
            NonZeroUsize::new(self.max_frag.get() - DTLS_HANDSHAKE_HEADER_SIZE).unwrap(),
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
        version: EncodableVersion,
        handshake_messages: &'a [(HandshakeType, HandshakeSequenceNumber, Vec<u8>)],
    ) -> Vec<EncodedMessage<Payload<'a>>> {
        let mut records = Vec::new();
        // The current record we are packing with the handshake flight. Does not include record
        // header.
        // TODO(DTLS): this is wrong: the sequence number will increase as we
        // emit records, and could become big enough to require a larger unified
        // header, so we need to recompute record capacity for each record.
        let record_capacity = self.max_frag.get();
        let mut curr_record = Vec::with_capacity(record_capacity);

        let mut finish_record = |curr_record: &mut Vec<u8>| {
            let finished_record = mem::replace(curr_record, Vec::with_capacity(record_capacity));
            records.push(EncodedMessage {
                typ: ContentType::Handshake,
                version,
                payload: Payload::new(finished_record),
            });
        };

        for (idx, (handshake_type, handshake_seq, handshake_payload)) in
            handshake_messages.iter().enumerate()
        {
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
                    message_seq: *handshake_seq,
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
        }

        records
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than the most recently configured
    /// `set_max_fragment_size()`, less an allowance for `encryption_overhead` which
    /// should be zero if no encryption will be performed.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment<'a>(
        &self,
        typ: ContentType,
        version: EncodableVersion,
        payload: OutboundPlain<'a>,
        encryption_overhead: usize,
    ) -> impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>> + use<'a> {
        assert!(
            !version.version().is_datagram_tls(),
            "To fragment a DTLS handshake message, use fragment_dtls_handshake_message. \
            Other DTLS messages may not be fragmented.",
        );
        let max_plaintext = NonZeroUsize::new(
            self.max_frag
                .get()
                .saturating_sub(encryption_overhead),
        )
        .unwrap_or(NonZeroUsize::MIN);
        Chunker::new(payload, max_plaintext).map(move |payload| EncodedMessage {
            typ,
            version,
            payload,
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This is the maximum size of each TLS record on the wire, including the
    /// record header. When records are encrypted, plaintext is fragmented
    /// more aggressively so the protected record still fits in this limit.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389 (for
    /// `Protocol::{Tls, Quic}`) or 16397 (`Protocol::Udp`).
    ///
    /// # Bugs
    ///
    /// This limit only applies to plaintext payload size and does not account for overhead from
    /// encryption (#991).
    pub(crate) fn set_max_fragment_size(
        &mut self,
        max_fragment_size: Option<usize>,
        protocol: Protocol,
    ) -> Result<(), Error> {
        self.max_frag = match (protocol, max_fragment_size) {
            (Protocol::Tcp | Protocol::Quic(_), Some(sz @ 32..=MAX_STREAM_FRAGMENT_SIZE)) => {
                NonZeroUsize::new(sz - HEADER_SIZE).unwrap()
            }
            (Protocol::Udp, Some(sz @ 32..=MAX_UDP_FRAGMENT_SIZE)) => {
                NonZeroUsize::new(sz - DTLS_12_HEADER_SIZE).unwrap()
            }
            (_, None) => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
        }
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundPlain<'a>,
    limit: NonZeroUsize,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundPlain<'a>, limit: NonZeroUsize) -> Self {
        Self { payload, limit }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundPlain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (before, after) = self.payload.split_at(self.limit.get());
        self.payload = after;
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        self.payload
            .len()
            .div_ceil(self.limit.get())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::vec;

    use super::Fragmenter;
    use crate::common_state::Protocol;
    use crate::crypto::cipher::{
        EncodableVersion, EncodedMessage, EncodingContext, OutboundPlain, Payload,
    };
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::HEADER_SIZE;

    fn msg_eq(
        m: &EncodedMessage<OutboundPlain<'_>>,
        total_len: usize,
        typ: &ContentType,
        version: &EncodableVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m.to_unencrypted_bytes(EncodingContext::new());

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = EncodableVersion::Legacy(ProtocolVersion::TLSv1_2);
        let data: Vec<u8> = (1..70u8).collect();
        let m = EncodedMessage {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32), Protocol::Tcp)
            .unwrap();
        let q = frag
            .fragment(m.typ, m.version, m.payload.bytes().into(), 0)
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
            version: EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32), Protocol::Tcp)
            .unwrap();
        let q = frag
            .fragment(m.typ, m.version, m.payload.bytes().into(), 0)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            HEADER_SIZE + 8,
            &ContentType::Handshake,
            &EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = EncodableVersion::Legacy(ProtocolVersion::TLSv1_2);
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundPlain::new(&payload_owner);
        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(37), Protocol::Tcp) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment(typ, version, borrowed_payload, 0)
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

    #[test]
    fn fragment_respects_overhead() {
        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32), Protocol::Tcp)
            .unwrap();

        let p = Payload::new((0..128).collect::<Vec<u8>>());
        let q = frag
            .fragment(
                ContentType::Handshake,
                EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                p.bytes().into(),
                13,
            )
            .collect::<Vec<_>>();

        let each_len = 32 - HEADER_SIZE - 13;

        let mut expect = vec![each_len; 128usize.div_euclid(each_len)];
        expect.push(128usize.rem_euclid(each_len));

        assert_eq!(
            q.iter()
                .map(|m| m.payload.len())
                .collect::<Vec<usize>>(),
            expect
        );
    }
}
