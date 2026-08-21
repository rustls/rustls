use core::num::NonZeroUsize;

use crate::Error;
use crate::crypto::cipher::{EncodableVersion, OutboundPlain, Record};
use crate::enums::ContentType;

pub(crate) const MAX_FRAGMENT_LEN: NonZeroUsize = NonZeroUsize::new(16384).unwrap();
pub(crate) const PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN.get() + PACKET_OVERHEAD;

pub(crate) struct Fragmenter {
    max_frag: NonZeroUsize,
}

impl Fragmenter {
    /// Take `payload` and fragment it into new records with given type and version.
    ///
    /// Each returned record size is no more than the most recently configured
    /// `set_max_fragment_size()`, less an allowance for `encryption_overhead` which
    /// should be zero if no encryption will be performed.
    ///
    /// Return an iterator across those records.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment<'a>(
        &self,
        typ: ContentType,
        version: EncodableVersion,
        payload: OutboundPlain<'a>,
        encryption_overhead: usize,
    ) -> impl ExactSizeIterator<Item = Record<OutboundPlain<'a>>> + use<'a> {
        let max_plaintext = NonZeroUsize::new(
            self.max_frag
                .get()
                .saturating_sub(encryption_overhead),
        )
        .unwrap_or(NonZeroUsize::MIN);
        Chunker::new(payload, max_plaintext).map(move |payload| Record {
            typ,
            version,
            payload,
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This is the maximum size of each TLS record on the wire, including the
    /// five-byte record header. When records are encrypted, plaintext is fragmented
    /// more aggressively so the protected record still fits in this limit.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub(crate) fn set_max_fragment_size(
        &mut self,
        max_fragment_size: Option<usize>,
    ) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => NonZeroUsize::new(sz - PACKET_OVERHEAD).unwrap(),
            None => MAX_FRAGMENT_LEN,
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

    use super::{Fragmenter, PACKET_OVERHEAD};
    use crate::crypto::cipher::{EncodableVersion, OutboundPlain, Payload, Record};
    use crate::enums::{ContentType, ProtocolVersion};

    fn record_eq(
        record: &Record<OutboundPlain<'_>>,
        total_len: usize,
        typ: &ContentType,
        version: &EncodableVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&record.typ, typ);
        assert_eq!(&record.version, version);
        assert_eq!(record.payload.to_vec(), bytes);

        let buf = record.to_unencrypted_bytes();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = EncodableVersion::Legacy(ProtocolVersion::TLSv1_2);
        let data: Vec<u8> = (1..70u8).collect();
        let record = Record {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment(record.typ, record.version, record.payload.bytes().into(), 0)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        record_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        record_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        record_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let record = Record {
            typ: ContentType::Handshake,
            version: EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment(record.typ, record.version, record.payload.bytes().into(), 0)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        record_eq(
            &q[0],
            PACKET_OVERHEAD + 8,
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
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment(typ, version, borrowed_payload, 0)
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        record_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        record_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        record_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }

    #[test]
    fn fragment_respects_overhead() {
        let mut frag = Fragmenter::default();
        frag.set_max_fragment_size(Some(32))
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

        let each_len = 32 - PACKET_OVERHEAD - 13;

        let mut expect = vec![each_len; 128usize.div_euclid(each_len)];
        expect.push(128usize.rem_euclid(each_len));

        assert_eq!(
            q.iter()
                .map(|record| record.payload.len())
                .collect::<Vec<usize>>(),
            expect
        );
    }
}
