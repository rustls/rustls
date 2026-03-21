use core::mem;
use core::ops::Range;
use std::collections::VecDeque;

use crate::crypto::cipher::{EncodedMessage, InboundOpaque, MessageError};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::{Codec, Reader, U24};
use crate::msgs::{HEADER_SIZE, read_opaque_message_header};

mod buffers;
use buffers::Coalescer;
pub(crate) use buffers::{Delocator, Locator, TlsInputBuffer, VecInput};

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut deframer = Deframer::default();
    while let Some(result) = deframer.deframe(&mut buf) {
        if result.is_err() {
            break;
        }
    }

    assert!(deframer.processed() <= buf.len());
}

#[derive(Debug)]
pub(crate) struct Deframer {
    /// Spans covering individual handshake payloads, in order of receipt.
    spans: VecDeque<FragmentSpan>,

    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl Deframer {
    pub(crate) fn deframe<'a>(&mut self, buf: &'a mut [u8]) -> Option<Result<Deframed<'a>, Error>> {
        let mut reader = Reader::new(buf.get(self.processed..)?);

        let (typ, version, len) = match read_opaque_message_header(&mut reader) {
            Ok(header) => header,
            Err(err) => {
                let err = match err {
                    MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                        return None;
                    }
                    MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                    MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                    MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
                };
                return Some(Err(err.into()));
            }
        };

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let end = self.processed + HEADER_SIZE + len as usize;
        let head = buf.get_mut(..end)?;
        let bounds = self.processed..end;
        self.processed = end;

        Some(Ok(Deframed {
            message: EncodedMessage {
                typ,
                version,
                payload: InboundOpaque(&mut head[bounds.start + HEADER_SIZE..]),
            },
            bounds,
        }))
    }

    /// Accepts a message into the deframer.
    ///
    /// `containing_buffer` allows mapping the message payload to its position
    /// in the input buffer, and thereby avoid retaining a borrow on the input
    /// buffer.
    ///
    /// That is required because our processing of handshake messages requires
    /// them to be contiguous (and avoiding that would mean supporting gather-based
    /// parsing in a large number of places, including `core`, `webpki`, and the
    /// `CryptoProvider` interface).  `coalesce()` arranges for that to happen, but
    /// to do so it needs to move the fragments together in the original buffer.
    /// This would not be possible if the messages were borrowing from that buffer.
    pub(crate) fn input_message(&mut self, msg: EncodedMessage<&'_ [u8]>, bounds: Range<usize>) {
        debug_assert_eq!(msg.typ, ContentType::Handshake);

        // if our last span is incomplete, we can blindly add this as a new span --
        // no need to attempt parsing it with `DissectHandshakeIter`.
        //
        // `coalesce()` will later move this new message to be contiguous with
        // `_last_incomplete`, and reparse the result.
        //
        // we cannot merge these processes, because `coalesce` mutates the underlying
        // buffer, and `msg` borrows it.
        if let Some(_last_incomplete) = self
            .spans
            .back()
            .filter(|span| !span.is_complete())
        {
            self.spans.push_back(FragmentSpan {
                version: msg.version,
                size: None,
                bounds,
            });
            return;
        }

        // otherwise, we can expect `msg` to contain a handshake header introducing
        // a new message (and perhaps several of them.)
        for span in DissectHandshakeIter::new(msg, bounds) {
            self.spans.push_back(span);
        }
    }

    /// Coalesce the handshake portions of the given buffer,
    /// if needed.
    ///
    /// This does nothing if there is nothing to do.
    ///
    /// In a normal TLS stream, handshake messages need not be contiguous.
    /// For example, each handshake message could be delivered in its own
    /// outer TLS message.  This would mean the handshake messages are
    /// separated by the outer TLS message headers, and likely also
    /// separated by encryption overhead (any explicit nonce in front,
    /// any padding and authentication tag afterwards).
    ///
    /// For a toy example of one handshake message in two fragments, and:
    ///
    /// - the letter `h` for handshake header octets
    /// - the letter `H` for handshake payload octets
    /// - the letter `x` for octets in the buffer ignored by this code,
    ///
    /// the buffer and `spans` data structure could look like:
    ///
    /// ```text
    /// 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9
    /// x x x x x h h h h H H H x x x x x H H H H H H x x x
    ///           '------------'          '----------'
    ///            |                               |
    /// spans = [ { bounds = (5, 12),              |
    ///              size = Some(9), .. },         |
    ///                                 { bounds = (17, 23), .. } ]
    /// ```
    ///
    /// In this case, `requires_coalesce` returns `Some(0)`.  Then
    /// `coalesce_one` moves the second range leftwards:
    ///
    /// ```text
    /// 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9
    /// x x x x x h h h h H H H x x x x x H H H H H H x x x
    ///                         '----------'
    ///                          ^        '----------'
    ///                          |         v
    ///                          '--<---<--'
    ///                 copy_within(from = (17, 23),
    ///                             to = (12, 18))
    /// ```
    ///
    /// Leaving the buffer and spans:
    ///
    /// ```text
    /// 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9
    /// x x x x x h h h h H H H H H H H H H x x x x x x x x
    ///           '------------------------'
    ///            |
    /// spans = [ { bounds = (5, 18), size = Some(9), .. } ]
    /// ```
    pub(crate) fn coalesce(&mut self, containing_buffer: &mut [u8]) -> Result<(), InvalidMessage> {
        // Strategy: while there is work to do, scan `spans`
        // for a pair where the first is not complete.  move
        // the second down towards the first, then reparse the contents.
        loop {
            let limit = self.spans.len().saturating_sub(1);
            let iter = self.spans.iter();
            let Some(index) = iter
                .enumerate()
                .take(limit)
                .find_map(|(i, span)| (!span.is_complete()).then_some(i))
            else {
                return Ok(());
            };

            let Some(second) = self.spans.remove(index + 1) else {
                return Ok(());
            };

            let Some(mut first) = self.spans.remove(index) else {
                self.spans.insert(index + 1, second);
                return Ok(());
            };

            // move the entirety of `second` to be contiguous with `first`
            let len = second.bounds.len();
            let target = Range {
                start: first.bounds.end,
                end: first.bounds.end + len,
            };

            let mut coalescer = Coalescer::new(containing_buffer);
            coalescer.copy_within(second.bounds, target);
            let delocator = coalescer.delocator();

            // now adjust `first` to cover both
            first.bounds.end += len;

            // finally, attempt to re-dissect `first`
            let msg = EncodedMessage {
                typ: ContentType::Handshake,
                version: first.version,
                payload: delocator.slice_from_range(&first.bounds),
            };

            let mut too_large = false;
            for (i, span) in DissectHandshakeIter::new(msg, first.bounds).enumerate() {
                if span.size.unwrap_or_default() > MAX_HANDSHAKE_SIZE {
                    too_large = true;
                }
                self.spans.insert(index + i, span);
            }

            if too_large {
                return Err(InvalidMessage::HandshakePayloadTooLarge);
            }
        }
    }

    /// Yield the next complete handshake message from `containing_buffer`.
    ///
    /// If this was the last pending handshake message, marks the processed
    /// buffer region for discard.
    pub(crate) fn message<'b>(
        &mut self,
        next_span: FragmentSpan,
        containing_buffer: &'b [u8],
    ) -> EncodedMessage<&'b [u8]> {
        // if this is the last handshake message, then we'll end
        // up with an empty `spans` and can discard the remainder
        // of the input buffer.
        if self.spans.is_empty() {
            self.discard += self.processed;
        }

        EncodedMessage {
            typ: ContentType::Handshake,
            version: next_span.version,
            payload: Delocator::new(containing_buffer).slice_from_range(&next_span.bounds),
        }
    }

    /// Yield the first complete [`FragmentSpan`] if any.
    pub(crate) fn complete_span(&mut self) -> Option<FragmentSpan> {
        match self.spans.front() {
            Some(span) if span.is_complete() => self.spans.pop_front(),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self
            .processed
            .saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn discard_processed(&mut self) {
        self.discard = self.processed;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    /// We are "aligned" if there is no partial fragments of a handshake message.
    pub(crate) fn aligned(&self) -> Option<HandshakeAlignedProof> {
        self.spans
            .iter()
            .all(|span| span.is_complete())
            .then_some(HandshakeAlignedProof(()))
    }

    /// Do we have any message data, partial or otherwise?
    pub(crate) fn is_active(&self) -> bool {
        !self.spans.is_empty()
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

impl Default for Deframer {
    fn default() -> Self {
        Self {
            // capacity: a typical upper limit on handshake messages in
            // a single flight
            spans: VecDeque::with_capacity(16),
            processed: 0,
            discard: 0,
        }
    }
}

struct DissectHandshakeIter<'b> {
    version: ProtocolVersion,
    payload: &'b [u8],
    bounds: Range<usize>,
}

impl<'b> DissectHandshakeIter<'b> {
    fn new(msg: EncodedMessage<&'b [u8]>, bounds: Range<usize>) -> Self {
        Self {
            version: msg.version,
            payload: msg.payload,
            bounds,
        }
    }
}

impl Iterator for DissectHandshakeIter<'_> {
    type Item = FragmentSpan;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        // If there is not enough data to have a header the length is unknown
        let all = mem::take(&mut self.payload);
        let Some((header, rest)) = all.split_at_checked(HANDSHAKE_HEADER_LEN) else {
            return Some(FragmentSpan {
                version: self.version,
                size: None,
                bounds: mem::take(&mut self.bounds),
            });
        };

        // safety: header[1..] is exactly 3 bytes, so `u24::read_bytes` cannot fail
        let size = U24::read_bytes(&header[1..])
            .unwrap()
            .into();

        let payload = match rest.split_at_checked(size) {
            Some((payload, rest)) => {
                self.payload = rest;
                payload
            }
            None => rest,
        };

        let span_len = header.len() + payload.len();
        let bounds = self.bounds.start..self.bounds.start + span_len;
        self.bounds = self.bounds.start + span_len..self.bounds.end;
        Some(FragmentSpan {
            version: self.version,
            size: Some(size),
            bounds,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FragmentSpan {
    /// version taken from containing message.
    version: ProtocolVersion,

    /// size of the handshake message body (excluding header)
    ///
    /// `None` means the size is unknown, because `bounds` is not
    /// large enough to encompass a whole header.
    size: Option<usize>,

    /// bounds of the handshake message, including header
    bounds: Range<usize>,
}

impl FragmentSpan {
    /// A `FragmentSpan` is "complete" if its size is known, and its
    /// bounds exactly encompasses one handshake message.
    fn is_complete(&self) -> bool {
        match self.size {
            Some(sz) => sz + HANDSHAKE_HEADER_LEN == self.bounds.len(),
            None => false,
        }
    }
}

pub(crate) struct Deframed<'a> {
    pub(crate) message: EncodedMessage<InboundOpaque<'a>>,
    pub(crate) bounds: Range<usize>,
}

/// Proof type that the handshake deframer is aligned.
///
/// See [`Deframer::aligned()`] for more details.
#[must_use]
#[derive(Clone, Copy)]
pub(crate) struct HandshakeAlignedProof(());

const HANDSHAKE_HEADER_LEN: usize = 1 + 3;

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: usize = 0xffff;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::msgs::HEADER_SIZE;

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }

    fn add_bytes(deframer: &mut Deframer, range: Range<usize>, within: &[u8]) {
        let msg = EncodedMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: &within[range.start..range.end],
        };

        deframer.processed = range.end;
        deframer.input_message(msg, range);
    }

    #[test]
    fn coalesce() {
        let mut input = vec![0, 0, 0, 0x21, 0, 0, 0, 0, 0x01, 0xff, 0x00, 0x01];
        let mut deframer = Deframer::default();

        add_bytes(&mut deframer, 3..4, &input);
        add_bytes(&mut deframer, 4..6, &input);
        add_bytes(&mut deframer, 8..10, &input);

        std::println!("before: {deframer:?}");
        deframer.coalesce(&mut input).unwrap();
        std::println!("after:  {deframer:?}");

        let span = deframer.complete_span().unwrap();
        let msg = deframer.message(span, &input);
        std::println!("msg {msg:?}");
        assert_eq!(msg.typ, ContentType::Handshake);
        assert_eq!(msg.version, ProtocolVersion::TLSv1_3);
        assert_eq!(msg.payload, &[0x21, 0x00, 0x00, 0x01, 0xff]);

        input.drain(..deframer.take_discard());

        assert_eq!(input, &[0, 1]);
    }

    #[test]
    fn append() {
        let mut input = vec![0, 0, 0, 0x21, 0, 0, 5, 0, 0, 1, 2, 3, 4, 5, 0];
        let mut deframer = Deframer::default();

        add_bytes(&mut deframer, 3..7, &input);
        add_bytes(&mut deframer, 9..14, &input);
        assert_eq!(deframer.spans.len(), 2);

        deframer.coalesce(&mut input).unwrap();
        let span = deframer.complete_span().unwrap();

        let msg = std::dbg!(deframer.message(span, &input));
        assert_eq!(msg.typ, ContentType::Handshake);
        assert_eq!(msg.version, ProtocolVersion::TLSv1_3);
        assert_eq!(msg.payload, &[0x21, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5]);

        input.drain(..deframer.take_discard());

        assert_eq!(input, &[0]);
    }

    #[test]
    fn coalesce_rejects_excess_size_message() {
        const X: u8 = 0xff;
        let mut input = vec![0x21, 0x01, 0x00, X, 0x00, 0xab, X];
        let mut deframer = Deframer::default();

        // split header over multiple messages, which motivates doing
        // this check in `coalesce()`
        add_bytes(&mut deframer, 0..3, &input);
        add_bytes(&mut deframer, 4..6, &input);

        assert_eq!(
            deframer.coalesce(&mut input),
            Err(InvalidMessage::HandshakePayloadTooLarge)
        );
    }

    #[test]
    fn iter_only_returns_full_messages() {
        let input = [0, 0, 0, 0x21, 0, 0, 1, 0xab, 0x21, 0, 0, 1];

        let mut deframer = Deframer::default();

        add_bytes(&mut deframer, 3..8, &input);
        add_bytes(&mut deframer, 8..12, &input);

        let span = deframer.complete_span().unwrap();
        let msg = deframer.message(span, &input);
        assert!(deframer.complete_span().is_none());

        assert_eq!(msg.typ, ContentType::Handshake);
        assert_eq!(msg.version, ProtocolVersion::TLSv1_3);
        assert_eq!(msg.payload, &[0x21, 0x00, 0x00, 0x01, 0xab]);
        // second span is incomplete, so no discard yet
        assert_eq!(deframer.discard, 0);
    }

    #[test]
    fn handshake_flight() {
        // intended to be a realistic example
        let mut input = include_bytes!("../../testdata/handshake-test.1.bin").to_vec();

        let mut deframer = Deframer::default();
        while let Some(result) = deframer.deframe(&mut input) {
            let Deframed { message, bounds } = result.unwrap();
            let plain = message.into_plain_message();
            std::println!("message {plain:?}");

            deframer.input_message(plain, bounds.start + HEADER_SIZE..bounds.end);
        }

        deframer
            .coalesce(&mut input[..])
            .unwrap();

        for _ in 0..4 {
            let span = deframer.complete_span().unwrap();
            let msg = deframer.message(span, &input[..]);
            assert!(matches!(
                msg,
                EncodedMessage {
                    typ: ContentType::Handshake,
                    ..
                }
            ));
            assert_eq!(deframer.discard, 0);
        }

        let span = deframer.complete_span().unwrap();
        let msg = deframer.message(span, &input[..]);
        assert!(matches!(
            msg,
            EncodedMessage {
                typ: ContentType::Handshake,
                ..
            }
        ));

        let discard = deframer.take_discard();
        assert_eq!(discard, 4280);
        input.drain(0..discard);
        assert!(input.is_empty());
    }

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(
            Deframer::default()
                .deframe(&mut [])
                .is_none()
        );
        assert!(
            Deframer::default()
                .deframe(&mut [0x16])
                .is_none()
        );
        assert!(
            Deframer::default()
                .deframe(&mut [0x16, 0x03])
                .is_none()
        );
        assert!(
            Deframer::default()
                .deframe(&mut [0x16, 0x03, 0x03])
                .is_none()
        );
        assert!(
            Deframer::default()
                .deframe(&mut [0x16, 0x03, 0x03, 0x00])
                .is_none()
        );
        assert!(
            Deframer::default()
                .deframe(&mut [0x16, 0x03, 0x03, 0x00, 0x01])
                .is_none()
        );
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut deframer = Deframer::default();

        let Deframed { message, bounds } = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 6);
        assert!(deframer.deframe(&mut buffer).is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut deframer = Deframer::default();

        let Deframed { message, bounds } = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::Handshake);
        assert_eq!(bounds.end, 6);

        let Deframed { message, bounds } = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 12);
        assert!(deframer.deframe(&mut buffer).is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut deframer = Deframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut deframer = Deframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut deframer = Deframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut deframer = Deframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload))
        );
    }

    #[test]
    fn iterator_over_many_messages() {
        let client_hello = include_bytes!("../../testdata/deframer-test.1.bin");
        let mut buffer = Vec::with_capacity(3 * client_hello.len());
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        let mut deframer = Deframer::default();
        let mut count = 0;
        let mut end = 0;

        while let Some(result) = deframer.deframe(&mut buffer) {
            let Deframed { message, bounds } = result.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
            end = bounds.end;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, end);
    }
}
