use core::mem;
use core::ops::Range;
use std::collections::VecDeque;

use crate::crypto::cipher::{EncodedMessage, InboundOpaque, MessageError};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::{Codec, Reader, U24};
use crate::msgs::{
    DTLS_12_HEADER_SIZE, DTLS_HANDSHAKE_HEADER_SIZE, DtlsHandshakeFragment, EpochAndSequence,
    HEADER_SIZE, MessageHeader, UnifiedHeader, read_opaque_message_header,
};

mod buffers;
#[cfg(test)]
mod dtls_test;
use buffers::Coalescer;
pub(crate) use buffers::{Delocator, Locator, SliceInput, TlsInputBuffer, VecInput};

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

    /// Most recent epoch and sequence number deprotected, if DTLS is in use.
    /// Used to reconstruct epochs and sequence numbers for DTLS 1.3.
    /// <https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.2>
    latest_epoch_and_sequence: EpochAndSequence,
}

impl Deframer {
    pub(crate) fn deframe<'a>(&mut self, buf: &'a mut [u8]) -> Option<Result<Deframed<'a>, Error>> {
        let unprocessed_buf = buf.get(self.processed..)?;

        let mut reader = Reader::new(unprocessed_buf);
        let (typ, version, epoch_and_sequence, len, header_size) = if unprocessed_buf.len() > 0
            && UnifiedHeader::is_unified_header(unprocessed_buf[0])
        {
            let (
                header_size,
                UnifiedHeader {
                    connection_id: _,
                    length,
                    epoch_and_sequence,
                },
            ) = match UnifiedHeader::read(&mut reader, self.latest_epoch_and_sequence) {
                Ok(header) => (header.encoded_length(), header),
                Err(err) => return Some(Err(err.into())),
            };

            // The 16 bit epoch was inferred based on the low bits in the header. If it matches the
            // current epoch, we assume it's from the current epoch. If we're wrong, the record will
            // fail to deprotect later.
            //
            // TODO(timg): If it's from an older epoch, we should discard it ([1]). This requires
            // cooperation from `ReceivePath` so that we seek past the record and can try deframing
            // other messages.
            //
            // TODO(timg): It's from a later epoch, we should buffer it and try again later after an
            // epoch change/rekey. That requires cooperation from `ReceivePath` so it can put the
            // message back in a `ChunkVecBuffer` somewhere.
            //
            // [1]: https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.1
            if epoch_and_sequence.epoch != self.latest_epoch_and_sequence.epoch {
                return Some(Err(Error::InvalidMessage(InvalidMessage::WrongEpoch)));
            }

            // If there's no length in the unified header, then assume the record occupies the
            // entirety of the provided buffer, which is in turn assumed to be a whole datagram.
            // TODO(timg): I don't have a test that exercises this because the send path/fragmenter
            // doesn't know how to omit length
            let length = length.unwrap_or_else(|| buf.len() as u16);

            (
                ContentType::Dtls13Ciphertext,
                ProtocolVersion::DTLSv1_3,
                Some(epoch_and_sequence),
                length,
                header_size,
            )
        } else {
            let MessageHeader {
                typ,
                version,
                epoch_and_sequence,
                len,
            } = match read_opaque_message_header(&mut reader) {
                Ok(header) => header,
                Err(err) => {
                    let err = match err {
                        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                            return None;
                        }
                        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                        MessageError::UnknownProtocolVersion => {
                            InvalidMessage::UnknownProtocolVersion
                        }
                    };
                    return Some(Err(err.into()));
                }
            };
            (
                typ,
                version,
                epoch_and_sequence,
                len,
                // If we're here, then there wasn't a unified header on the record, and so DTLS 1.2
                // and 1.3 records have the same header size.
                if version.is_datagram_tls() {
                    DTLS_12_HEADER_SIZE
                } else {
                    HEADER_SIZE
                },
            )
        };

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let end = self.processed + header_size + len as usize;
        let head = buf.get_mut(..end)?;
        // This bound, returned from the function, INCLUDES the TLS record header. However
        // message.payload DOES NOT, and starts at (possibly) the handshake header.
        let bounds = self.processed..end;
        self.processed = end;

        Some(Ok(Deframed {
            message: EncodedMessage {
                typ,
                version,
                payload: InboundOpaque(&mut head[bounds.start + header_size..]),
            },
            bounds,
            epoch_and_sequence,
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
    ///
    /// This function is for inputting TLS message fragments. Use [`Self::input_message_dtls`] for
    /// DTLS records containing handshake fragments.
    pub(crate) fn input_message(&mut self, msg: EncodedMessage<&'_ [u8]>, bounds: Range<usize>) {
        debug_assert_eq!(msg.typ, ContentType::Handshake);
        debug_assert!(!msg.version.is_datagram_tls());

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
            self.spans
                .push_back(FragmentSpan::new(msg.version, None, bounds));
            return;
        }

        // otherwise, we can expect `msg` to contain a handshake header introducing
        // a new message (and perhaps several of them.)
        for span in DissectHandshakeIter::new(msg, bounds) {
            self.spans.push_back(span);
        }
    }

    /// Input a DTLS record containing one or more handshake fragments so that they can be
    /// re-ordered and re-assembled by [`Self::coalesce_dtls`]. There should not be any trailing
    /// bytes on the message payload.
    ///
    /// `msg` is a parsed TLS record, which may contain one or more handshake messages, each
    /// starting with a handshake header.
    ///
    /// `bounds` is the position within the containing buffer of the record payload. That is, it
    /// begins at the start of the first handshake header.
    pub(crate) fn input_message_dtls(
        &mut self,
        msg: EncodedMessage<&'_ [u8]>,
        bounds: Range<usize>,
    ) -> Result<(), Error> {
        debug_assert!(msg.typ == ContentType::Handshake);
        debug_assert!(msg.version.is_datagram_tls());

        // Using DissectHandshakeIter wouldn't be appropriate here because parsing DTLS handshake
        // fragments is fallible: if there isn't enough room for a handshake fragment header, we
        // have a short read.
        let mut bound_start = bounds.start;
        let mut reader = Reader::new(msg.payload);
        while reader.any_left() {
            let handshake_fragment = DtlsHandshakeFragment::read(&mut reader)?;
            let fragment_len =
                DTLS_HANDSHAKE_HEADER_SIZE + handshake_fragment.fragment_length.0 as usize;
            self.spans.push_back(FragmentSpan {
                version: msg.version,
                size: Some(handshake_fragment.length.into()),
                bounds: bound_start..bound_start + fragment_len,
                dtls_fragment_fields: Some((
                    handshake_fragment.message_seq,
                    handshake_fragment.fragment_offset,
                    handshake_fragment.fragment_length,
                )),
                is_coalesced: false,
            });
            bound_start += fragment_len;
            if bound_start > bounds.end {
                return Err(Error::InvalidMessage(InvalidMessage::MessageTooLarge));
            }
        }

        Ok(())
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

    /// Coalesce the contents of `containing_buffer` into one or more complete DTLS handshake
    /// messages.
    ///
    /// `containing_buffer` is understood to contain some number of DTLS records containing
    /// handshake messages, i.e., a record header, then one or more handshake headers and payloads.
    /// Before calling this function, each of those records must have been parsed by
    /// [`Self::deframe`] and then input into this deframer with [`Self::input_message_dtls`].
    ///
    /// If `containing_buffer` contains all the fragments of a handshake message, then on return,
    /// the buffer will contain the coalesced (reassembled) handshake message, followed by any
    /// remaining uncoalesced fragments.
    ///
    /// If `containing_buffer` contains all the fragments of multiple handshake messages, then on
    /// return, the buffer will contain coalesced handshake messages, ordered by the handshake
    /// sequence number, not to be confused with the sequence number at the DTLS record layer.
    ///
    /// Coalesced handshake messages consist of the handshake header of the first fragment,
    /// concatenated with just the handshake payloads of subsequent fragments. Coalesced messages
    /// include `DTLSHandshake.{message_seq, fragment_offset, fragment_length}` values but these are
    /// no longer meaningful since the message is coalesced. See [1], [2] for details of the
    /// `DTLSHandshake` structure.
    ///
    /// After calling this method, callers should call [`Self::complete_span`] to find out the
    /// position of the next coalesced handshake message, if any, and then [`Self::message`] to
    /// obtain it.
    ///
    /// More fragments may then be added into the deframer by calling [`Self::deframe`] and
    /// [`Self::input_message_dtls`] again.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
    /// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.2
    pub(crate) fn coalesce_dtls(&mut self, containing_buffer: &mut [u8]) {
        // Sort the spans by sequence number and fragment offset so we can reorder
        // containing_buffer.
        self.spans
            .make_contiguous()
            .sort_by(|left, right| {
                // Unwrap safety: this method should only be used for DTLS, in which case these
                // fields are always set
                let (left_seq, left_fragment_offset, _) = left.dtls_fragment_fields.unwrap();
                let (right_seq, right_fragment_offset, _) = right.dtls_fragment_fields.unwrap();

                (left_seq, left_fragment_offset).cmp(&(right_seq, right_fragment_offset))
            });

        // Scratch buffer to hold fragments while we slide the rest of `containing_buffer` around.
        // 4096 is chosen because it's _probably_ bigger than the PMTU anyone will use and thus
        // _probably_ big enough for any DTLS fragment we'll encounter.
        // TODO(timg): We shouldn't make guesses about PMTU here. Make this a smaller buffer, say
        // 1024 bytes, and then do the copy-aside-and-slide-containing-buffer dance one chunk at
        // a time.
        let mut scratch = [0u8; 4096];

        // Which handshake message are we reassembling into?
        let mut first_fragment_index = 0;
        // How much of the current handshake message have we reassembled (excluding handshake
        // headers)?
        let mut current_message_len = 0;
        // How many bytes of handshake message have we reassembled, total, including the first
        // fragment's handshake header but excluding any headers from subsequent messages?
        // Equivalentlty, what position of containing_buffer are we copying into?
        let mut reassembled_len = 0;

        // We can't idiomatically iterate over self.spans because we need to mutably borrow elements
        // besides the current one in the loop body.
        for index in 0..self.spans.len() {
            let (current_seq, U24(current_fragment_offset), U24(current_fragment_length)) = self
                .spans[index]
                .dtls_fragment_fields
                .unwrap();

            let (coalesce_into_seq, coalsce_into_offset, _) = self.spans[first_fragment_index]
                .dtls_fragment_fields
                .unwrap();

            let is_first_fragment = index == 0 || current_seq > coalesce_into_seq;
            if is_first_fragment {
                first_fragment_index = index;
                current_message_len = 0;
            }

            if current_fragment_offset > current_message_len {
                // We are still missing some fragments and can't yet reassemble this handshake.
                break;
            }

            // Figure out what portion of the current handshake fragment we'll copy aside and back
            // into containing_buffer.
            let mut copy_bounds = self.spans[index].bounds.clone();

            // Each span's bounds include only the handshake header and the handshake message
            // fragment. We retain the handshake header for the first fragment of each handshake
            // message, but skip it for subsequent fragments. As a result, after decoalescing,
            // we'll have what appears to be a single handshake message.
            if !is_first_fragment {
                copy_bounds.start += self.spans[index]
                    .version
                    .handshake_header_size();
            }

            // DTLS handshake fragments may overlap, so work out what portion of this span to append
            let overlap = current_message_len - current_fragment_offset;
            copy_bounds.start += overlap as usize;
            current_message_len += current_fragment_length - overlap;

            if !is_first_fragment {
                // Grow the fragment we coalesce into and mark the fragment we coalesced from for
                // pruning.
                self.spans[first_fragment_index]
                    .bounds
                    .end += copy_bounds.len();
                self.spans[first_fragment_index].dtls_fragment_fields = Some((
                    coalesce_into_seq,
                    coalsce_into_offset,
                    U24(current_message_len),
                ));
                self.spans[index].is_coalesced = true;
            }

            // Copy the fragment we want into scratch.
            scratch[0..copy_bounds.len()].copy_from_slice(&containing_buffer[copy_bounds.clone()]);

            // If there is any portion of containing_buffer between the fragment we coalesce into
            // and the fragment we are copying, shift that portion to the right to make room. The
            // span might be preceded by a record header, but we don't need to preserve it.
            let curr_fragment_start = self.spans[index].bounds.start;
            if curr_fragment_start > reassembled_len {
                let shifted_range = reassembled_len..curr_fragment_start;
                let dest = reassembled_len + copy_bounds.len();
                containing_buffer.copy_within(shifted_range.clone(), dest);

                // Fix up bounds of all spans in the portion that got shifted.
                for span in &mut self.spans {
                    if shifted_range.contains(&span.bounds.start)
                        && shifted_range.contains(&(span.bounds.end - 1))
                    {
                        span.bounds.start += copy_bounds.len();
                        span.bounds.end += copy_bounds.len();
                    }
                }
            }

            // Copy the span we want from scratch back into containing_buffer
            let destination_bounds = reassembled_len..reassembled_len + copy_bounds.len();
            containing_buffer[destination_bounds.clone()]
                .copy_from_slice(&scratch[0..copy_bounds.len()]);

            if is_first_fragment {
                // We may have copied the first fragment to a new position, so fix up its bounds
                self.spans[index].bounds = destination_bounds;
            }

            reassembled_len += copy_bounds.len();
        }

        // Remove spans which have been coalesced into other spans so we don't have to deal with
        // them later. Iterate in reverse so we can use Vec::remove without invalidating indices.
        for index in (0..self.spans.len()).rev() {
            if self.spans[index].is_coalesced {
                self.spans.remove(index);
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

    /// Increment the sequence number. Should only be called after a record has
    /// been successfully deprotected. Sequence is ignored unless DTLS is in
    /// use.
    pub(crate) fn increment_sequence(&mut self) {
        self.latest_epoch_and_sequence
            .add_sequence_increment(1);
    }

    /// Set the epoch.
    /// Epoch is ignored unless DTLS is in use.
    #[cfg(test)]
    pub(crate) fn set_epoch(&mut self, epoch: u16) {
        self.latest_epoch_and_sequence.epoch = epoch;
    }

    /// Set the sequence. Used by tests. Sequence is ignored unless DTLS is in
    /// use.
    #[cfg(test)]
    pub(crate) fn set_sequence(&mut self, sequence: u64) {
        self.latest_epoch_and_sequence
            .sequence_number = crate::msgs::U48(sequence);
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
            latest_epoch_and_sequence: EpochAndSequence::new(0, 0),
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
        debug_assert!(!msg.version.is_datagram_tls());
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
        let Some((header, rest)) = all.split_at_checked(self.version.handshake_header_size())
        else {
            return Some(FragmentSpan::new(
                self.version,
                None,
                mem::take(&mut self.bounds),
            ));
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
        Some(FragmentSpan::new(self.version, Some(size), bounds))
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

    /// If using DTLS, the handshake message fragment will contain message_seq, fragment_offset and
    /// fragment_length
    dtls_fragment_fields: Option<(u16, U24, U24)>,

    /// Whether this span has been coalesced into another and thus can be ignored or removed. Only
    /// relevant when coalescing DTLS fragments.
    is_coalesced: bool,
}

impl FragmentSpan {
    /// Create a new fragment span.
    fn new(version: ProtocolVersion, size: Option<usize>, bounds: Range<usize>) -> Self {
        Self {
            version,
            size,
            bounds,
            dtls_fragment_fields: None,
            is_coalesced: false,
        }
    }

    /// A `FragmentSpan` is "complete" if its size is known, and its
    /// bounds exactly encompasses one handshake message.
    fn is_complete(&self) -> bool {
        match self.size {
            Some(sz) => sz + self.version.handshake_header_size() == self.bounds.len(),
            None => false,
        }
    }
}

pub(crate) struct Deframed<'a> {
    pub(crate) message: EncodedMessage<InboundOpaque<'a>>,
    pub(crate) bounds: Range<usize>,
    pub(crate) epoch_and_sequence: Option<EpochAndSequence>,
}

/// Proof type that the handshake deframer is aligned.
///
/// See [`Deframer::aligned()`] for more details.
#[must_use]
#[derive(Clone, Copy)]
pub(crate) struct HandshakeAlignedProof(());

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
            let Deframed {
                message, bounds, ..
            } = result.unwrap();
            let plain = message.into_plain_message();

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

        let Deframed {
            message, bounds, ..
        } = deframer
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

        let Deframed {
            message, bounds, ..
        } = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::Handshake);
        assert_eq!(bounds.end, 6);

        let Deframed {
            message, bounds, ..
        } = deframer
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
            let Deframed {
                message, bounds, ..
            } = result.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
            end = bounds.end;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, end);
    }
}
