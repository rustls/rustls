use alloc::vec::Vec;
use core::ops::Range;
use core::slice::SliceIndex;
use std::io;

use super::base::Payload;
use super::codec::Codec;
use super::message::PlainMessage;
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::codec;
use crate::msgs::message::{MessageError, OpaqueMessage};
use crate::record_layer::{Decrypted, RecordLayer};

/// This deframer works to reconstruct TLS messages from a stream of arbitrary-sized reads.
///
/// It buffers incoming data into a `Vec` through `read()`, and returns messages through `pop()`.
/// QUIC connections will call `push()` to append handshake payload data directly.
#[derive(Default)]
pub struct MessageDeframer {
    /// Set if the peer is not talking TLS, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    last_error: Option<Error>,

    /// If we're in the middle of joining a handshake payload, this is the metadata.
    joining_hs: Option<HandshakePayloadMeta>,
}

impl MessageDeframer {
    /// Return any decrypted messages that the deframer has been able to parse.
    ///
    /// Returns an `Error` if the deframer failed to parse some message contents or if decryption
    /// failed, `Ok(None)` if no full message is buffered or if trial decryption failed, and
    /// `Ok(Some(_))` if a valid message was found and decrypted successfully.
    pub fn pop(
        &mut self,
        record_layer: &mut RecordLayer,
        negotiated_version: Option<ProtocolVersion>,
        buffer: &mut DeframerSliceBuffer,
    ) -> Result<Option<Deframed>, Error> {
        if let Some(last_err) = self.last_error.clone() {
            return Err(last_err);
        } else if buffer.is_empty() {
            return Ok(None);
        }

        // We loop over records we've received but not processed yet.
        // For records that decrypt as `Handshake`, we keep the current state of the joined
        // handshake message payload in `self.joining_hs`, appending to it as we see records.
        let expected_len = loop {
            let start = match &self.joining_hs {
                Some(meta) => {
                    match meta.expected_len {
                        // We're joining a handshake payload, and we've seen the full payload.
                        Some(len) if len <= meta.payload.len() => break len,
                        // Not enough data, and we can't parse any more out of the buffer (QUIC).
                        _ if meta.quic => return Ok(None),
                        // Try parsing some more of the encrypted buffered data.
                        _ => meta.message.end,
                    }
                }
                None => 0,
            };

            // Does our `buf` contain a full message?  It does if it is big enough to
            // contain a header, and that header has a length which falls within `buf`.
            // If so, deframe it and place the message onto the frames output queue.
            let mut rd = codec::Reader::init(buffer.filled_get(start..));
            let m = match OpaqueMessage::read(&mut rd) {
                Ok(m) => m,
                Err(msg_err) => {
                    let err_kind = match msg_err {
                        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                            return Ok(None)
                        }
                        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                        MessageError::UnknownProtocolVersion => {
                            InvalidMessage::UnknownProtocolVersion
                        }
                    };

                    return Err(self.set_err(err_kind));
                }
            };

            // Return CCS messages and early plaintext alerts immediately without decrypting.
            let end = start + rd.used();
            let version_is_tls13 = matches!(negotiated_version, Some(ProtocolVersion::TLSv1_3));
            let allowed_plaintext = match m.typ {
                // CCS messages are always plaintext.
                ContentType::ChangeCipherSpec => true,
                // Alerts are allowed to be plaintext if-and-only-if:
                // * The negotiated protocol version is TLS 1.3. - In TLS 1.2 it is unambiguous when
                //   keying changes based on the CCS message. Only TLS 1.3 requires these heuristics.
                // * We have not yet decrypted any messages from the peer - if we have we don't
                //   expect any plaintext.
                // * The payload size is indicative of a plaintext alert message.
                ContentType::Alert
                    if version_is_tls13
                        && !record_layer.has_decrypted()
                        && m.payload().len() <= 2 =>
                {
                    true
                }
                // In other circumstances, we expect all messages to be encrypted.
                _ => false,
            };
            if self.joining_hs.is_none() && allowed_plaintext {
                // This is unencrypted. We check the contents later.
                buffer.queue_discard(end);
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message: m.into_plain_message(),
                }));
            }

            // Decrypt the encrypted message (if necessary).
            let msg = match record_layer.decrypt_incoming(m) {
                Ok(Some(decrypted)) => {
                    let Decrypted {
                        want_close_before_decrypt,
                        plaintext,
                    } = decrypted;
                    debug_assert!(!want_close_before_decrypt);
                    plaintext
                }
                // This was rejected early data, discard it. If we currently have a handshake
                // payload in progress, this counts as interleaved, so we error out.
                Ok(None) if self.joining_hs.is_some() => {
                    return Err(self.set_err(
                        PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage,
                    ));
                }
                Ok(None) => {
                    buffer.queue_discard(end);
                    continue;
                }
                Err(e) => return Err(e),
            };

            if self.joining_hs.is_some() && msg.typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(self.set_err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage));
            }

            // If it's not a handshake message, just return it -- no joining necessary.
            if msg.typ != ContentType::Handshake {
                let end = start + rd.used();
                buffer.queue_discard(end);
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message: msg,
                }));
            }

            // If we don't know the payload size yet or if the payload size is larger
            // than the currently buffered payload, we need to wait for more data.
            match self.append_hs::<_, false>(msg.version, &msg.payload.0, end, buffer)? {
                HandshakePayloadState::Blocked => return Ok(None),
                HandshakePayloadState::Complete(len) => break len,
                HandshakePayloadState::Continue => continue,
            }
        };

        let meta = self.joining_hs.as_mut().unwrap(); // safe after calling `append_hs()`

        // We can now wrap the complete handshake payload in a `PlainMessage`, to be returned.
        let message = PlainMessage {
            typ: ContentType::Handshake,
            version: meta.version,
            payload: Payload::new(
                buffer.filled_get(meta.payload.start..meta.payload.start + expected_len),
            ),
        };

        // But before we return, update the `joining_hs` state to skip past this payload.
        if meta.payload.len() > expected_len {
            // If we have another (beginning of) a handshake payload left in the buffer, update
            // the payload start to point past the payload we're about to yield, and update the
            // `expected_len` to match the state of that remaining payload.
            meta.payload.start += expected_len;
            meta.expected_len =
                payload_size(buffer.filled_get(meta.payload.start..meta.payload.end))?;
        } else {
            // Otherwise, we've yielded the last handshake payload in the buffer, so we can
            // discard all of the bytes that we're previously buffered as handshake data.
            let end = meta.message.end;
            self.joining_hs = None;
            buffer.queue_discard(end);
        }

        Ok(Some(Deframed {
            want_close_before_decrypt: false,
            aligned: self.joining_hs.is_none(),
            trial_decryption_finished: true,
            message,
        }))
    }

    /// Fuses this deframer's error and returns the set value.
    ///
    /// Any future calls to `pop` will return `err` again.
    fn set_err(&mut self, err: impl Into<Error>) -> Error {
        let err = err.into();
        self.last_error = Some(err.clone());
        err
    }

    /// Allow pushing handshake messages directly into the buffer.
    pub(crate) fn push(
        &mut self,
        version: ProtocolVersion,
        payload: &[u8],
        buffer: &mut DeframerVecBuffer,
    ) -> Result<(), Error> {
        if !buffer.is_empty() && self.joining_hs.is_none() {
            return Err(Error::General(
                "cannot push QUIC messages into unrelated connection".into(),
            ));
        } else if let Err(err) = buffer.prepare_read(self.joining_hs.is_some()) {
            return Err(Error::General(err.into()));
        }

        let end = buffer.len() + payload.len();
        self.append_hs::<_, true>(version, payload, end, buffer)?;
        Ok(())
    }

    /// Write the handshake message contents into the buffer and update the metadata.
    ///
    /// Returns true if a complete message is found.
    fn append_hs<T: DeframerBuffer<QUIC>, const QUIC: bool>(
        &mut self,
        version: ProtocolVersion,
        payload: &[u8],
        end: usize,
        buffer: &mut T,
    ) -> Result<HandshakePayloadState, Error> {
        let meta = match &mut self.joining_hs {
            Some(meta) => {
                debug_assert_eq!(meta.quic, QUIC);

                // We're joining a handshake message to the previous one here.
                // Write it into the buffer and update the metadata.

                DeframerBuffer::<QUIC>::copy(buffer, payload, meta.payload.end);
                meta.message.end = end;
                meta.payload.end += payload.len();

                // If we haven't parsed the payload size yet, try to do so now.
                if meta.expected_len.is_none() {
                    meta.expected_len =
                        payload_size(buffer.filled_get(meta.payload.start..meta.payload.end))?;
                }

                meta
            }
            None => {
                // We've found a new handshake message here.
                // Write it into the buffer and create the metadata.

                let expected_len = payload_size(payload)?;
                DeframerBuffer::<QUIC>::copy(buffer, payload, 0);
                self.joining_hs
                    .insert(HandshakePayloadMeta {
                        message: Range { start: 0, end },
                        payload: Range {
                            start: 0,
                            end: payload.len(),
                        },
                        version,
                        expected_len,
                        quic: QUIC,
                    })
            }
        };

        Ok(match meta.expected_len {
            Some(len) if len <= meta.payload.len() => HandshakePayloadState::Complete(len),
            _ => match buffer.len() > meta.message.end {
                true => HandshakePayloadState::Continue,
                false => HandshakePayloadState::Blocked,
            },
        })
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    #[allow(clippy::comparison_chain)]
    pub fn read(
        &mut self,
        rd: &mut dyn io::Read,
        buffer: &mut DeframerVecBuffer,
    ) -> io::Result<usize> {
        if let Err(err) = buffer.prepare_read(self.joining_hs.is_some()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(buffer.unfilled())?;
        buffer.advance(new_bytes);
        Ok(new_bytes)
    }
}

#[derive(Default, Debug)]
pub struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,
}

impl DeframerVecBuffer {
    /// Borrows the initialized contents of this buffer and tracks pending discard operations via
    /// the `discard` reference
    pub fn borrow(&mut self) -> DeframerSliceBuffer {
        DeframerSliceBuffer::new(&mut self.buf[..self.used])
    }

    /// Returns true if there are messages for the caller to process
    pub fn has_pending(&self) -> bool {
        !self.is_empty()
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => OpaqueMessage::MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `OpaqueMessage::MAX_WIRE_SIZE`),
        // make sure to reduce the buffer size again (large messages should be rare).
        // Also, reduce the buffer size if there are neither full nor partial messages in it,
        // which usually means that the other side suspended sending data.
        let need_capacity = Ord::min(allow_max, self.used + READ_SIZE);
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.used == 0 || self.buf.len() > allow_max {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        Ok(())
    }

    /// Discard `taken` bytes from the start of our buffer.
    pub fn discard(&mut self, taken: usize) {
        #[allow(clippy::comparison_chain)]
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf
                .copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken == self.used {
            self.used = 0;
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.used..]
    }
}

impl FilledDeframerBuffer for DeframerVecBuffer {
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl DeframerBuffer<true> for DeframerVecBuffer {
    fn copy(&mut self, src: &[u8], at: usize) {
        copy_into_buffer(self.unfilled(), src, at);
        self.advance(src.len());
    }
}

impl DeframerBuffer<false> for DeframerVecBuffer {
    fn copy(&mut self, src: &[u8], at: usize) {
        self.borrow().copy(src, at)
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
pub struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

impl<'a> DeframerSliceBuffer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    /// Returns the number of bytes that need to be discarded
    pub fn pending_discard(&self) -> usize {
        self.discard
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FilledDeframerBuffer for DeframerSliceBuffer<'_> {
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard..]
    }

    fn filled(&self) -> &[u8] {
        &self.buf[self.discard..]
    }
}

impl DeframerBuffer<false> for DeframerSliceBuffer<'_> {
    fn copy(&mut self, src: &[u8], at: usize) {
        copy_into_buffer(self.filled_mut(), src, at)
    }
}

trait DeframerBuffer<const QUIC: bool>: FilledDeframerBuffer {
    /// Copies from the `src` buffer into this buffer at the requested index
    ///
    /// If `QUIC` is true the data will be copied into the *un*filled section of the buffer
    ///
    /// If `QUIC` is false the data will be copied into the filled section of the buffer
    fn copy(&mut self, src: &[u8], at: usize);
}

fn copy_into_buffer(buf: &mut [u8], src: &[u8], at: usize) {
    buf[at..at + src.len()].copy_from_slice(src);
}

trait FilledDeframerBuffer {
    fn filled_mut(&mut self) -> &mut [u8];

    fn filled_get<I>(&self, index: I) -> &I::Output
    where
        I: SliceIndex<[u8]>,
    {
        self.filled().get(index).unwrap()
    }

    fn len(&self) -> usize {
        self.filled().len()
    }

    fn filled(&self) -> &[u8];
}

enum HandshakePayloadState {
    /// Waiting for more data.
    Blocked,
    /// We have a complete handshake message.
    Complete(usize),
    /// More records available for processing.
    Continue,
}

struct HandshakePayloadMeta {
    /// The range of bytes from the deframer buffer that contains data processed so far.
    ///
    /// This will need to be discarded as the last of the handshake message is `pop()`ped.
    message: Range<usize>,
    /// The range of bytes from the deframer buffer that contains payload.
    payload: Range<usize>,
    /// The protocol version as found in the decrypted handshake message.
    version: ProtocolVersion,
    /// The expected size of the handshake payload, if available.
    ///
    /// If the received payload exceeds 4 bytes (the handshake payload header), we update
    /// `expected_len` to contain the payload length as advertised (at most 16_777_215 bytes).
    expected_len: Option<usize>,
    /// True if this is a QUIC handshake message.
    ///
    /// In the case of QUIC, we get a plaintext handshake data directly from the CRYPTO stream,
    /// so there's no need to unwrap and decrypt the outer TLS record. This is implemented
    /// by directly calling `MessageDeframer::push()` from the connection.
    quic: bool,
}

/// Determine the expected length of the payload as advertised in the header.
///
/// Returns `Err` if the advertised length is larger than what we want to accept
/// (`MAX_HANDSHAKE_SIZE`), `Ok(None)` if the buffer is too small to contain a complete header,
/// and `Ok(Some(len))` otherwise.
fn payload_size(buf: &[u8]) -> Result<Option<usize>, Error> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    let (header, _) = buf.split_at(HEADER_SIZE);
    match codec::u24::read_bytes(&header[1..]) {
        Ok(len) if len.0 > MAX_HANDSHAKE_SIZE => Err(Error::InvalidMessage(
            InvalidMessage::HandshakePayloadTooLarge,
        )),
        Ok(len) => Ok(Some(HEADER_SIZE + usize::from(len))),
        _ => Ok(None),
    }
}

#[derive(Debug)]
pub struct Deframed {
    pub(crate) want_close_before_decrypt: bool,
    pub(crate) aligned: bool,
    pub(crate) trial_decryption_finished: bool,
    pub message: PlainMessage,
}

const HEADER_SIZE: usize = 1 + 3;

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

const READ_SIZE: usize = 4096;

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::vec;

    use crate::msgs::message::Message;

    use super::*;

    #[test]
    fn check_incremental() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_incremental_2() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());
        input_whole_incremental(&mut d, SECOND_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(d.has_pending());
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), d.input_bytes(FIRST_MESSAGE));
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole_2() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), d.input_bytes(FIRST_MESSAGE));
        assert_len(SECOND_MESSAGE.len(), d.input_bytes(SECOND_MESSAGE));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            d.input_bytes_concat(FIRST_MESSAGE, SECOND_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read_shortest_first() {
        let mut d = BufferedDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            d.input_bytes_concat(SECOND_MESSAGE, FIRST_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_second(&mut d, &mut rl);
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_incremental_with_nonfatal_read_error() {
        let mut d = BufferedDeframer::default();
        assert_len(3, d.input_bytes(&FIRST_MESSAGE[..3]));
        input_error(&mut d);
        assert_len(FIRST_MESSAGE.len() - 3, d.input_bytes(&FIRST_MESSAGE[3..]));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_contenttype_errors() {
        let mut d = BufferedDeframer::default();
        assert_len(
            INVALID_CONTENTTYPE_MESSAGE.len(),
            d.input_bytes(INVALID_CONTENTTYPE_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, None).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidContentType)
        );
    }

    #[test]
    fn test_invalid_version_errors() {
        let mut d = BufferedDeframer::default();
        assert_len(
            INVALID_VERSION_MESSAGE.len(),
            d.input_bytes(INVALID_VERSION_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, None).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        );
    }

    #[test]
    fn test_invalid_length_errors() {
        let mut d = BufferedDeframer::default();
        assert_len(
            INVALID_LENGTH_MESSAGE.len(),
            d.input_bytes(INVALID_LENGTH_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, None).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn test_empty_applicationdata() {
        let mut d = BufferedDeframer::default();
        assert_len(
            EMPTY_APPLICATIONDATA_MESSAGE.len(),
            d.input_bytes(EMPTY_APPLICATIONDATA_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        let m = d
            .pop(&mut rl, None)
            .unwrap()
            .unwrap()
            .message;
        assert_eq!(m.typ, ContentType::ApplicationData);
        assert_eq!(m.payload.0.len(), 0);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_empty_errors() {
        let mut d = BufferedDeframer::default();
        assert_len(
            INVALID_EMPTY_MESSAGE.len(),
            d.input_bytes(INVALID_EMPTY_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, None).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
        // CorruptMessage has been fused
        assert_eq!(
            d.pop(&mut rl, None).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
    }

    #[test]
    fn test_limited_buffer() {
        const PAYLOAD_LEN: usize = 16_384;
        let mut message = Vec::with_capacity(16_389);
        message.push(0x17); // ApplicationData
        message.extend(&[0x03, 0x04]); // ProtocolVersion
        message.extend((PAYLOAD_LEN as u16).to_be_bytes()); // payload length
        message.extend(&[0; PAYLOAD_LEN]);

        let mut d = BufferedDeframer::default();
        assert_len(4096, d.input_bytes(&message));
        assert_len(4096, d.input_bytes(&message));
        assert_len(4096, d.input_bytes(&message));
        assert_len(4096, d.input_bytes(&message));
        assert_len(
            OpaqueMessage::MAX_WIRE_SIZE - 16_384,
            d.input_bytes(&message),
        );
        assert!(d.input_bytes(&message).is_err());
    }

    fn input_error(d: &mut BufferedDeframer) {
        let error = io::Error::from(io::ErrorKind::TimedOut);
        let mut rd = ErrorRead::new(error);
        d.read(&mut rd)
            .expect_err("error not propagated");
    }

    fn input_whole_incremental(d: &mut BufferedDeframer, bytes: &[u8]) {
        let before = d.buffer.len();

        for i in 0..bytes.len() {
            assert_len(1, d.input_bytes(&bytes[i..i + 1]));
            assert!(d.has_pending());
        }

        assert_eq!(before + bytes.len(), d.buffer.len());
    }

    fn pop_first(d: &mut BufferedDeframer, rl: &mut RecordLayer) {
        let m = d
            .pop(rl, None)
            .unwrap()
            .unwrap()
            .message;
        assert_eq!(m.typ, ContentType::Handshake);
        Message::try_from(m).unwrap();
    }

    fn pop_second(d: &mut BufferedDeframer, rl: &mut RecordLayer) {
        let m = d
            .pop(rl, None)
            .unwrap()
            .unwrap()
            .message;
        assert_eq!(m.typ, ContentType::Alert);
        Message::try_from(m).unwrap();
    }

    // buffered version to ease testing
    #[derive(Default)]
    struct BufferedDeframer {
        inner: MessageDeframer,
        buffer: DeframerVecBuffer,
    }

    impl BufferedDeframer {
        fn input_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut rd = io::Cursor::new(bytes);
            self.read(&mut rd)
        }

        fn input_bytes_concat(&mut self, bytes1: &[u8], bytes2: &[u8]) -> io::Result<usize> {
            let mut bytes = vec![0u8; bytes1.len() + bytes2.len()];
            bytes[..bytes1.len()].clone_from_slice(bytes1);
            bytes[bytes1.len()..].clone_from_slice(bytes2);
            let mut rd = io::Cursor::new(&bytes);
            self.read(&mut rd)
        }

        fn pop(
            &mut self,
            record_layer: &mut RecordLayer,
            negotiated_version: Option<ProtocolVersion>,
        ) -> Result<Option<Deframed>, Error> {
            let mut deframer_buffer = self.buffer.borrow();
            let res = self
                .inner
                .pop(record_layer, negotiated_version, &mut deframer_buffer);
            let discard = deframer_buffer.pending_discard();
            self.buffer.discard(discard);
            res
        }

        fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
            self.inner.read(rd, &mut self.buffer)
        }

        fn has_pending(&self) -> bool {
            self.buffer.has_pending()
        }
    }

    // grant access to the `MessageDeframer.last_error` field
    impl core::ops::Deref for BufferedDeframer {
        type Target = MessageDeframer;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    struct ErrorRead {
        error: Option<io::Error>,
    }

    impl ErrorRead {
        fn new(error: io::Error) -> Self {
            Self { error: Some(error) }
        }
    }

    impl io::Read for ErrorRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }

            let error = self.error.take().unwrap();
            Err(error)
        }
    }

    fn assert_len(want: usize, got: io::Result<usize>) {
        assert_eq!(Some(want), got.ok())
    }

    const FIRST_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.1.bin");
    const SECOND_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.2.bin");

    const EMPTY_APPLICATIONDATA_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-empty-applicationdata.bin");

    const INVALID_EMPTY_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-empty.bin");
    const INVALID_CONTENTTYPE_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-contenttype.bin");
    const INVALID_VERSION_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-version.bin");
    const INVALID_LENGTH_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-length.bin");
}
