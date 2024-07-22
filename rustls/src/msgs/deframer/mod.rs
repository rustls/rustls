use alloc::vec::Vec;
use core::mem;
#[cfg(feature = "std")]
use core::ops::Range;
use core::slice::SliceIndex;
#[cfg(feature = "std")]
use std::io;

use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::Reader;
#[cfg(feature = "std")]
use crate::msgs::message::MAX_WIRE_SIZE;
use crate::msgs::message::{
    read_opaque_message_header, InboundOpaqueMessage, MessageError, HEADER_SIZE,
};

pub(crate) mod buffers;
pub(crate) mod handshake;

/// A deframer of TLS wire messages.
///
/// Returns `Some(Ok(_))` containing each `InboundOpaqueMessage` deframed
/// from the buffer.
///
/// Returns `None` if no further messages can be deframed from the
/// buffer.  More data is required for further progress.
///
/// Returns `Some(Err(_))` if the peer is not talking TLS, but some
/// other protocol.  The caller should abort the connection, because
/// the deframer cannot recover.
///
/// Call `bytes_consumed()` to learn how many bytes the iterator has
/// processed from the front of the original buffer.  This is only updated
/// when a message is successfully deframed (ie. `Some(Ok(_))` is returned).
pub(crate) struct DeframerIter<'a> {
    buf: &'a mut [u8],
    consumed: usize,
}

impl<'a> DeframerIter<'a> {
    /// Make a new `DeframerIter`
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, consumed: 0 }
    }

    /// How many bytes were processed successfully from the front
    /// of the buffer passed to `new()`?
    pub(crate) fn bytes_consumed(&self) -> usize {
        self.consumed
    }
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<InboundOpaqueMessage<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut reader = Reader::init(self.buf);

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

        let end = HEADER_SIZE + len as usize;

        self.buf.get(HEADER_SIZE..end)?;

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(end);
        self.buf = remainder;
        self.consumed += end;

        Some(Ok(InboundOpaqueMessage::new(
            typ,
            version,
            &mut consumed[HEADER_SIZE..],
        )))
    }
}

#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,

    pub(crate) processed: usize,
}

impl DeframerVecBuffer {
    /// Discard `taken` bytes from the start of our buffer.
    pub(crate) fn discard(&mut self, taken: usize) {
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
            self.processed = self.processed.saturating_sub(taken);
        } else if taken == self.used {
            self.used = 0;
            self.processed = 0;
        }
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Read some bytes from `rd`, and add them to the buffer.
    pub(crate) fn read(&mut self, rd: &mut dyn io::Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(self.unfilled())?;
        self.advance(new_bytes);
        Ok(new_bytes)
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
            false => MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `OutboundOpaqueMessage::MAX_WIRE_SIZE`),
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

    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.used..]
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Range<usize> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }
}

#[cfg(feature = "std")]
impl FilledDeframerBuffer for DeframerVecBuffer {
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub(crate) struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

impl<'a> DeframerSliceBuffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub(crate) fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    pub(crate) fn pending_discard(&self) -> usize {
        self.discard
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

pub(crate) trait FilledDeframerBuffer {
    fn filled_mut(&mut self) -> &mut [u8];

    fn filled_get<I>(&self, index: I) -> &I::Output
    where
        I: SliceIndex<[u8]>,
    {
        self.filled().get(index).unwrap()
    }

    fn filled(&self) -> &[u8];
}

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut iter = DeframerIter::new(&mut buf);

    for message in iter.by_ref() {
        if message.is_err() {
            break;
        }
    }

    assert!(iter.bytes_consumed() <= buf.len());
}

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

#[cfg(feature = "std")]
const READ_SIZE: usize = 4096;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::prelude::v1::*;

    use super::*;
    use crate::ContentType;

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(DeframerIter::new(&mut [])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00, 0x01])
            .next()
            .is_none());
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 6);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(iter.next().unwrap().unwrap().typ, ContentType::Handshake);
        assert_eq!(iter.bytes_consumed(), 6);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 12);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
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
        let mut iter = DeframerIter::new(&mut buffer);
        let mut count = 0;

        for message in iter.by_ref() {
            let message = message.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, iter.bytes_consumed());
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
