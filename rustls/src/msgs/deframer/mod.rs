use core::mem;
use core::ops::Range;

use super::{HEADER_SIZE, read_opaque_message_header};
use crate::crypto::cipher::{EncodedMessage, InboundOpaque, MessageError};
use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::Reader;

mod buffers;
pub(crate) use buffers::{Delocator, Locator, TlsInputBuffer, VecInput};

mod handshake;
pub(crate) use handshake::{HandshakeAlignedProof, HandshakeDeframer};

/// A deframer of TLS wire messages.
///
/// Returns `Some(Ok(_))` containing each [`EncodedMessage<InboundOpaque<'_>>`] deframed
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
    processed: usize,
}

impl<'a> DeframerIter<'a> {
    /// Make a new `DeframerIter`
    pub(crate) fn new(buf: &'a mut [u8], processed: usize) -> Self {
        Self { buf, processed }
    }
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<(EncodedMessage<InboundOpaque<'a>>, Range<usize>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut reader = Reader::new(&mut self.buf);

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
        let end = HEADER_SIZE + len as usize; // relative to start of `buf`
        let (message, remainder) = mem::take(&mut self.buf).split_at_mut_checked(end)?;
        self.buf = remainder;
        let bounds = self.processed..self.processed + end;
        self.processed += end;

        Some(Ok((
            EncodedMessage {
                typ,
                version,
                payload: InboundOpaque(&mut message[HEADER_SIZE..]),
            },
            bounds,
        )))
    }
}

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut iter = DeframerIter::new(&mut buf, 0);

    for message in iter.by_ref() {
        if message.is_err() {
            break;
        }
    }

    assert!(iter.processed <= buf.len());
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::enums::ContentType;

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(
            DeframerIter::new(&mut [], 0)
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16], 0)
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03], 0)
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03], 0)
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00], 0)
                .next()
                .is_none()
        );
        assert!(
            DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00, 0x01], 0)
                .next()
                .is_none()
        );
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new(&mut buffer, 0);
        let (message, bounds) = iter.next().unwrap().unwrap();
        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 6);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];

        let mut iter = DeframerIter::new(&mut buffer, 0);
        let (message, bounds) = iter.next().unwrap().unwrap();
        assert_eq!(message.typ, ContentType::Handshake);
        assert_eq!(bounds.end, 6);

        let (message, bounds) = iter.next().unwrap().unwrap();
        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 12);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
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
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
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
        let mut iter = DeframerIter::new(&mut buffer, 0);
        let mut count = 0;

        let mut end = 0;
        for result in iter.by_ref() {
            let (message, bounds) = result.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
            end = bounds.end;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, end);
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
