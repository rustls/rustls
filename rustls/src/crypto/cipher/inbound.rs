use core::ops::{Deref, DerefMut, Range};

use super::{EncodedMessage, Payload};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;

impl<'a> EncodedMessage<InboundOpaque<'a>> {
    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// [`EncodedMessage<InboundOpaque>`] should be decrypted into a
    /// [`EncodedMessage<Payload<'_>>`] using a [`MessageDecrypter`][super::MessageDecrypter].
    pub fn into_plain_message(self) -> EncodedMessage<Payload<'a>> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: Payload::Borrowed(self.payload.into_inner()),
        }
    }

    /// Force conversion into a plaintext message.
    ///
    /// `range` restricts the resulting message: this function panics if it is out of range for
    /// the underlying message payload.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// [`EncodedMessage<InboundOpaque>`] should be decrypted into a
    /// [`EncodedMessage<Payload<'_>>`] using a [`MessageDecrypter`][super::MessageDecrypter].
    pub fn into_plain_message_range(self, range: Range<usize>) -> EncodedMessage<Payload<'a>> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: Payload::Borrowed(&self.payload.into_inner()[range]),
        }
    }

    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<EncodedMessage<Payload<'a>>, Error> {
        let payload = &mut self.payload;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.typ = unpad_tls13_payload(payload);
        if self.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.version = ProtocolVersion::TLSv1_3;
        Ok(self.into_plain_message())
    }
}

/// A borrowed payload buffer.
#[expect(clippy::exhaustive_structs)]
pub struct InboundOpaque<'a>(pub &'a mut [u8]);

impl Deref for InboundOpaque<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for InboundOpaque<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a> InboundOpaque<'a> {
    /// Truncate the payload to `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }

        self.0 = core::mem::take(&mut self.0)
            .split_at_mut(len)
            .0;
    }

    pub(crate) fn into_inner(self) -> &'a mut [u8] {
        self.0
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }

        let len = self.len();
        let last = self[len - 1];
        self.truncate(len - 1);
        Some(last)
    }
}

/// Decode a TLS1.3 `TLSInnerPayloadtext` encoding.
///
/// `p` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13_payload(p: &mut InboundOpaque<'_>) -> ContentType {
    loop {
        match p.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}
