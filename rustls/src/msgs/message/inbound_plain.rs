use crate::{ContentType, ProtocolVersion};

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This inbound type borrows its decrypted payload from a `[MessageDeframer]`.
/// It results from decryption.
#[derive(Debug)]
pub struct InboundPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl InboundPlainMessage<'_> {
    /// Returns true if the payload is a CCS message.
    ///
    /// We passthrough ChangeCipherSpec messages in the deframer without decrypting them.
    /// Note: this is prior to the record layer, so is unencrypted. See
    /// third paragraph of section 5 in RFC8446.
    pub(crate) fn is_valid_ccs(&self) -> bool {
        self.typ == ContentType::ChangeCipherSpec && self.payload == [0x01]
    }

    #[cfg(test)]
    pub(crate) fn into_owned(self) -> super::PlainMessage {
        super::PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: crate::msgs::base::Payload::Owned(self.payload.to_vec()),
        }
    }
}
