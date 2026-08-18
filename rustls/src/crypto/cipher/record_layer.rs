use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::min;

use crate::crypto::cipher::{
    InboundOpaque, OutboundPlain, Record, RecordDecrypter, RecordEncrypter, encode_record_header,
};
use crate::error::Error;
use crate::msgs::{HEADER_SIZE, HandshakeAlignedProof};
use crate::tracing::trace;

/// Record layer that tracks encryption keys.
pub(crate) struct EncryptionState {
    record_encrypter: Option<Box<dyn RecordEncrypter>>,
    write_seq_max: u64,
    write_seq: u64,
}

impl EncryptionState {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            record_encrypter: None,
            write_seq_max: 0,
            write_seq: 0,
        }
    }

    /// Encrypt a TLS message, returning the fully-encoded record.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    ///
    /// The result including framing is appended to `output`.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: Record<OutboundPlain<'_>>,
        output: &mut Vec<u8>,
    ) {
        // Contents are fully overwritten below, so zeroing is pure cost.
        // A fresh buffer gets pre-zeroed memory straight from the allocator
        // while a reused one zeroes only what `resize` grows.
        let needed = HEADER_SIZE + self.encrypted_len(plain.payload.len());
        let start = output.len();
        output.resize(start + needed, 0);
        let written = self.encrypt_outgoing_into(plain, &mut output[start..]);
        debug_assert_eq!(
            written, needed,
            "RecordEncrypter::encrypt() returned wrong length"
        );
        output.truncate(start + written);
    }

    /// Encrypt a TLS message directly into `out`, returning the encoded
    /// record's length.
    ///
    /// The record, header included, is written to the front of `out`,
    /// which must be at least `HEADER_SIZE` plus
    /// [`Self::encrypted_len()`](Self::encrypted_len) bytes long.
    ///
    /// This function panics if the requisite keying material hasn't been
    /// established yet.
    pub(crate) fn encrypt_outgoing_into(
        &mut self,
        plain: Record<OutboundPlain<'_>>,
        out: &mut [u8],
    ) -> usize {
        assert!(self.pre_encrypt_action(0) != Some(PreEncryptAction::Refuse));
        let encrypter = self.record_encrypter.as_mut().unwrap();

        let seq = self.write_seq;
        self.write_seq += 1;

        #[cfg(debug_assertions)]
        let (out_ptr, out_len) = (out.as_ptr(), out.len());
        let encrypted = encrypter
            .encrypt(plain, seq, &mut out[HEADER_SIZE..])
            .unwrap();

        #[cfg(debug_assertions)]
        {
            // `RecordEncrypter::encrypt()` requires the returned payload to be
            // the written prefix of the passed-in buffer. Try to catch misbehaving
            // implementations in debug mode. In release builds a violation would corrupt
            // the sent stream.
            debug_assert_eq!(
                encrypted.payload.as_ptr(),
                out_ptr.wrapping_add(HEADER_SIZE)
            );
            debug_assert!(encrypted.payload.len() <= out_len - HEADER_SIZE);
        }

        let (typ, version, len) = (encrypted.typ, encrypted.version, encrypted.payload.len());
        debug_assert!(len <= usize::from(u16::MAX));
        out[..HEADER_SIZE].copy_from_slice(&encode_record_header(typ, version, len as u16));
        HEADER_SIZE + len
    }

    /// Set and start using the given `RecordEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_record_encrypter(
        &mut self,
        cipher: Box<dyn RecordEncrypter>,
        max_records: u64,
    ) {
        *self = Self {
            record_encrypter: Some(cipher),
            write_seq_max: min(SEQ_SOFT_LIMIT, max_records),
            write_seq: 0,
        };
    }

    /// Return a remedial action when we are near to encrypting too many messages.
    ///
    /// `add` is added to the current sequence number.  `add` as `0` means
    /// "the next message processed by `encrypt_outgoing`"
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> Option<PreEncryptAction> {
        match self.write_seq.saturating_add(add) {
            v if v == self.write_seq_max => Some(PreEncryptAction::RefreshOrClose),
            SEQ_HARD_LIMIT.. => Some(PreEncryptAction::Refuse),
            _ => None,
        }
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.record_encrypter
            .as_ref()
            .map(|enc| enc.encrypted_payload_len(payload_len))
            .unwrap_or_default()
    }

    /// Number of bytes added to a plaintext fragment by record protection.
    pub(crate) fn encrypted_record_overhead(&self) -> usize {
        self.encrypted_len(0)
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.record_encrypter.is_some()
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }
}

/// Record layer that tracks decryption keys.
pub(crate) struct DecryptionState {
    record_decrypter: Option<Box<dyn RecordDecrypter>>,
    read_seq: u64,
    has_decrypted: bool,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
}

impl DecryptionState {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            record_decrypter: None,
            read_seq: 0,
            has_decrypted: false,
            trial_decryption_len: None,
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: Record<InboundOpaque<'a>>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        let Some(decrypter) = &mut self.record_decrypter else {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_record(),
            }));
        };

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match decrypter.decrypt(encr, self.read_seq) {
            Ok(plaintext) => {
                self.read_seq += 1;
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Set and start using the given `RecordDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_record_decrypter(
        &mut self,
        cipher: Box<dyn RecordDecrypter>,
        _proof: &HandshakeAlignedProof,
    ) {
        self.record_decrypter = Some(cipher);
        self.read_seq = 0;
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `RecordDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_record_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn RecordDecrypter>,
        max_length: usize,
        _proof: &HandshakeAlignedProof,
    ) {
        self.record_decrypter = Some(cipher);
        self.read_seq = 0;
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_seq
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: Record<&'a [u8]>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PreEncryptAction {
    /// A `key_update` request should be sent ASAP.
    ///
    /// If that is not possible (for example, the connection is TLS1.2), a `close_notify`
    /// alert should be sent instead.
    RefreshOrClose,

    /// Do not call `encrypt_outgoing` further, it will panic rather than
    /// over-use the key.
    Refuse,
}

/// When to take action to avoid sequence space exhaustion.
///
/// This gives a margin in which any action can have an effect, prior to `SEQ_HARD_LIMIT`
/// being reached.
const SEQ_SOFT_LIMIT: u64 = u64::MAX - 0xffff;

/// When to refuse further encryptions.
const SEQ_HARD_LIMIT: u64 = u64::MAX - 1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::EncodableVersion;
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::Deframer;

    #[test]
    fn test_has_decrypted() {
        struct PassThroughDecrypter;
        impl RecordDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                record: Record<InboundOpaque<'a>>,
                _: u64,
            ) -> Result<Record<&'a [u8]>, Error> {
                Ok(record.into_plain_record())
            }
        }

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = DecryptionState::new();
        assert!(record_layer.record_decrypter.is_none());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Initializing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        let deframer = Deframer::default();
        record_layer
            .set_record_decrypter(Box::new(PassThroughDecrypter), &deframer.aligned().unwrap());
        assert!(record_layer.record_decrypter.is_some());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(Record::new(
                ContentType::Handshake,
                EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                InboundOpaque(&mut [0xC0, 0xFF, 0xEE]),
            ))
            .unwrap();
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer
            .set_record_decrypter(Box::new(PassThroughDecrypter), &deframer.aligned().unwrap());
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
