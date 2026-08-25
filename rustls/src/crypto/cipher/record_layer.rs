use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::min;

use crate::common_state::Side;
use crate::crypto::cipher::antireplay::ReplayWindow;
use crate::crypto::cipher::{
    EncodedMessage, EncodingContext, InboundOpaque, MessageDecrypter, MessageEncrypter,
    OutboundPlain, RecordSequenceNumberEncrypter, encode_record_header,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::{EncrypterDecrypterPurpose, Epoch, HandshakeAlignedProof, Reader, UnifiedHeader};
use crate::tracing::trace;

/// Record layer that tracks encryption keys.
pub(crate) struct EncryptionState {
    message_encrypter: Option<Box<dyn MessageEncrypter>>,
    record_sequence_number_encrypter: Option<Box<dyn RecordSequenceNumberEncrypter>>,
    write_seq_max: u64,
    /// Encryption epoch.
    ///
    /// This value is tracked for all protocol versions, but only used for DTLS.
    epoch: Epoch,
    write_seq: u64,
    side: Side,
}

impl EncryptionState {
    /// Create new record layer with no keys.
    pub(crate) fn new(side: Side) -> Self {
        Self {
            message_encrypter: None,
            record_sequence_number_encrypter: None,
            write_seq_max: 0,
            epoch: Epoch::Unencrypted,
            write_seq: 0,
            side,
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
        plain: EncodedMessage<OutboundPlain<'_>>,
        output: &mut Vec<u8>,
    ) {
        // Contents are fully overwritten below, so zeroing is pure cost.
        // A fresh buffer gets pre-zeroed memory straight from the allocator
        // while a reused one zeroes only what `resize` grows.
        let needed = plain
            .version
            .version()
            .encrypted_header_len()
            + self.encrypted_len(plain.payload.len());
        let start = output.len();
        output.resize(start + needed, 0);
        let written = self.encrypt_outgoing_into(plain, &mut output[start..]);
        debug_assert_eq!(
            written, needed,
            "MessageEncrypter::encrypt() returned wrong length"
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
        plain: EncodedMessage<OutboundPlain<'_>>,
        out: &mut [u8],
    ) -> usize {
        assert!(self.pre_encrypt_action(0) != Some(PreEncryptAction::Refuse));
        let version_in_use = plain.version.version();
        let header_size = version_in_use.encrypted_header_len();
        let encrypter = self.message_encrypter.as_mut().unwrap();

        let record_seq = self
            .epoch
            .per_record_additional_data(self.write_seq, plain.version.version());
        std::println!("encrypting with record seq {record_seq}");
        self.write_seq += 1;

        let (header, payload) = out.split_at_mut(header_size);

        // First, encode the header, because DTLS 1.3 needs to use it as the AAD.
        encode_record_header(
            match version_in_use {
                ProtocolVersion::TLSv1_2 | ProtocolVersion::DTLSv1_2 => plain.typ,
                ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3 => {
                    ContentType::ApplicationData
                }
                v => panic!("unsupported protocol version {v:?}"),
            },
            plain.version,
            payload.len() as u16,
            EncodingContext {
                payload_is_encrypted: true,
                epoch: self.epoch,
                record_seq,
            },
            header,
        );

        #[cfg(debug_assertions)]
        let (out_ptr, out_len) = (payload.as_ptr(), payload.len());
        let encrypted_len = {
            let encrypted = encrypter
                .encrypt(plain, record_seq, header, payload)
                .unwrap();

            #[cfg(debug_assertions)]
            {
                // `MessageEncrypter::encrypt()` requires the returned payload to be
                // the written prefix of the passed-in buffer. Try to catch misbehaving
                // implementations in debug mode. In release builds a violation would corrupt
                // the sent stream.
                debug_assert_eq!(encrypted.payload.as_ptr(), out_ptr);
                debug_assert!(encrypted.payload.len() <= out_len);
            }

            debug_assert!(encrypted.payload.len() <= usize::from(u16::MAX));

            encrypted.payload.len()
        };

        if let Some(record_sequence_number_encrypter) = self
            .record_sequence_number_encrypter
            .as_ref()
            && version_in_use.is_datagram_tls()
        {
            let mut encoded_record_seq = (record_seq as u16).to_be_bytes();

            // Now that we have encrypted the record, we can use the ciphertext to encrypt the
            // record number and overwrite the previously written header.
            record_sequence_number_encrypter
                .transform(&mut encoded_record_seq, &payload[..16])
                .unwrap();

            header[1..3].copy_from_slice(&encoded_record_seq);
        }

        header_size + encrypted_len
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
        purpose: EncrypterDecrypterPurpose,
        version: ProtocolVersion,
    ) {
        self.message_encrypter = Some(cipher);
        self.write_seq_max = min(SEQ_SOFT_LIMIT, max_messages);
        self.epoch = self.epoch.increment(purpose, version);
        self.write_seq = 0;
    }

    pub(crate) fn set_record_sequence_number_encrypter(
        &mut self,
        encrypter: Box<dyn RecordSequenceNumberEncrypter>,
    ) {
        self.record_sequence_number_encrypter = Some(encrypter);
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
        self.message_encrypter
            .as_ref()
            .map(|enc| enc.encrypted_payload_len(payload_len))
            .unwrap_or_default()
    }

    /// Number of bytes added to a plaintext fragment by record protection.
    pub(crate) fn encrypted_record_overhead(&self) -> usize {
        self.encrypted_len(0)
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.message_encrypter.is_some()
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }

    /// Current epoch.
    pub(crate) fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Record layer that tracks decryption keys.
pub(crate) struct DecryptionState {
    message_decrypter: Option<Box<dyn MessageDecrypter>>,
    record_sequence_number_encrypter: Option<Box<dyn RecordSequenceNumberEncrypter>>,
    /// Encryption epoch.
    ///
    /// This value is tracked for all protocol versions, but only used for Datagram TLS.
    epoch: Epoch,
    read_seq: u64,
    has_decrypted: bool,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,

    side: Side,

    /// Sliding window to detect anti-replay.
    ///
    /// Only used for Datagram TLS.
    anti_replay: ReplayWindow,
}

impl DecryptionState {
    /// Create new record layer with no keys.
    pub(crate) fn new(side: Side) -> Self {
        Self {
            message_decrypter: None,
            record_sequence_number_encrypter: None,
            epoch: Epoch::Unencrypted,
            read_seq: 0,
            has_decrypted: false,
            trial_decryption_len: None,
            side,
            anti_replay: ReplayWindow::default(),
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: EncodedMessage<InboundOpaque<'a>>,
        record_seq: u64,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        let Some(decrypter) = &mut self.message_decrypter else {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        };

        let record_seq = if let Some(record_sequence_number_encrypter) = self
            .record_sequence_number_encrypter
            .as_ref()
            && encr.version.version().is_datagram_tls()
        {
            let mut encoded_record_seq = (record_seq as u16).to_be_bytes();

            // Now that we have encrypted the record, we can use the ciphertext to encrypt the
            // record number and overwrite the previously written header.
            record_sequence_number_encrypter
                .transform(&mut encoded_record_seq, &encr.payload.iter().as_ref()[..16])
                .unwrap();

            encr.payload.0[1..3].copy_from_slice(&encoded_record_seq);

            // TODO(DTLS): it sucks to have to re-parse the header here. Should work out a way to
            // make the parsed header available to this function.
            let mut unified_header =
                UnifiedHeader::read(&mut Reader::new(encr.payload.0), self.epoch).unwrap();
            unified_header.reconstruct_sequence_number(self.read_seq);

            unified_header.sequence()
        } else {
            record_seq
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
        let seq = self
            .epoch
            .per_record_additional_data(record_seq, encr.version.version());
        match decrypter.decrypt(encr, seq) {
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

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        _proof: &HandshakeAlignedProof,
        purpose: EncrypterDecrypterPurpose,
        version: ProtocolVersion,
    ) {
        self.message_decrypter = Some(cipher);
        self.read_seq = 0;
        self.epoch = self.epoch.increment(purpose, version);
        self.trial_decryption_len = None;
        self.anti_replay = ReplayWindow::default();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
        _proof: &HandshakeAlignedProof,
        purpose: EncrypterDecrypterPurpose,
        version: ProtocolVersion,
    ) {
        self.message_decrypter = Some(cipher);
        self.read_seq = 0;
        self.epoch = self.epoch.increment(purpose, version);
        self.trial_decryption_len = Some(max_length);
        self.anti_replay = ReplayWindow::default();
    }

    pub(crate) fn set_record_sequence_number_encrypter(
        &mut self,
        encrypter: Box<dyn RecordSequenceNumberEncrypter>,
    ) {
        self.record_sequence_number_encrypter = Some(encrypter);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_seq
    }

    /// Anti-replay state.
    pub(crate) fn anti_replay(&mut self) -> &mut ReplayWindow {
        &mut self.anti_replay
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
    /// The decrypted message payload.
    pub(crate) plaintext: EncodedMessage<&'a [u8]>,
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
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: EncodedMessage<InboundOpaque<'a>>,
                _: u64,
            ) -> Result<EncodedMessage<&'a [u8]>, Error> {
                Ok(m.into_plain_message())
            }
        }

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = DecryptionState::new(Side::Server);
        assert!(record_layer.message_decrypter.is_none());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Initializing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        let deframer = Deframer::default();
        record_layer.set_message_decrypter(
            Box::new(PassThroughDecrypter),
            &deframer.aligned().unwrap(),
            EncrypterDecrypterPurpose::HandshakeMessages,
            ProtocolVersion::TLSv1_3,
        );
        assert!(record_layer.message_decrypter.is_some());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(
                EncodedMessage::new(
                    ContentType::Handshake,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_3),
                    InboundOpaque(&mut [], &mut [0xC0, 0xFF, 0xEE]),
                ),
                record_layer.read_seq,
            )
            .unwrap();
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(
            Box::new(PassThroughDecrypter),
            &deframer.aligned().unwrap(),
            EncrypterDecrypterPurpose::ApplicationData,
            ProtocolVersion::TLSv1_3,
        );
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
