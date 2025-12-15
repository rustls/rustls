use alloc::boxed::Box;
use core::cmp::min;

use crate::crypto::cipher::{
    EncodedMessage, InboundOpaque, MessageDecrypter, MessageEncrypter, OutboundOpaque,
    OutboundPlain,
};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::deframer::HandshakeAlignedProof;

/// Record layer that tracks encryption keys.
pub(crate) struct EncryptionState {
    message_encrypter: Option<Box<dyn MessageEncrypter>>,
    write_seq_max: u64,
    write_seq: u64,
}

impl EncryptionState {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            message_encrypter: None,
            write_seq_max: 0,
            write_seq: 0,
        }
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: EncodedMessage<OutboundPlain<'_>>,
    ) -> EncodedMessage<OutboundOpaque> {
        assert!(self.next_pre_encrypt_action() != PreEncryptAction::Refuse);
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter
            .as_mut()
            .unwrap()
            .encrypt(plain, seq)
            .unwrap()
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        *self = Self {
            message_encrypter: Some(cipher),
            write_seq_max: min(SEQ_SOFT_LIMIT, max_messages),
            write_seq: 0,
        };
    }

    pub(crate) fn next_pre_encrypt_action(&self) -> PreEncryptAction {
        self.pre_encrypt_action(0)
    }

    /// Return a remedial action when we are near to encrypting too many messages.
    ///
    /// `add` is added to the current sequence number.  `add` as `0` means
    /// "the next message processed by `encrypt_outgoing`"
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> PreEncryptAction {
        match self.write_seq.saturating_add(add) {
            v if v == self.write_seq_max => PreEncryptAction::RefreshOrClose,
            SEQ_HARD_LIMIT.. => PreEncryptAction::Refuse,
            _ => PreEncryptAction::Nothing,
        }
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.message_encrypter
            .as_ref()
            .map(|enc| enc.encrypted_payload_len(payload_len))
            .unwrap_or_default()
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.message_encrypter.is_some()
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }
}

/// Record layer that tracks decryption keys.
pub(crate) struct DecryptionState {
    message_decrypter: Option<Box<dyn MessageDecrypter>>,
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
            message_decrypter: None,
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
        encr: EncodedMessage<InboundOpaque<'a>>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        let Some(decrypter) = &mut self.message_decrypter else {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
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

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        _proof: &HandshakeAlignedProof,
    ) {
        self.message_decrypter = Some(cipher);
        self.read_seq = 0;
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
        _proof: &HandshakeAlignedProof,
    ) {
        self.message_decrypter = Some(cipher);
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
    pub(crate) plaintext: EncodedMessage<&'a [u8]>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PreEncryptAction {
    /// No action is needed before calling `encrypt_outgoing`
    Nothing,

    /// A `key_update` request should be sent ASAP.
    ///
    /// If that is not possible (for example, the connection is TLS1.2), a `close_notify`
    /// alert should be sent instead.
    RefreshOrClose,

    /// Do not call `encrypt_outgoing` further, it will panic rather than
    /// over-use the key.
    Refuse,
}

const SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
const SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::deframer::HandshakeDeframer;

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
        let mut record_layer = DecryptionState::new();
        assert!(record_layer.message_decrypter.is_none());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Initializing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        let deframer = HandshakeDeframer::default();
        record_layer
            .set_message_decrypter(Box::new(PassThroughDecrypter), &deframer.aligned().unwrap());
        assert!(record_layer.message_decrypter.is_some());
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(EncodedMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                InboundOpaque(&mut [0xC0, 0xFF, 0xEE]),
            ))
            .unwrap();
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer
            .set_message_decrypter(Box::new(PassThroughDecrypter), &deframer.aligned().unwrap());
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
