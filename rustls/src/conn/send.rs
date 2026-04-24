use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::cipher::{
    EncodedMessage, EncryptionState, MessageEncrypter, OutboundPlain, Payload, PreEncryptAction,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::log::{debug, error};
use crate::msgs::{AlertLevel, Message, MessageFragmenter};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::vecbuf::ChunkVecBuffer;

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) encrypt_state: EncryptionState,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_send_half_rtt_data: bool,
    has_sent_fatal_alert: bool,
    /// If we signaled end of stream.
    pub(crate) has_sent_close_notify: bool,
    message_fragmenter: MessageFragmenter,
    pub(crate) sendable_tls: ChunkVecBuffer,
    queued_key_update_message: Option<Vec<u8>>,
    pub(crate) refresh_traffic_keys_pending: bool,
    negotiated_version: Option<ProtocolVersion>,
    pub(crate) tls13_key_schedule: Option<Box<KeyScheduleTrafficSend>>,
}

impl SendPath {
    #[expect(dead_code)]
    pub(crate) fn write_plaintext(
        &mut self,
        payload: OutboundPlain<'_>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            );

        for f in 0..fragments.len() {
            self.preflight_encrypt(f)?;
        }

        self.perhaps_write_key_update();
        for m in fragments {
            self.sendable_tls.append(
                self.encrypt_state
                    .encrypt_outgoing(m)
                    .encode(),
            );
        }

        Ok(self.sendable_tls.take())
    }

    pub(crate) fn send_early_plaintext(&mut self, data: &[u8]) -> usize {
        debug_assert!(self.encrypt_state.is_encrypting());

        // Limit on `sendable_tls` should apply to encrypted data but is enforced
        // for plaintext data instead which does not include cipher+record overhead.
        let len = self
            .sendable_tls
            .apply_limit(data.len());
        if len == 0 {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(data[..len].into())
    }

    pub(crate) fn send_close_notify(&mut self) {
        if self.has_sent_close_notify {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.has_sent_close_notify = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
    }

    pub(crate) fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        match level {
            AlertLevel::Fatal if self.has_sent_fatal_alert => return,
            AlertLevel::Fatal => self.has_sent_fatal_alert = true,
            _ => {}
        };
        self.send_msg(
            Message::build_alert(level, desc),
            self.encrypt_state.is_encrypting(),
        );
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self, payload: OutboundPlain<'_>) -> usize {
        let len = payload.len();
        self.send_messages(
            self.message_fragmenter
                .fragment_payload(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                ),
        );
        len
    }

    /// Encrypt and queue a single fragment.
    fn send_messages<'a>(
        &mut self,
        iter: impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>>,
    ) {
        for m in iter {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            if m.typ != ContentType::Alert && self.preflight_encrypt(0).is_err() {
                return;
            }

            self.perhaps_write_key_update();
            self.sendable_tls.append(
                self.encrypt_state
                    .encrypt_outgoing(m)
                    .encode(),
            );
        }
    }

    fn preflight_encrypt(&mut self, n: usize) -> Result<(), Error> {
        match self
            .encrypt_state
            .pre_encrypt_action(n as u64)
        {
            None => Ok(()),

            // Close connection once we start to run out of sequence space.
            Some(PreEncryptAction::RefreshOrClose) => {
                match self.negotiated_version {
                    // driven by caller, as we don't have the `State` here
                    Some(ProtocolVersion::TLSv1_3) => {
                        self.refresh_traffic_keys_pending = true;
                        Ok(())
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        Err(Error::EncryptError)
                    }
                }
            }

            // Refuse to wrap counter at all costs. This is basically untestable unfortunately.
            Some(PreEncryptAction::Refuse) => Err(Error::EncryptError),
        }
    }

    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, this function will not accept
    /// all the data.
    pub(crate) fn buffer_plaintext(
        &mut self,
        payload: OutboundPlain<'_>,
        sendable_plaintext: &mut ChunkVecBuffer,
    ) -> usize {
        self.perhaps_write_key_update();
        if !self.may_send_application_data {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            return sendable_plaintext.append_limited_copy(payload);
        }

        // Limit on `sendable_tls` should apply to encrypted data but is enforced
        // for plaintext data instead which does not include cipher+record overhead.
        let len = self
            .sendable_tls
            .apply_limit(payload.len());
        if len == 0 {
            // Don't send empty fragments.
            return 0;
        }

        debug_assert!(self.encrypt_state.is_encrypting());
        self.send_appdata_encrypt(payload.split_at(len).0)
    }

    pub(crate) fn send_buffered_plaintext(&mut self, plaintext: &mut ChunkVecBuffer) {
        while let Some(buf) = plaintext.pop() {
            self.send_appdata_encrypt(buf.as_slice().into());
        }
    }

    pub(crate) fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        debug_assert!(self.encrypt_state.is_encrypting());
    }

    fn perhaps_write_key_update(&mut self) {
        if let Some(message) = self.queued_key_update_message.take() {
            self.sendable_tls.append(message);
        }
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    pub(crate) fn ensure_key_update_queued(&mut self) {
        if self.queued_key_update_message.is_some() {
            return;
        }

        let message = EncodedMessage::<Payload<'static>>::from(Message::build_key_update_notify());
        self.queued_key_update_message = Some(
            self.encrypt_state
                .encrypt_outgoing(message.borrow_outbound())
                .encode(),
        );

        if let Some(mut ks) = self.tls13_key_schedule.take() {
            ks.update_encrypter_for_key_update(self);
            self.tls13_key_schedule = Some(ks);
        }
    }

    /// Trigger a `refresh_traffic_keys` if required.
    pub(crate) fn maybe_refresh_traffic_keys(&mut self) {
        if self.refresh_traffic_keys_pending {
            let _ = self.refresh_traffic_keys();
        }
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        let ks = self.tls13_key_schedule.take();

        let Some(mut ks) = ks else {
            return Err(Error::HandshakeNotComplete);
        };

        ks.request_key_update_and_update_encrypter(self);
        self.refresh_traffic_keys_pending = false;
        self.tls13_key_schedule = Some(ks);
        Ok(())
    }
}

impl SendOutput for SendPath {
    fn negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn ensure_key_update_queued(&mut self) {
        self.ensure_key_update_queued();
    }

    fn set_encrypter(&mut self, encrypter: Box<dyn MessageEncrypter>, max_messages: u64) {
        self.encrypt_state
            .set_message_encrypter(encrypter, max_messages);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        self.tls13_key_schedule = Some(schedule);
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        self.send_alert(level, desc);
    }

    fn start_traffic(&mut self) {
        self.may_send_half_rtt_data = true;
        self.start_outgoing_traffic();
    }

    /// Send a raw TLS message, fragmenting it if needed.
    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        let encoded = EncodedMessage::from(m);
        if must_encrypt {
            self.send_messages(
                self.message_fragmenter
                    .fragment_message(&encoded),
            );
            return;
        }

        let iter = self
            .message_fragmenter
            .fragment_message(&encoded);
        self.perhaps_write_key_update();
        for m in iter {
            self.sendable_tls
                .append(m.to_unencrypted_opaque().encode());
        }
    }
}

impl Default for SendPath {
    fn default() -> Self {
        Self {
            encrypt_state: EncryptionState::new(),
            may_send_application_data: false,
            may_send_half_rtt_data: false,
            has_sent_fatal_alert: false,
            has_sent_close_notify: false,
            message_fragmenter: MessageFragmenter::default(),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            queued_key_update_message: None,
            refresh_traffic_keys_pending: false,
            negotiated_version: None,
            tls13_key_schedule: None,
        }
    }
}

pub(crate) trait SendOutput {
    fn negotiated_version(&mut self, version: ProtocolVersion);

    fn ensure_key_update_queued(&mut self);

    fn set_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>, max_messages: u64);

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription);

    fn start_traffic(&mut self);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool);
}

pub(super) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
