use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::cipher::{
    EncodableVersion, EncryptionState, OutboundPlain, Payload, PreEncryptAction, Record,
    RecordEncrypter,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::msgs::{AlertLevel, Fragmenter, HEADER_SIZE, Message};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::tracing::{debug, error};

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) encrypt_state: EncryptionState,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_send_half_rtt_data: bool,
    has_sent_fatal_alert: bool,
    /// If we signaled end of stream.
    pub(crate) has_sent_close_notify: bool,
    message_fragmenter: Fragmenter,
    key_update_local: KeyUpdateLocal,
    key_update_remote: KeyUpdateRemote,
    negotiated_version: Option<ProtocolVersion>,
    pub(crate) tls13_key_schedule: Option<Box<KeyScheduleTrafficSend>>,
}

impl SendPath {
    pub(crate) fn send_close_notify(&mut self, tls: &mut Vec<u8>) {
        if self.has_sent_close_notify {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.has_sent_close_notify = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify, tls);
    }

    fn preflight_encrypt(&mut self, n: usize, tls: &mut Vec<u8>) -> Result<(), Error> {
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
                        self.key_update_local = KeyUpdateLocal::Requested;
                        Ok(())
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify(tls);
                        Err(Error::EncryptError)
                    }
                }
            }

            // Refuse to wrap counter at all costs. This is basically untestable unfortunately.
            Some(PreEncryptAction::Refuse) => Err(Error::EncryptError),
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    pub(crate) fn send_appdata_encrypt(
        &mut self,
        payload: OutboundPlain<'_>,
        tls: &mut Vec<u8>,
    ) -> usize {
        let len = payload.len();
        self.send_messages::<true>(
            self.message_fragmenter.fragment(
                ContentType::ApplicationData,
                EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                payload,
                self.encrypt_state
                    .encrypted_record_overhead(),
            ),
            tls,
        );
        self.maybe_refresh_traffic_keys(tls);
        len
    }

    /// Encrypt and queue each fragment in `iter`.
    fn send_messages<'a, const MUST_ENCRYPT: bool>(
        &mut self,
        iter: impl ExactSizeIterator<Item = Record<OutboundPlain<'a>>>,
        tls: &mut Vec<u8>,
    ) {
        self.perhaps_write_key_update(tls);
        let count = iter.len();
        let mut iter = iter.peekable();
        if let Some(first) = iter.peek() {
            let record_len = HEADER_SIZE
                + match MUST_ENCRYPT {
                    true => self
                        .encrypt_state
                        .encrypted_len(first.payload.len()),
                    false => first.payload.len(),
                };
            tls.reserve(count * record_len);
        }

        for record in iter {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            if MUST_ENCRYPT
                && record.typ != ContentType::Alert
                && self.preflight_encrypt(0, tls).is_err()
            {
                return;
            }

            match MUST_ENCRYPT {
                true => self
                    .encrypt_state
                    .encrypt_outgoing(record, tls),
                false => record.encode_unencrypted(tls),
            }
        }
    }

    pub(crate) fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        debug_assert!(self.encrypt_state.is_encrypting());
    }

    fn perhaps_write_key_update(&mut self, tls: &mut Vec<u8>) {
        let KeyUpdateRemote::Queued(message) = &mut self.key_update_remote else {
            return;
        };
        tls.append(message);
        self.key_update_remote = KeyUpdateRemote::Idle;
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    /// Trigger a `refresh_traffic_keys` if requested.
    fn maybe_refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) {
        if let KeyUpdateLocal::Requested = self.key_update_local {
            let _ = self.send_key_update_request(tls);
        }
    }

    pub(crate) fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        if let KeyUpdateLocal::Outstanding = self.key_update_local {
            return Ok(());
        }
        self.send_key_update_request(tls)
    }

    fn send_key_update_request(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        let ks = self.tls13_key_schedule.take();

        let Some(mut ks) = ks else {
            return Err(Error::HandshakeNotComplete);
        };

        self.send_msg(Message::build_key_update_request(), true, tls);
        ks.update_encrypter(self);
        self.key_update_local = KeyUpdateLocal::Outstanding;
        self.tls13_key_schedule = Some(ks);
        Ok(())
    }
}

impl SendOutput for SendPath {
    fn negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn queue_requested_key_update(&mut self) {
        if let KeyUpdateRemote::Queued(_) = &self.key_update_remote {
            return;
        }

        let record = Record::<Payload<'static>>::from(Message::build_key_update_notify());
        let mut queued = Vec::new();
        self.encrypt_state
            .encrypt_outgoing(record.borrow_outbound(), &mut queued);
        self.key_update_remote = KeyUpdateRemote::Queued(queued);

        if let Some(mut ks) = self.tls13_key_schedule.take() {
            ks.update_encrypter_for_key_update(self);
            self.tls13_key_schedule = Some(ks);
        }
    }

    fn note_key_update_response(&mut self) {
        if let KeyUpdateLocal::Outstanding = self.key_update_local {
            self.key_update_local = KeyUpdateLocal::Idle;
        }
    }

    fn set_encrypter(&mut self, encrypter: Box<dyn RecordEncrypter>, max_records: u64) {
        self.encrypt_state
            .set_record_encrypter(encrypter, max_records);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        self.tls13_key_schedule = Some(schedule);
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription, tls: &mut Vec<u8>) {
        match level {
            AlertLevel::Fatal if self.has_sent_fatal_alert => return,
            AlertLevel::Fatal => self.has_sent_fatal_alert = true,
            _ => {}
        };

        self.send_msg(
            Message::build_alert(level, desc),
            self.encrypt_state.is_encrypting(),
            tls,
        );
    }

    fn start_traffic(&mut self) {
        self.may_send_half_rtt_data = true;
        self.start_outgoing_traffic();
    }

    /// Send a raw TLS message, fragmenting it if needed.
    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool, tls: &mut Vec<u8>) {
        let record = Record::from(m);
        let fragments = self.message_fragmenter.fragment(
            record.typ,
            record.version,
            record.payload.bytes().into(),
            self.encrypt_state
                .encrypted_record_overhead(),
        );

        match must_encrypt {
            true => self.send_messages::<true>(fragments, tls),
            false => self.send_messages::<false>(fragments, tls),
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
            message_fragmenter: Fragmenter::default(),
            key_update_local: KeyUpdateLocal::Idle,
            key_update_remote: KeyUpdateRemote::Idle,
            negotiated_version: None,
            tls13_key_schedule: None,
        }
    }
}

/// State machine for TLS1.3 key updates triggered by us.
///
/// This sits at [`Self::Idle`] for TLS1.2 connections.
enum KeyUpdateLocal {
    /// Nothing is happening.
    Idle,

    /// A key update request should be sent at the next sending opportunity.
    Requested,

    /// A key update request is outstanding; we await a response.
    Outstanding,
}

/// State machine for TLS1.3 key updates triggered by peer.
///
/// This sits at [`Self::Idle`] for TLS1.2 connections.
enum KeyUpdateRemote {
    /// Nothing is happening.
    Idle,

    /// A key update response is awaiting sending.
    Queued(Vec<u8>),
}

pub(crate) trait SendOutput {
    fn negotiated_version(&mut self, version: ProtocolVersion);

    fn queue_requested_key_update(&mut self);

    fn note_key_update_response(&mut self);

    fn set_encrypter(&mut self, cipher: Box<dyn RecordEncrypter>, max_records: u64);

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription, tls: &mut Vec<u8>);

    fn start_traffic(&mut self);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool, tls: &mut Vec<u8>);
}
