use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::common_state::Protocol;
use crate::crypto::cipher::{
    EncodableVersion, EncodedMessage, EncodingContext, EncryptionState, MessageEncrypter,
    OutboundPlain, Payload, PreEncryptAction,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::log::{debug, error};
use crate::msgs::{
    AlertLevel, Codec, EpochAndSequence, HandshakeSequence, HandshakeSequenceNumber, Message,
    MessageFragmenter, MessagePayload,
};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::vecbuf::ChunkVecBuffer;

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) protocol: Protocol,
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
    handshake_sequence: HandshakeSequence,
}

impl SendPath {
    pub(crate) fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
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
            handshake_sequence: HandshakeSequence::default(),
        }
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

    fn preflight_encrypt(&mut self, n: usize) -> Result<(), Error> {
        match self
            .encrypt_state
            .pre_encrypt_action(n as u64)
        {
            None => Ok(()),

            // Close connection once we start to run out of sequence space.
            Some(PreEncryptAction::RefreshOrClose) => {
                match self.negotiated_version() {
                    // driven by caller, as we don't have the `State` here
                    ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3 => {
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

    /// Encrypt application data from `payload` directly into `out`.
    ///
    /// Any records already queued inside the connection (for example, a
    /// pending `key_update`) are written to `out` first.
    ///
    /// Records are written while `out` has space for them. The returned
    /// [`WrittenInto`] indicates how much of `payload` was consumed and how many
    /// bytes were written. The caller should call `write_appdata_into()` again with
    /// the unconsumed remainder of `payload` once it has disposed of the written bytes.
    pub(crate) fn write_appdata_into(
        &mut self,
        payload: OutboundPlain<'_>,
        out: &mut [u8],
    ) -> Result<WrittenInto, Error> {
        debug_assert!(self.encrypt_state.is_encrypting());
        let mut written = self.sendable_tls.read(out);
        let mut consumed = 0;

        let mut send_msg =
            |this: &mut Self, m: EncodedMessage<OutboundPlain<'_>>| -> Result<bool, Error> {
                this.preflight_encrypt(0)?;
                this.perhaps_write_key_update();
                written += this
                    .sendable_tls
                    .read(&mut out[written..]);

                let fragment_len = m.payload.len();
                if out.len() - written
                    < this
                        .negotiated_version()
                        .encrypted_header_len()
                        + this
                            .encrypt_state
                            .encrypted_len(fragment_len)
                {
                    return Ok(false);
                }

                written += this
                    .encrypt_state
                    .encrypt_outgoing_into(m, &mut out[written..]);
                consumed += fragment_len;

                Ok(true)
            };

        if self
            .negotiated_version()
            .is_datagram_tls()
        {
            // For DTLS, we don't fragment application data, instead expecting clients to chunk up
            // application layer messages appropriately themselves.
            send_msg(
                self,
                EncodedMessage {
                    typ: ContentType::ApplicationData,
                    version: EncodableVersion::Legacy(self.negotiated_version()),
                    payload,
                },
            )?;
        } else {
            for m in self
                .message_fragmenter
                .fragment_payload(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(self.negotiated_version()),
                    payload,
                )
            {
                if !send_msg(self, m)? {
                    break;
                }
            }
        }

        Ok(WrittenInto {
            plaintext_consumed: consumed,
            tls_written: written,
        })
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

    /// Like send_msg_encrypt, but operate on an appdata directly.
    pub(crate) fn send_appdata_encrypt(&mut self, payload: OutboundPlain<'_>) -> usize {
        let len = payload.len();
        self.send_messages::<true>(
            self.message_fragmenter
                .fragment_payload(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                    payload,
                ),
        );
        len
    }

    /// Encrypt and queue each fragment in `iter`.
    fn send_messages<'a, const MUST_ENCRYPT: bool>(
        &mut self,
        iter: impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>>,
    ) {
        self.perhaps_write_key_update();
        for m in iter {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            if MUST_ENCRYPT && m.typ != ContentType::Alert && self.preflight_encrypt(0).is_err() {
                return;
            }

            let record = match MUST_ENCRYPT {
                true => self
                    .encrypt_state
                    .encrypt_outgoing(m, self.sendable_tls.take_spare()),
                false => m.to_unencrypted_bytes(EncodingContext {
                    payload_is_encrypted: false,
                    epoch_and_sequence: self.dtls_epoch_and_sequence(),
                }),
            };
            self.sendable_tls.append(record);
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
            .set_max_fragment_size(new, self.protocol)
    }

    fn dtls_epoch_and_sequence(&self) -> Option<EpochAndSequence> {
        if self.protocol.is_dtls() {
            Some(EpochAndSequence::from_sequence_number(
                self.encrypt_state.write_seq(),
            ))
        } else {
            None
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

        ks.request_key_update_and_update_encrypter(self.negotiated_version(), self);
        self.refresh_traffic_keys_pending = false;
        self.tls13_key_schedule = Some(ks);
        Ok(())
    }

    fn negotiated_version(&self) -> ProtocolVersion {
        if let Some(version) = self.negotiated_version {
            version
        }
        // If the negotiated version has not been set yet, then we are early in the handshake and
        // will behave as though doing (D)TLS 1.2 for backward compatibility
        else if self.protocol.is_dtls() {
            ProtocolVersion::DTLSv1_2
        } else {
            ProtocolVersion::TLSv1_2
        }
    }
}

impl SendOutput for SendPath {
    fn set_negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn ensure_key_update_queued(&mut self) {
        if self.queued_key_update_message.is_some() {
            return;
        }

        let message = EncodedMessage::<Payload<'static>>::from(Message::build_key_update_notify(
            self.negotiated_version(),
            self.outbound_handshake_seq(),
        ));
        self.queued_key_update_message = Some(
            self.encrypt_state
                .encrypt_outgoing(message.borrow_outbound(), Vec::new()),
        );

        if let Some(mut ks) = self.tls13_key_schedule.take() {
            ks.update_encrypter_for_key_update(self);
            self.tls13_key_schedule = Some(ks);
        }
    }

    fn set_encrypter(&mut self, encrypter: Box<dyn MessageEncrypter>, max_messages: u64) {
        self.encrypt_state
            .set_message_encrypter(encrypter, max_messages);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        self.tls13_key_schedule = Some(schedule);
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        match level {
            AlertLevel::Fatal if self.has_sent_fatal_alert => return,
            AlertLevel::Fatal => self.has_sent_fatal_alert = true,
            _ => {}
        };

        self.send_msg(
            Message::build_alert(level, desc, self.negotiated_version()),
            self.encrypt_state.is_encrypting(),
        );
    }

    fn start_traffic(&mut self) {
        self.may_send_half_rtt_data = true;
        self.start_outgoing_traffic();
    }

    /// Send a raw TLS message, fragmenting it if needed.
    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        match (self.protocol, &m.payload) {
            // DTLS handshake messages can be fragmented into multiple records which contain
            // information necessary for reassembly.
            (
                Protocol::Udp,
                MessagePayload::Handshake {
                    parsed,
                    encoded,
                    seq,
                },
            ) => {
                std::println!("send path handshake seq: {:?}", self.handshake_sequence);
                let messages: Vec<_> = self
                    .message_fragmenter
                    .fragment_dtls_handshake_message(
                        m.version,
                        parsed.0.handshake_type(),
                        *seq,
                        encoded.bytes(),
                    )
                    .map(|m| {
                        std::println!(
                            "sedn path post fragment sending {:?} seq {:?}",
                            m.typ,
                            m.payload.message_seq
                        );
                        EncodedMessage {
                            typ: m.typ,
                            version: m.version,
                            payload: m.payload.get_encoding(),
                        }
                    })
                    .collect();
                match must_encrypt {
                    true => self.send_messages::<true>(messages.iter().map(|m| EncodedMessage {
                        typ: m.typ,
                        version: m.version,
                        payload: m.payload.as_slice().into(),
                    })),
                    false => self.send_messages::<false>(messages.iter().map(|m| EncodedMessage {
                        typ: m.typ,
                        version: m.version,
                        payload: m.payload.as_slice().into(),
                    })),
                };
            }
            (Protocol::Udp, MessagePayload::HandshakeFlight(encoded)) => {
                let epoch_and_sequence = self
                    .dtls_epoch_and_sequence()
                    .expect("epoch and sequence should be set for DTLS");
                let messages: Vec<_> = self
                    .message_fragmenter
                    .fragment_dtls_handshake_message_flight(m.version, epoch_and_sequence, encoded)
                    .into_iter()
                    .map(|m| EncodedMessage {
                        typ: m.typ,
                        version: m.version,
                        payload: m.payload.get_encoding(),
                    })
                    .collect();
                match must_encrypt {
                    true => self.send_messages::<true>(messages.iter().map(|m| EncodedMessage {
                        typ: m.typ,
                        version: m.version,
                        payload: m.payload.as_slice().into(),
                    })),
                    false => self.send_messages::<false>(messages.iter().map(|m| EncodedMessage {
                        typ: m.typ,
                        version: m.version,
                        payload: m.payload.as_slice().into(),
                    })),
                };

                // TODO(timg): update epoch and sequence in this object's encrypt state?
            }
            // Other DTLS messages are required to fit into a single record. Application data should
            // be chunked by the application before being handled off to rustls.
            (Protocol::Udp, _) => match must_encrypt {
                true => self
                    .send_messages::<true>([EncodedMessage::from(m).borrow_outbound()].into_iter()),
                false => self.send_messages::<false>(
                    [EncodedMessage::from(m).borrow_outbound()].into_iter(),
                ),
            },
            // TLS messages can be fragmented into multiple TCP or QUIC packets
            _ => match must_encrypt {
                true => self.send_messages::<true>(
                    self.message_fragmenter
                        .fragment_message(&EncodedMessage::from(m)),
                ),
                false => self.send_messages::<false>(
                    self.message_fragmenter
                        .fragment_message(&EncodedMessage::from(m)),
                ),
            },
        }
    }

    fn outbound_handshake_seq(&mut self) -> HandshakeSequenceNumber {
        self.handshake_sequence.increment()
    }
}

pub(crate) trait SendOutput {
    fn set_negotiated_version(&mut self, version: ProtocolVersion);

    fn ensure_key_update_queued(&mut self);

    fn set_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>, max_messages: u64);

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription);

    fn start_traffic(&mut self);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool);

    fn outbound_handshake_seq(&mut self) -> HandshakeSequenceNumber;
}

/// The outcome of encrypting application data into a caller-provided buffer.
///
/// Returned by [`SendTraffic::write_tls_into()`].
///
/// [`SendTraffic::write_tls_into()`]: crate::split::SendTraffic::write_tls_into()
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WrittenInto {
    /// How many plaintext bytes were consumed from the input payload.
    pub plaintext_consumed: usize,

    /// How many TLS bytes were written to the output buffer.
    pub tls_written: usize,
}

pub(super) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
