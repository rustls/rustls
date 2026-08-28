use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::common_state::{Protocol, Side};
use crate::crypto::cipher::{
    EncodableVersion, EncodedMessage, EncodingContext, EncryptionState, MessageEncrypter,
    OutboundPlain, Payload, PreEncryptAction, RecordSequenceNumberEncrypter,
};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::msgs::{
    AckRecordSequenceNumber, AlertLevel, Codec, EncrypterDecrypterPurpose, Fragmenter,
    HandshakeSequence, HandshakeSequenceNumber, Message, MessagePayload,
};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::tracing::{debug, error};

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) protocol: Protocol,
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
    handshake_sequence: HandshakeSequence,
    side: Side,
}

impl SendPath {
    pub(crate) fn new(protocol: Protocol, side: Side) -> Self {
        Self {
            protocol,
            encrypt_state: EncryptionState::new(side),
            may_send_application_data: false,
            may_send_half_rtt_data: false,
            has_sent_fatal_alert: false,
            has_sent_close_notify: false,
            message_fragmenter: Fragmenter::default(),
            key_update_local: KeyUpdateLocal::Idle,
            key_update_remote: KeyUpdateRemote::Idle,
            negotiated_version: None,
            tls13_key_schedule: None,
            handshake_sequence: HandshakeSequence::default(),
            side,
        }
    }

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
                match self.negotiated_version() {
                    // driven by caller, as we don't have the `State` here
                    ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3 => {
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
        if self
            .negotiated_version()
            .is_datagram_tls()
        {
            // For DTLS, we don't fragment application data, instead expecting clients to chunk up
            // application layer messages appropriately themselves.
            self.send_messages::<true>(
                [EncodedMessage {
                    typ: ContentType::ApplicationData,
                    version: EncodableVersion::Legacy(self.negotiated_version()),
                    payload,
                }]
                .into_iter(),
                tls,
            );
        } else {
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
        }
        self.maybe_refresh_traffic_keys(tls);
        len
    }

    /// Encrypt and queue each fragment in `iter`.
    fn send_messages<'a, const MUST_ENCRYPT: bool>(
        &mut self,
        iter: impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>>,
        tls: &mut Vec<u8>,
    ) {
        self.perhaps_write_key_update(tls);
        let count = iter.len();
        let mut iter = iter.peekable();
        if let Some(first) = iter.peek() {
            let record_len = match MUST_ENCRYPT {
                true => {
                    first
                        .version
                        .version()
                        .encrypted_header_len()
                        + self
                            .encrypt_state
                            .encrypted_len(first.payload.len())
                }
                false => {
                    first
                        .version
                        .version()
                        .unencrypted_header_len()
                        + first.payload.len()
                }
            };
            tls.reserve(count * record_len);
        }

        for m in iter {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            if MUST_ENCRYPT
                && m.typ != ContentType::Alert
                && self.preflight_encrypt(0, tls).is_err()
            {
                return;
            }

            match MUST_ENCRYPT {
                true => self
                    .encrypt_state
                    .encrypt_outgoing(m, tls),
                false => {
                    m.encode_unencrypted(
                        tls,
                        EncodingContext {
                            payload_is_encrypted: false,
                            // Despite the message being unencrypted, we still indicate the current
                            // epoch
                            epoch: self.encrypt_state.epoch(),
                            record_seq: self.encrypt_state.increment_sequence(),
                        },
                    )
                }
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
            .set_max_fragment_size(new, self.protocol)
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

        let msg = Message::build_key_update_request(
            self.negotiated_version(),
            self.outbound_handshake_seq(),
        );

        self.send_msg(msg, true, tls);
        ks.update_encrypter(self);
        self.key_update_local = KeyUpdateLocal::Outstanding;
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

    fn send_dtls_handshake_flight<E: AsRef<[u8]>>(
        &mut self,
        m: &Message<'_>,
        encoded: &[(HandshakeType, HandshakeSequenceNumber, E)],
        must_encrypt: bool,
        tls: &mut Vec<u8>,
    ) {
        let messages: Vec<_> = self
            .message_fragmenter
            .fragment_dtls_handshake_message_flight(m.version, encoded)
            .into_iter()
            .map(|m| EncodedMessage {
                typ: m.typ,
                version: m.version,
                payload: m.payload.get_encoding(),
            })
            .collect();
        match must_encrypt {
            true => self.send_messages::<true>(
                messages.iter().map(|m| EncodedMessage {
                    typ: m.typ,
                    version: m.version,
                    payload: m.payload.as_slice().into(),
                }),
                tls,
            ),
            false => self.send_messages::<false>(
                messages.iter().map(|m| EncodedMessage {
                    typ: m.typ,
                    version: m.version,
                    payload: m.payload.as_slice().into(),
                }),
                tls,
            ),
        };
    }
}

impl SendOutput for SendPath {
    fn set_negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn queue_requested_key_update(&mut self) {
        if let KeyUpdateRemote::Queued(_) = &self.key_update_remote {
            return;
        }

        let message = EncodedMessage::<Payload<'static>>::from(Message::build_key_update_notify(
            self.negotiated_version(),
            self.outbound_handshake_seq(),
        ));
        let mut queued = Vec::new();
        self.encrypt_state
            .encrypt_outgoing(message.borrow_outbound(), &mut queued);
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

    fn set_encrypter(
        &mut self,
        encrypter: Box<dyn MessageEncrypter>,
        max_messages: u64,
        purpose: EncrypterDecrypterPurpose,
    ) {
        self.encrypt_state
            .set_message_encrypter(encrypter, max_messages, purpose, self.negotiated_version());
    }

    fn set_record_sequence_number_encrypter(
        &mut self,
        encrypter: Box<dyn RecordSequenceNumberEncrypter>,
    ) {
        self.encrypt_state
            .set_record_sequence_number_encrypter(encrypter);
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
            Message::build_alert(level, desc, self.negotiated_version()),
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
                self.send_dtls_handshake_flight(
                    &m,
                    &[(parsed.0.handshake_type(), *seq, encoded.bytes())],
                    must_encrypt,
                    tls,
                );
            }
            (Protocol::Udp, MessagePayload::HandshakeFlight(encoded)) => {
                self.send_dtls_handshake_flight(&m, encoded, must_encrypt, tls);
            }
            // Other DTLS messages are required to fit into a single record. Application data should
            // be chunked by the application before being handled off to rustls.
            (Protocol::Udp, _) => match must_encrypt {
                true => self.send_messages::<true>(
                    [EncodedMessage::from(m).borrow_outbound()].into_iter(),
                    tls,
                ),
                false => self.send_messages::<false>(
                    [EncodedMessage::from(m).borrow_outbound()].into_iter(),
                    tls,
                ),
            },
            // TLS messages can be fragmented into multiple TCP or QUIC packets
            _ => {
                let EncodedMessage {
                    typ,
                    version,
                    payload,
                } = EncodedMessage::from(m);
                match must_encrypt {
                    true => self.send_messages::<true>(
                        self.message_fragmenter.fragment(
                            typ,
                            version,
                            payload.bytes().into(),
                            self.encrypt_state
                                .encrypted_record_overhead(),
                        ),
                        tls,
                    ),
                    false => self.send_messages::<false>(
                        self.message_fragmenter.fragment(
                            typ,
                            version,
                            payload.bytes().into(),
                            self.encrypt_state
                                .encrypted_record_overhead(),
                        ),
                        tls,
                    ),
                }
            }
        }
    }

    fn outbound_handshake_seq(&mut self) -> HandshakeSequenceNumber {
        self.handshake_sequence.increment()
    }

    fn ack_flight(&mut self, record_seqs: &[AckRecordSequenceNumber], tls: &mut Vec<u8>) {
        self.send_msg(Message::build_ack(record_seqs), false, tls);
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
    fn set_negotiated_version(&mut self, version: ProtocolVersion);

    fn queue_requested_key_update(&mut self);

    fn note_key_update_response(&mut self);

    fn set_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
        purpose: EncrypterDecrypterPurpose,
    );

    fn set_record_sequence_number_encrypter(
        &mut self,
        encrypter: Box<dyn RecordSequenceNumberEncrypter>,
    );

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription, tls: &mut Vec<u8>);

    fn start_traffic(&mut self);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool, tls: &mut Vec<u8>);

    fn outbound_handshake_seq(&mut self) -> HandshakeSequenceNumber;

    fn ack_flight(&mut self, record_seqs: &[AckRecordSequenceNumber], tls: &mut Vec<u8>);
}
