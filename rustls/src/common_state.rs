use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut, Range};

use pki_types::{DnsName, FipsStatus};

use crate::client::EchStatus;
use crate::conn::Exporter;
use crate::conn::kernel::KernelState;
use crate::conn::unbuffered::{EncryptError, InsufficientSizeError};
use crate::crypto::Identity;
use crate::crypto::cipher::{
    Decrypted, DecryptionState, EncodedMessage, EncryptionState, MessageDecrypter,
    MessageEncrypter, OutboundOpaque, OutboundPlain, Payload, PreEncryptAction,
};
use crate::crypto::kx::SupportedKxGroup;
use crate::crypto::tls13::OkmBlock;
use crate::enums::{ApplicationProtocol, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, ApiMisuse, Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, error, trace, warn};
use crate::msgs::{
    AlertLevel, AlertMessagePayload, BufferProgress, Codec, DeframerIter, Delocator,
    HandshakeAlignedProof, HandshakeDeframer, HandshakeMessagePayload, Locator, Message,
    MessageFragmenter, MessagePayload,
};
use crate::suites::{PartiallyExtractedSecrets, SupportedCipherSuite};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::vecbuf::ChunkVecBuffer;
use crate::{SideData, quic};

pub(crate) fn process_main_protocol<Data: SideData>(
    msg: EncodedMessage<&'_ [u8]>,
    aligned_handshake: Option<HandshakeAlignedProof>,
    state: Box<dyn State>,
    plaintext_locator: &Locator,
    received_plaintext: &mut Option<UnborrowedPayload>,
    data: &mut Data,
) -> Result<Box<dyn State>, Error> {
    // Drop CCS messages during handshake in TLS1.3
    if msg.typ == ContentType::ChangeCipherSpec && data.recv.drop_tls13_ccs(&msg)? {
        trace!("Dropping CCS");
        return Ok(state);
    }

    let common = data.deref_mut();
    let msg = common
        .recv
        .parse_and_maybe_drop(&msg, &mut common.send)?;

    let Some(msg) = msg else {
        // Message is dropped.
        return Ok(state);
    };

    let mut cx = CaptureAppData {
        data,
        plaintext_locator,
        received_plaintext,
    };

    state.handle(
        Input {
            message: msg,
            aligned_handshake,
        },
        &mut cx,
    )
}

/// Connection state common to both client and server connections.
pub struct CommonState {
    pub(crate) outputs: ConnectionOutputs,
    pub(crate) send: SendPath,
    pub(crate) recv: ReceivePath,
    pub(crate) quic: quic::Quic,

    /// Protocol whose key schedule should be used. Unused for TLS < 1.3.
    protocol: Protocol,
}

impl CommonState {
    pub(crate) fn new(side: Side, protocol: Protocol) -> Self {
        Self {
            outputs: ConnectionOutputs::default(),
            send: SendPath::default(),
            recv: ReceivePath::new(side),
            quic: quic::Quic::default(),
            protocol,
        }
    }

    /// Returns true if the caller should call [`Connection::write_tls`] as soon as possible.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn wants_write(&self) -> bool {
        !self.send.sendable_tls.is_empty()
    }

    /// Queues a `close_notify` warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn send_close_notify(&mut self) {
        self.send.send_close_notify()
    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    ///
    /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
    pub fn is_handshaking(&self) -> bool {
        !(self.send.may_send_application_data && self.recv.may_receive_application_data)
    }
}

impl Output for CommonState {
    fn emit(&mut self, ev: Event<'_>) {
        match ev.disposition() {
            EventDisposition::MessageOutput => match self.protocol {
                Protocol::Tcp => self.send.emit(ev),
                Protocol::Quic(_) => self.quic.emit(ev),
            },

            EventDisposition::SendPath => self.send.emit(ev),
            EventDisposition::ReceivePath => self.recv.emit(ev),
            EventDisposition::ConnectionOutputs => self.outputs.emit(ev),
            EventDisposition::Quic => self.quic.emit(ev),
            EventDisposition::SideSpecific => unreachable!(),

            EventDisposition::ProtocolVersion(ver) => {
                self.outputs
                    .emit(Event::ProtocolVersion(ver));
                self.recv
                    .emit(Event::ProtocolVersion(ver));
                self.send
                    .emit(Event::ProtocolVersion(ver));
            }
            EventDisposition::StartTraffic => {
                self.recv.emit(Event::StartTraffic);
                self.send.emit(Event::StartTraffic);
            }
        }
    }
}

impl Deref for CommonState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.outputs
    }
}

impl DerefMut for CommonState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.outputs
    }
}

impl fmt::Debug for CommonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonState")
            .finish_non_exhaustive()
    }
}

/// Facts about the connection learned through the handshake.
pub struct ConnectionOutputs {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    handshake_kind: Option<HandshakeKind>,
    suite: Option<SupportedCipherSuite>,
    negotiated_kx_group: Option<&'static dyn SupportedKxGroup>,
    pub(crate) alpn_protocol: Option<ApplicationProtocol<'static>>,
    pub(crate) peer_identity: Option<Identity<'static>>,
    pub(crate) exporter: Option<Box<dyn Exporter>>,
    pub(crate) early_exporter: Option<Box<dyn Exporter>>,
    pub(crate) fips: FipsStatus,
    pub(crate) tls13_tickets_received: u32,
}

impl ConnectionOutputs {
    /// Retrieves the certificate chain or the raw public key used by the peer to authenticate.
    ///
    /// This is made available for both full and resumed handshakes.
    ///
    /// For clients, this is the identity of the server. For servers, this is the identity of the
    /// client, if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    pub fn peer_identity(&self) -> Option<&Identity<'static>> {
        self.peer_identity.as_ref()
    }

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of `None` after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    pub fn alpn_protocol(&self) -> Option<&ApplicationProtocol<'static>> {
        self.alpn_protocol.as_ref()
    }

    /// Retrieves the cipher suite agreed with the peer.
    ///
    /// This returns None until the cipher suite is agreed.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// Retrieves the key exchange group agreed with the peer.
    ///
    /// This function may return `None` depending on the state of the connection,
    /// the type of handshake, and the protocol version.
    ///
    /// If [`CommonState::is_handshaking()`] is true this function will return `None`.
    /// Similarly, if the [`ConnectionOutputs::handshake_kind()`] is [`HandshakeKind::Resumed`]
    /// and the [`ConnectionOutputs::protocol_version()`] is TLS 1.2, then no key exchange will have
    /// occurred and this function will return `None`.
    pub fn negotiated_key_exchange_group(&self) -> Option<&'static dyn SupportedKxGroup> {
        self.negotiated_kx_group
    }

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns `None` until the version is agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    /// Which kind of handshake was performed.
    ///
    /// This tells you whether the handshake was a resumption or not.
    ///
    /// This will return `None` before it is known which sort of
    /// handshake occurred.
    pub fn handshake_kind(&self) -> Option<HandshakeKind> {
        self.handshake_kind
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    ///
    /// Only clients receive tickets, so this is zero for servers.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.tls13_tickets_received
    }

    /// Return the FIPS validation status of the connection.
    ///
    /// This is different from [`crate::crypto::CryptoProvider::fips()`]:
    /// it is concerned only with cryptography, whereas this _also_ covers TLS-level
    /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
    pub fn fips(&self) -> FipsStatus {
        self.fips
    }

    pub(super) fn into_kernel_parts(self) -> Option<(ProtocolVersion, SupportedCipherSuite)> {
        let Self {
            negotiated_version,
            suite,
            ..
        } = self;

        match (negotiated_version, suite) {
            (Some(version), Some(suite)) => Some((version, suite)),
            _ => None,
        }
    }
}

impl Output for ConnectionOutputs {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::ApplicationProtocol(protocol) => {
                self.alpn_protocol = Some(ApplicationProtocol::from(protocol.as_ref()).to_owned())
            }
            Event::CipherSuite(suite) => self.suite = Some(suite),
            Event::EarlyExporter(exporter) => self.early_exporter = Some(exporter),
            Event::Exporter(exporter) => self.exporter = Some(exporter),
            Event::HandshakeKind(hk) => {
                assert!(self.handshake_kind.is_none());
                self.handshake_kind = Some(hk);
            }
            Event::KeyExchangeGroup(kxg) => {
                assert!(self.negotiated_kx_group.is_none());
                self.negotiated_kx_group = Some(kxg);
            }
            Event::PeerIdentity(identity) => self.peer_identity = Some(identity),
            Event::ProtocolVersion(ver) => {
                self.negotiated_version = Some(ver);
            }
            Event::ReceivedTicket => {
                self.tls13_tickets_received = self
                    .tls13_tickets_received
                    .saturating_add(1)
            }
            _ => unreachable!(),
        }
    }
}

impl Default for ConnectionOutputs {
    fn default() -> Self {
        Self {
            negotiated_version: None,
            handshake_kind: None,
            suite: None,
            negotiated_kx_group: None,
            alpn_protocol: None,
            peer_identity: None,
            exporter: None,
            early_exporter: None,
            fips: FipsStatus::Unvalidated,
            tls13_tickets_received: 0,
        }
    }
}

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) encrypt_state: EncryptionState,
    pub(crate) may_send_application_data: bool,
    has_sent_fatal_alert: bool,
    /// If we signaled end of stream.
    pub(crate) has_sent_close_notify: bool,
    message_fragmenter: MessageFragmenter,
    pub(crate) sendable_tls: ChunkVecBuffer,
    queued_key_update_message: Option<Vec<u8>>,
    pub(crate) refresh_traffic_keys_pending: bool,
    negotiated_version: Option<ProtocolVersion>,
}

impl SendPath {
    pub(crate) fn maybe_send_fatal_alert(&mut self, error: &Error) {
        let Ok(alert) = AlertDescription::try_from(error) else {
            return;
        };
        debug_assert!(!self.has_sent_fatal_alert);
        let m = Message::build_alert(AlertLevel::Fatal, alert);
        self.send_msg(m, self.encrypt_state.is_encrypting());
        self.has_sent_fatal_alert = true;
    }

    #[expect(dead_code)]
    pub(crate) fn write_plaintext(
        &mut self,
        payload: OutboundPlain<'_>,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        if payload.is_empty() {
            return Ok(0);
        }

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload.clone(),
            );

        for f in 0..fragments.len() {
            match self
                .encrypt_state
                .pre_encrypt_action(f as u64)
            {
                PreEncryptAction::Nothing => {}
                PreEncryptAction::RefreshOrClose => match self.negotiated_version {
                    Some(ProtocolVersion::TLSv1_3) => {
                        // driven by caller, as we don't have the `State` here
                        self.refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        return Err(EncryptError::EncryptExhausted);
                    }
                },
                PreEncryptAction::Refuse => {
                    return Err(EncryptError::EncryptExhausted);
                }
            }
        }

        self.perhaps_write_key_update();

        self.check_required_size(outgoing_tls, fragments)?;

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            );

        Ok(self.write_fragments(outgoing_tls, fragments))
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

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    fn send_msg_encrypt(&mut self, m: EncodedMessage<Payload<'_>>) {
        let iter = self
            .message_fragmenter
            .fragment_message(&m);
        for m in iter {
            self.send_single_fragment(m);
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self, payload: OutboundPlain<'_>) -> usize {
        let len = payload.len();
        let iter = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            );
        for m in iter {
            self.send_single_fragment(m);
        }

        len
    }

    fn send_single_fragment(&mut self, m: EncodedMessage<OutboundPlain<'_>>) {
        if m.typ == ContentType::Alert {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            let em = self.encrypt_state.encrypt_outgoing(m);
            self.queue_tls_message(em);
            return;
        }

        match self
            .encrypt_state
            .next_pre_encrypt_action()
        {
            PreEncryptAction::Nothing => {}

            // Close connection once we start to run out of
            // sequence space.
            PreEncryptAction::RefreshOrClose => {
                match self.negotiated_version {
                    Some(ProtocolVersion::TLSv1_3) => {
                        // driven by caller, as we don't have the `State` here
                        self.refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        return;
                    }
                }
            }

            // Refuse to wrap counter at all costs.  This
            // is basically untestable unfortunately.
            PreEncryptAction::Refuse => {
                return;
            }
        };

        let em = self.encrypt_state.encrypt_outgoing(m);
        self.queue_tls_message(em);
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

    fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        debug_assert!(self.encrypt_state.is_encrypting());
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: EncodedMessage<OutboundOpaque>) {
        self.perhaps_write_key_update();
        self.sendable_tls.append(m.encode());
    }

    pub(crate) fn perhaps_write_key_update(&mut self) {
        if let Some(message) = self.queued_key_update_message.take() {
            self.sendable_tls.append(message);
        }
    }

    /// Send a raw TLS message, fragmenting it if needed.
    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        if !must_encrypt {
            let msg = &m.into();
            let iter = self
                .message_fragmenter
                .fragment_message(msg);
            for m in iter {
                self.queue_tls_message(m.to_unencrypted_opaque());
            }
        } else {
            self.send_msg_encrypt(m.into());
        }
    }

    fn send_close_notify(&mut self) {
        if self.has_sent_close_notify {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.has_sent_close_notify = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
    }

    #[expect(dead_code)]
    pub(crate) fn eager_send_close_notify(
        &mut self,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.send_close_notify();
        self.check_required_size(outgoing_tls, [].into_iter())?;
        Ok(self.write_fragments(outgoing_tls, [].into_iter()))
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
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

    fn check_required_size<'a>(
        &self,
        outgoing_tls: &[u8],
        fragments: impl Iterator<Item = EncodedMessage<OutboundPlain<'a>>>,
    ) -> Result<(), EncryptError> {
        let mut required_size = self.sendable_tls.len();

        for m in fragments {
            required_size += m.encoded_len(&self.encrypt_state);
        }

        if required_size > outgoing_tls.len() {
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size,
            }));
        }

        Ok(())
    }

    fn write_fragments<'a>(
        &mut self,
        outgoing_tls: &mut [u8],
        fragments: impl Iterator<Item = EncodedMessage<OutboundPlain<'a>>>,
    ) -> usize {
        let mut written = 0;

        // Any pre-existing encrypted messages in `sendable_tls` must
        // be output before encrypting any of the `fragments`.
        while let Some(message) = self.sendable_tls.pop() {
            let len = message.len();
            outgoing_tls[written..written + len].copy_from_slice(&message);
            written += len;
        }

        for m in fragments {
            let em = self
                .encrypt_state
                .encrypt_outgoing(m)
                .encode();

            let len = em.len();
            outgoing_tls[written..written + len].copy_from_slice(&em);
            written += len;
        }

        written
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    pub(crate) fn ensure_key_update_queued(&mut self) -> bool {
        if self.queued_key_update_message.is_some() {
            return false;
        }
        let message = EncodedMessage::<Payload<'static>>::from(Message::build_key_update_notify());
        self.queued_key_update_message = Some(
            self.encrypt_state
                .encrypt_outgoing(message.borrow_outbound())
                .encode(),
        );
        true
    }
}

impl Output for SendPath {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::EncryptMessage(m) => self.send_msg(m, true),
            Event::MaybeKeyUpdateRequest(ks) => {
                if self.ensure_key_update_queued() {
                    ks.update_encrypter_for_key_update(self);
                }
            }
            Event::MessageEncrypter { encrypter, limit } => self
                .encrypt_state
                .set_message_encrypter(encrypter, limit),
            Event::PlainMessage(m) => self.send_msg(m, false),
            Event::ProtocolVersion(ver) => self.negotiated_version = Some(ver),
            Event::SendAlert(level, desc) => self.send_alert(level, desc),
            Event::StartOutgoingTraffic | Event::StartTraffic => self.start_outgoing_traffic(),
            _ => unreachable!(),
        }
    }
}

impl Default for SendPath {
    fn default() -> Self {
        Self {
            encrypt_state: EncryptionState::new(),
            may_send_application_data: false,
            has_sent_fatal_alert: false,
            has_sent_close_notify: false,
            message_fragmenter: MessageFragmenter::default(),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            queued_key_update_message: None,
            refresh_traffic_keys_pending: false,
            negotiated_version: None,
        }
    }
}

pub(crate) struct ReceivePath {
    side: Side,
    pub(crate) decrypt_state: DecryptionState,
    may_receive_application_data: bool,
    /// If the peer has signaled end of stream.
    pub(crate) has_received_close_notify: bool,
    pub(crate) has_seen_eof: bool,
    temper_counters: TemperCounters,
    negotiated_version: Option<ProtocolVersion>,
    pub(crate) hs_deframer: HandshakeDeframer,

    /// We limit consecutive empty fragments to avoid a route for the peer to send
    /// us significant but fruitless traffic.
    pub(crate) seen_consecutive_empty_fragments: u8,
}

impl ReceivePath {
    fn new(side: Side) -> Self {
        Self {
            side,
            decrypt_state: DecryptionState::new(),
            may_receive_application_data: false,
            has_received_close_notify: false,
            has_seen_eof: false,
            temper_counters: TemperCounters::default(),
            negotiated_version: None,
            hs_deframer: HandshakeDeframer::default(),
            seen_consecutive_empty_fragments: 0,
        }
    }

    /// Pull a message out of the deframer and send any messages that need to be sent as a result.
    pub(crate) fn deframe<'b>(
        &mut self,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<Decrypted<'b>>, Error> {
        // before processing any more of `buffer`, return any extant messages from `hs_deframer`
        if self.hs_deframer.has_message_ready() {
            Ok(self.take_handshake_message(buffer, buffer_progress))
        } else {
            self.process_more_input(buffer, buffer_progress)
        }
    }

    fn take_handshake_message<'b>(
        &mut self,
        buffer: &'b [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Option<Decrypted<'b>> {
        self.hs_deframer
            .iter(buffer)
            .next()
            .map(|(message, discard)| {
                buffer_progress.add_discard(discard);
                Decrypted {
                    want_close_before_decrypt: false,
                    plaintext: message,
                }
            })
    }

    fn process_more_input<'b>(
        &mut self,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<Decrypted<'b>>, Error> {
        let version_is_tls13 = matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3));

        let locator = Locator::new(buffer);

        loop {
            let mut iter = DeframerIter::new(&mut buffer[buffer_progress.processed()..]);

            let (message, processed) = loop {
                let message = match iter.next().transpose() {
                    Ok(Some(message)) => message,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(err),
                };

                let allowed_plaintext = match message.typ {
                    // CCS messages are always plaintext.
                    ContentType::ChangeCipherSpec => true,
                    // Alerts are allowed to be plaintext if-and-only-if:
                    // * The negotiated protocol version is TLS 1.3. - In TLS 1.2 it is unambiguous when
                    //   keying changes based on the CCS message. Only TLS 1.3 requires these heuristics.
                    // * We have not yet decrypted any messages from the peer - if we have we don't
                    //   expect any plaintext.
                    // * The payload size is indicative of a plaintext alert message.
                    ContentType::Alert
                        if version_is_tls13
                            && !self.decrypt_state.has_decrypted()
                            && message.payload.len() <= 2 =>
                    {
                        true
                    }
                    // In other circumstances, we expect all messages to be encrypted.
                    _ => false,
                };

                if allowed_plaintext && !self.hs_deframer.is_active() {
                    break (
                        Decrypted {
                            plaintext: message.into_plain_message(),
                            want_close_before_decrypt: false,
                        },
                        iter.bytes_consumed(),
                    );
                }

                let message = match self
                    .decrypt_state
                    .decrypt_incoming(message)
                {
                    // failed decryption during trial decryption is not allowed to be
                    // interleaved with partial handshake data.
                    Ok(None) if self.hs_deframer.aligned().is_none() => {
                        return Err(
                            PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage.into(),
                        );
                    }

                    // failed decryption during trial decryption.
                    Ok(None) => continue,

                    Ok(Some(message)) => message,

                    Err(err) => return Err(err),
                };

                break (message, iter.bytes_consumed());
            };

            let Decrypted {
                plaintext: message,
                want_close_before_decrypt,
            } = message;

            if self.hs_deframer.aligned().is_none() && message.typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage.into());
            }

            match message.payload.len() {
                0 => {
                    if self.seen_consecutive_empty_fragments
                        == ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX
                    {
                        return Err(PeerMisbehaved::TooManyEmptyFragments.into());
                    }
                    self.seen_consecutive_empty_fragments += 1;
                }
                _ => {
                    self.seen_consecutive_empty_fragments = 0;
                }
            };

            buffer_progress.add_processed(processed);

            // do an end-run around the borrow checker, converting `message` (containing
            // a borrowed slice) to an unborrowed one (containing a `Range` into the
            // same buffer).  the reborrow happens inside the branch that returns the
            // message.
            //
            // is fixed by -Zpolonius
            // https://github.com/rust-lang/rfcs/blob/master/text/2094-nll.md#problem-case-3-conditional-control-flow-across-functions
            let unborrowed = InboundUnborrowedMessage::unborrow(&locator, message);

            if unborrowed.typ != ContentType::Handshake {
                let message = unborrowed.reborrow(&Delocator::new(buffer));
                buffer_progress.add_discard(processed);
                return Ok(Some(Decrypted {
                    plaintext: message,
                    want_close_before_decrypt,
                }));
            }

            let message = unborrowed.reborrow(&Delocator::new(buffer));
            self.hs_deframer
                .input_message(message, &locator, buffer_progress.processed());
            self.hs_deframer.coalesce(buffer)?;

            if self.hs_deframer.has_message_ready() {
                // trial decryption finishes with the first handshake message after it started.
                self.decrypt_state
                    .finish_trial_decryption();

                return Ok(self
                    .take_handshake_message(buffer, buffer_progress)
                    .map(|decrypted| Decrypted {
                        plaintext: decrypted.plaintext,
                        want_close_before_decrypt,
                    }));
            }
        }
    }

    fn drop_tls13_ccs(&mut self, msg: &EncodedMessage<&'_ [u8]>) -> Result<bool, Error> {
        if self.may_receive_application_data
            || !matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
        {
            return Ok(false);
        }

        if !msg.is_valid_ccs() {
            // "An implementation which receives any other change_cipher_spec value or
            //  which receives a protected change_cipher_spec record MUST abort the
            //  handshake with an "unexpected_message" alert."
            return Err(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.into());
        }

        self.temper_counters
            .received_tls13_change_cipher_spec()?;
        Ok(true)
    }

    fn parse_and_maybe_drop<'a>(
        &mut self,
        msg: &'a EncodedMessage<&'a [u8]>,
        send_path: &mut dyn Output,
    ) -> Result<Option<Message<'a>>, Error> {
        // Now we can fully parse the message payload.
        let msg = Message::try_from(msg)?;

        // For alerts, we have separate logic.
        if let MessagePayload::Alert(alert) = &msg.payload {
            self.process_alert(alert)?;
            return Ok(None);
        }

        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.reject_renegotiation_request(&msg, send_path)? {
            return Ok(None);
        }

        Ok(Some(msg))
    }

    fn reject_renegotiation_request(
        &mut self,
        msg: &Message<'_>,
        output: &mut dyn Output,
    ) -> Result<bool, Error> {
        if !self.may_receive_application_data
            || matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
        {
            return Ok(false);
        }

        let reject_ty = match self.side {
            Side::Client => HandshakeType::HelloRequest,
            Side::Server => HandshakeType::ClientHello,
        };

        if msg.handshake_type() != Some(reject_ty) {
            return Ok(false);
        }
        self.temper_counters
            .received_renegotiation_request()?;
        let desc = AlertDescription::NoRenegotiation;
        warn!("sending warning alert {desc:?}");
        output.emit(Event::SendAlert(AlertLevel::Warning, desc));
        Ok(true)
    }

    pub(crate) fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        // Reject unknown AlertLevels.
        if let AlertLevel::Unknown(level) = alert.level {
            return Err(PeerMisbehaved::IllegalAlertLevel(level, alert.description).into());
        }

        // If we get a CloseNotify, make a note to declare EOF to our
        // caller.  But do not treat unauthenticated alerts like this.
        if self.may_receive_application_data && alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
        // (except, for no good reason, user_cancelled).
        let err = Error::AlertReceived(alert.description);
        if alert.level == AlertLevel::Warning {
            self.temper_counters
                .received_warning_alert()?;
            if matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
                && alert.description != AlertDescription::UserCanceled
            {
                return Err(PeerMisbehaved::IllegalWarningAlert(alert.description).into());
            }

            // Some implementations send pointless `user_canceled` alerts, don't log them
            // in release mode (https://bugs.openjdk.org/browse/JDK-8323517).
            if alert.description != AlertDescription::UserCanceled || cfg!(debug_assertions) {
                warn!("TLS alert warning received: {alert:?}");
            }

            return Ok(());
        }

        Err(err)
    }
}

impl Output for ReceivePath {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::MessageDecrypter { decrypter, proof } => self
                .decrypt_state
                .set_message_decrypter(decrypter, &proof),
            Event::MessageDecrypterWithTrialDecryption {
                decrypter,
                max_length,
                proof,
            } => self
                .decrypt_state
                .set_message_decrypter_with_trial_decryption(decrypter, max_length, &proof),
            Event::ProtocolVersion(ver) => self.negotiated_version = Some(ver),
            Event::StartTraffic => self.may_receive_application_data = true,
            _ => unreachable!(),
        }
    }
}

/// Describes which sort of handshake happened.
#[derive(Debug, PartialEq, Clone, Copy)]
#[non_exhaustive]
pub enum HandshakeKind {
    /// A full handshake.
    ///
    /// This is the typical TLS connection initiation process when resumption is
    /// not yet unavailable, and the initial `ClientHello` was accepted by the server.
    Full,

    /// A full TLS1.3 handshake, with an extra round-trip for a `HelloRetryRequest`.
    ///
    /// The server can respond with a `HelloRetryRequest` if the initial `ClientHello`
    /// is unacceptable for several reasons, the most likely being if no supported key
    /// shares were offered by the client.
    FullWithHelloRetryRequest,

    /// A resumed handshake.
    ///
    /// Resumed handshakes involve fewer round trips and less cryptography than
    /// full ones, but can only happen when the peers have previously done a full
    /// handshake together, and then remember data about it.
    Resumed,

    /// A resumed handshake, with an extra round-trip for a `HelloRetryRequest`.
    ///
    /// The server can respond with a `HelloRetryRequest` if the initial `ClientHello`
    /// is unacceptable for several reasons, but this does not prevent the client
    /// from resuming.
    ResumedWithHelloRetryRequest,
}

pub(crate) trait State: Send + Sync {
    fn handle<'m>(
        self: Box<Self>,
        input: Input<'m>,
        output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error>;

    fn send_key_update_request(&mut self, _output: &mut dyn Output) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn handle_decrypt_error(&self) {}

    fn set_resumption_data(&mut self, _resumption_data: &[u8]) -> Result<(), Error> {
        Err(ApiMisuse::ResumptionDataProvidedTooLate.into())
    }

    fn into_external_state(
        self: Box<Self>,
    ) -> Result<(PartiallyExtractedSecrets, Box<dyn KernelState + 'static>), Error> {
        Err(Error::HandshakeNotComplete)
    }
}

struct CaptureAppData<'a> {
    data: &'a mut dyn Output,
    /// Store a [`Locator`] initialized from the current receive buffer
    ///
    /// Allows received plaintext data to be unborrowed and stored in
    /// `received_plaintext` for in-place decryption.
    plaintext_locator: &'a Locator,
    /// Unborrowed received plaintext data
    ///
    /// Set if plaintext data was received.
    ///
    /// Plaintext data may be reborrowed using a [`Delocator`] which was
    /// initialized from the same slice as `plaintext_locator`.
    received_plaintext: &'a mut Option<UnborrowedPayload>,
}

impl Output for CaptureAppData<'_> {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::ApplicationData(payload) => {
                // Receive plaintext data [`Payload<'_>`].
                //
                // Since [`Context`] does not hold a lifetime to the receive buffer the
                // passed [`Payload`] will have it's lifetime erased by storing an index
                // into the receive buffer as an [`UnborrowedPayload`]. This enables the
                // data to be later reborrowed after it has been decrypted in-place.
                let previous = self
                    .received_plaintext
                    .replace(UnborrowedPayload::unborrow(self.plaintext_locator, payload));
                debug_assert!(previous.is_none(), "overwrote plaintext data");
            }
            _ => self.data.emit(ev),
        }
    }
}

pub(crate) struct Input<'a> {
    pub(crate) message: Message<'a>,
    pub(crate) aligned_handshake: Option<HandshakeAlignedProof>,
}

impl Input<'_> {
    // Changing the keys must not span any fragmented handshake
    // messages.  Otherwise the defragmented messages will have
    // been protected with two different record layer protections,
    // which is illegal.  Not mentioned in RFC.
    pub(crate) fn check_aligned_handshake(&self) -> Result<HandshakeAlignedProof, Error> {
        self.aligned_handshake
            .ok_or_else(|| PeerMisbehaved::KeyEpochWithPendingFragment.into())
    }
}

/// The route for handshake state machine to surface determinations about the connection.
pub(crate) trait Output {
    fn emit(&mut self, ev: Event<'_>);
}

/// The set of events output by the low-level handshake state machine.
pub(crate) enum Event<'a> {
    ApplicationData(Payload<'a>),
    ApplicationProtocol(ApplicationProtocol<'a>),
    CipherSuite(SupportedCipherSuite),
    EarlyApplicationData(Payload<'a>),
    EarlyData(EarlyDataEvent),
    EarlyExporter(Box<dyn Exporter>),
    EchStatus(EchStatus),
    EncryptMessage(Message<'a>),
    Exporter(Box<dyn Exporter>),
    HandshakeKind(HandshakeKind),
    KeyExchangeGroup(&'static dyn SupportedKxGroup),
    MaybeKeyUpdateRequest(&'a mut KeyScheduleTrafficSend),
    MessageDecrypter {
        decrypter: Box<dyn MessageDecrypter>,
        proof: HandshakeAlignedProof,
    },
    MessageDecrypterWithTrialDecryption {
        decrypter: Box<dyn MessageDecrypter>,
        max_length: usize,
        proof: HandshakeAlignedProof,
    },
    MessageEncrypter {
        encrypter: Box<dyn MessageEncrypter>,
        limit: u64,
    },
    PeerIdentity(Identity<'static>),
    PlainMessage(Message<'a>),
    ProtocolVersion(ProtocolVersion),
    QuicEarlySecret(Option<OkmBlock>),
    QuicHandshakeSecrets(quic::Secrets),
    QuicTrafficSecrets(quic::Secrets),
    QuicTransportParameters(Vec<u8>),
    ReceivedServerName(Option<DnsName<'static>>),
    ReceivedTicket,
    ResumptionData(Vec<u8>),
    SendAlert(AlertLevel, AlertDescription),
    /// Mark the connection as ready to send application data.
    StartOutgoingTraffic,
    /// Mark the connection as ready to send and receive application data.
    StartTraffic,
}

impl Event<'_> {
    fn disposition(&self) -> EventDisposition {
        match self {
            // message dispatch
            Event::EncryptMessage(_) | Event::PlainMessage(_) => EventDisposition::MessageOutput,

            // send-specific events
            Event::MaybeKeyUpdateRequest(_)
            | Event::MessageEncrypter { .. }
            | Event::SendAlert(..)
            | Event::StartOutgoingTraffic => EventDisposition::SendPath,

            // recv-specific events
            Event::MessageDecrypter { .. } | Event::MessageDecrypterWithTrialDecryption { .. } => {
                EventDisposition::ReceivePath
            }

            // presentation API events
            Event::ApplicationProtocol(_)
            | Event::CipherSuite(_)
            | Event::EarlyExporter(_)
            | Event::Exporter(_)
            | Event::HandshakeKind(_)
            | Event::KeyExchangeGroup(_)
            | Event::PeerIdentity(_)
            | Event::ReceivedTicket => EventDisposition::ConnectionOutputs,

            // quic-specific events
            Event::QuicEarlySecret(_)
            | Event::QuicHandshakeSecrets(_)
            | Event::QuicTrafficSecrets(_)
            | Event::QuicTransportParameters(_) => EventDisposition::Quic,

            // broadcast events
            Event::ProtocolVersion(ver) => EventDisposition::ProtocolVersion(*ver),

            Event::StartTraffic => EventDisposition::StartTraffic,

            // higher levels
            Event::ApplicationData(_)
            | Event::EarlyApplicationData(_)
            | Event::EarlyData(_)
            | Event::EchStatus(_)
            | Event::ReceivedServerName(_)
            | Event::ResumptionData(_) => EventDisposition::SideSpecific,
        }
    }
}

/// Where a given `Event` should be routed to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EventDisposition {
    /// Events related to message output
    MessageOutput,

    /// Events destined for `SendPath`
    SendPath,

    /// Events destined for `ReceivePath`
    ReceivePath,

    /// Events destined for `ConnectionOutputs`
    ConnectionOutputs,

    /// Events related only to QUIC
    Quic,

    /// Event broadcast into `SendPath`, `ReceivePath`, and `ConnectionOutputs`
    ProtocolVersion(ProtocolVersion),

    /// Event broadcast into `SendPath` and `ReceivePath`
    StartTraffic,

    /// Events which are side (client or server) specific
    SideSpecific,
}

pub(crate) enum EarlyDataEvent {
    /// server: we accepted an early_data offer
    Accepted,
    /// client: declares the maximum amount of early data that can be sent
    Enable(usize),
    /// client: early data can now be sent using the record layer as normal
    Start,
    /// client: early data phase has closed after sending EndOfEarlyData
    Finished,
    /// client: the server rejected our request for early data
    Rejected,
}

/// Lifetime-erased equivalent to [`Payload`]
///
/// Stores an index into [`Payload`] buffer enabling in-place decryption
/// without holding a lifetime to the receive buffer.
pub(crate) enum UnborrowedPayload {
    Unborrowed(Range<usize>),
    Owned(Vec<u8>),
}

impl UnborrowedPayload {
    /// Convert [`Payload`] into [`UnborrowedPayload`] which stores a range
    /// into the [`Payload`] slice without borrowing such that it can be later
    /// reborrowed.
    ///
    /// # Panics
    ///
    /// Passed [`Locator`] must have been created from the same slice which
    /// contains the payload.
    pub(crate) fn unborrow(locator: &Locator, payload: Payload<'_>) -> Self {
        match payload {
            Payload::Borrowed(payload) => Self::Unborrowed(locator.locate(payload)),
            Payload::Owned(payload) => Self::Owned(payload),
        }
    }

    /// Convert [`UnborrowedPayload`] back into [`Payload`]
    ///
    /// # Panics
    ///
    /// Passed [`Delocator`] must have been created from the same slice that
    /// [`UnborrowedPayload`] was originally unborrowed from.
    pub(crate) fn reborrow<'b>(self, delocator: &Delocator<'b>) -> Payload<'b> {
        match self {
            Self::Unborrowed(range) => Payload::Borrowed(delocator.slice_from_range(&range)),
            Self::Owned(payload) => Payload::Owned(payload),
        }
    }
}

/// Side of the connection.
#[expect(clippy::exhaustive_enums)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Side {
    /// A client initiates the connection.
    Client,
    /// A server waits for a client to connect.
    Server,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Protocol {
    /// TCP-TLS, standardized in RFC5246 and RFC8446
    Tcp,
    /// QUIC, standardized in RFC9001
    Quic(quic::Version),
}

impl Protocol {
    pub(crate) fn is_quic(&self) -> bool {
        matches!(self, Self::Quic(_))
    }
}

/// Tracking technically-allowed protocol actions
/// that we limit to avoid denial-of-service vectors.
struct TemperCounters {
    allowed_warning_alerts: u8,
    allowed_renegotiation_requests: u8,
    allowed_middlebox_ccs: u8,
}

impl TemperCounters {
    fn received_warning_alert(&mut self) -> Result<(), Error> {
        match self.allowed_warning_alerts {
            0 => Err(PeerMisbehaved::TooManyWarningAlertsReceived.into()),
            _ => {
                self.allowed_warning_alerts -= 1;
                Ok(())
            }
        }
    }

    fn received_renegotiation_request(&mut self) -> Result<(), Error> {
        match self.allowed_renegotiation_requests {
            0 => Err(PeerMisbehaved::TooManyRenegotiationRequests.into()),
            _ => {
                self.allowed_renegotiation_requests -= 1;
                Ok(())
            }
        }
    }

    fn received_tls13_change_cipher_spec(&mut self) -> Result<(), Error> {
        match self.allowed_middlebox_ccs {
            0 => Err(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.into()),
            _ => {
                self.allowed_middlebox_ccs -= 1;
                Ok(())
            }
        }
    }
}

impl Default for TemperCounters {
    fn default() -> Self {
        Self {
            // cf. BoringSSL `kMaxWarningAlerts`
            // <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls_record.cc#L137-L139>
            allowed_warning_alerts: 4,

            // we rebuff renegotiation requests with a `NoRenegotiation` warning alerts.
            // a second request after this is fatal.
            allowed_renegotiation_requests: 1,

            // At most two CCS are allowed: one after each ClientHello (recall a second
            // ClientHello happens after a HelloRetryRequest).
            //
            // note BoringSSL allows up to 32.
            allowed_middlebox_ccs: 2,
        }
    }
}

pub(crate) struct TrafficTemperCounters {
    allowed_key_update_requests: u8,
}

impl TrafficTemperCounters {
    pub(crate) fn received_key_update_request(&mut self) -> Result<(), Error> {
        match self.allowed_key_update_requests {
            0 => Err(PeerMisbehaved::TooManyKeyUpdateRequests.into()),
            _ => {
                self.allowed_key_update_requests -= 1;
                Ok(())
            }
        }
    }

    pub(crate) fn received_app_data(&mut self) {
        self.allowed_key_update_requests = Self::INITIAL_KEY_UPDATE_REQUESTS;
    }

    // cf. BoringSSL `kMaxKeyUpdates`
    // <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls13_both.cc#L35-L38>
    const INITIAL_KEY_UPDATE_REQUESTS: u8 = 32;
}

impl Default for TrafficTemperCounters {
    fn default() -> Self {
        Self {
            allowed_key_update_requests: Self::INITIAL_KEY_UPDATE_REQUESTS,
        }
    }
}

pub(crate) struct HandshakeFlight<'a, const TLS13: bool> {
    pub(crate) transcript: &'a mut HandshakeHash,
    body: Vec<u8>,
}

impl<'a, const TLS13: bool> HandshakeFlight<'a, TLS13> {
    pub(crate) fn new(transcript: &'a mut HandshakeHash) -> Self {
        Self {
            transcript,
            body: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, hs: HandshakeMessagePayload<'_>) {
        let start_len = self.body.len();
        hs.encode(&mut self.body);
        self.transcript
            .add(&self.body[start_len..]);
    }

    pub(crate) fn finish(self, output: &mut dyn Output) {
        let m = Message {
            version: match TLS13 {
                true => ProtocolVersion::TLSv1_3,
                false => ProtocolVersion::TLSv1_2,
            },
            payload: MessagePayload::HandshakeFlight(Payload::new(self.body)),
        };

        output.emit(match TLS13 {
            true => Event::EncryptMessage(m),
            false => Event::PlainMessage(m),
        });
    }
}

pub(crate) type HandshakeFlightTls12<'a> = HandshakeFlight<'a, false>;
pub(crate) type HandshakeFlightTls13<'a> = HandshakeFlight<'a, true>;

/// An [`EncodedMessage<Payload<'_>>`] which does not borrow its payload, but
/// references a range that can later be borrowed.
struct InboundUnborrowedMessage {
    typ: ContentType,
    version: ProtocolVersion,
    bounds: Range<usize>,
}

impl InboundUnborrowedMessage {
    fn unborrow(locator: &Locator, msg: EncodedMessage<&'_ [u8]>) -> Self {
        Self {
            typ: msg.typ,
            version: msg.version,
            bounds: locator.locate(msg.payload),
        }
    }

    fn reborrow<'b>(self, delocator: &Delocator<'b>) -> EncodedMessage<&'b [u8]> {
        EncodedMessage {
            typ: self.typ,
            version: self.version,
            payload: delocator.slice_from_range(&self.bounds),
        }
    }
}

/// cf. BoringSSL's `kMaxEmptyRecords`
/// <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls_record.cc#L124-L128>
const ALLOWED_CONSECUTIVE_EMPTY_FRAGMENTS_MAX: u8 = 32;

pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
