use core::marker::PhantomData;
use core::mem;
use core::ops::Range;

use super::SendOutput;
use crate::SideData;
use crate::common_state::{
    ConnectionOutput, ConnectionOutputs, Event, Output, OutputEvent, Side, UnborrowedPayload,
    maybe_send_fatal_alert,
};
use crate::conn::StateMachine;
use crate::conn::private::SideOutput;
use crate::crypto::cipher::{Decrypted, DecryptionState, EncodedMessage, Payload};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::error::{AlertDescription, Error, PeerMisbehaved};
use crate::log::{trace, warn};
use crate::msgs::{
    AlertLevel, AlertLevelName, AlertMessagePayload, BufferProgress, DeframerIter, Delocator,
    FragmentSpan, HandshakeAlignedProof, HandshakeDeframer, Locator, Message, MessagePayload,
    TlsInputBuffer,
};
use crate::quic::QuicOutput;

pub(crate) struct ReceivePath {
    side: Side,
    pub(crate) decrypt_state: DecryptionState,
    pub(crate) may_receive_application_data: bool,
    /// If the peer has signaled end of stream.
    pub(crate) has_received_close_notify: bool,
    temper_counters: TemperCounters,
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) hs_deframer: HandshakeDeframer,

    /// We limit consecutive empty fragments to avoid a route for the peer to send
    /// us significant but fruitless traffic.
    seen_consecutive_empty_fragments: u8,

    pub(crate) tls13_tickets_received: u32,
}

impl ReceivePath {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            side,
            decrypt_state: DecryptionState::new(),
            may_receive_application_data: false,
            has_received_close_notify: false,
            temper_counters: TemperCounters::default(),
            negotiated_version: None,
            hs_deframer: HandshakeDeframer::default(),
            seen_consecutive_empty_fragments: 0,
            tls13_tickets_received: 0,
        }
    }

    pub(super) fn process_new_packets<'a, 'm, Side: SideData>(
        &mut self,
        input: &'m mut dyn TlsInputBuffer,
        buffer_progress: &mut BufferProgress,
        state: &mut Result<Side::State, Error>,
        output: &mut JoinOutput<'a>,
    ) -> Result<Option<UnborrowedPayload>, Error> {
        let mut st = match mem::replace(state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                *state = Err(e.clone());
                return Err(e);
            }
        };

        let mut plaintext = None;
        while st.wants_input() {
            let buffer = input.slice_mut();
            let locator = Locator::new(buffer);
            let res = self.deframe(buffer, buffer_progress);

            let mut output = CaptureAppData {
                recv: self,
                other: &mut *output,
                plaintext_locator: &locator,
                received_plaintext: &mut plaintext,
                _message_lifetime: PhantomData,
            };

            let opt_msg = match res {
                Ok(opt_msg) => opt_msg,
                Err(e) => {
                    maybe_send_fatal_alert(output.other.send, &e);
                    if let Error::DecryptError = e {
                        st.handle_decrypt_error();
                    }
                    *state = Err(e.clone());
                    input.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            };

            let Some(msg) = opt_msg else {
                break;
            };

            let Decrypted {
                plaintext: msg,
                want_close_before_decrypt,
            } = msg;

            if want_close_before_decrypt {
                output
                    .other
                    .send
                    .send_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
            }

            let hs_aligned = output.recv.hs_deframer.aligned();
            let result = match output
                .recv
                .receive_message(msg, hs_aligned, output.other.send)
            {
                Ok(Some(input)) => st.handle(input, &mut output),
                Ok(None) => Ok(st),
                Err(e) => Err(e),
            };

            match result {
                Ok(new) => st = new,
                Err(e) => {
                    maybe_send_fatal_alert(output.other.send, &e);
                    *state = Err(e.clone());
                    input.discard(buffer_progress.take_discard());
                    return Err(e);
                }
            }

            if self.has_received_close_notify {
                // "Any data received after a closure alert has been received MUST be ignored."
                // -- <https://datatracker.ietf.org/doc/html/rfc8446#section-6.1>
                // This is data that has already been accepted in `read_tls`.
                let entirety = input.slice_mut().len();
                input.discard(entirety);
                break;
            }

            if let Some(payload) = plaintext.take() {
                *state = Ok(st);
                return Ok(Some(payload));
            }

            input.discard(buffer_progress.take_discard());
        }

        input.discard(buffer_progress.take_discard());
        *state = Ok(st);
        Ok(None)
    }

    /// Pull a message out of the deframer and send any messages that need to be sent as a result.
    fn deframe<'b>(
        &mut self,
        buffer: &'b mut [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Result<Option<Decrypted<'b>>, Error> {
        // before processing any more of `buffer`, return any extant messages from `hs_deframer`
        match self.hs_deframer.complete_span() {
            Some(span) => Ok(Some(self.take_handshake_message(
                span,
                buffer,
                buffer_progress,
            ))),
            None => self.process_more_input(buffer, buffer_progress),
        }
    }

    fn take_handshake_message<'b>(
        &mut self,
        span: FragmentSpan,
        buffer: &'b [u8],
        buffer_progress: &mut BufferProgress,
    ) -> Decrypted<'b> {
        let (message, discard) = self.hs_deframer.message(span, buffer);
        if let Some(discard) = discard {
            buffer_progress.add_discard(discard);
        }

        Decrypted {
            want_close_before_decrypt: false,
            plaintext: message,
        }
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

            let Some(span) = self.hs_deframer.complete_span() else {
                continue;
            };

            // trial decryption finishes with the first handshake message after it started.
            self.decrypt_state
                .finish_trial_decryption();

            let decrypted = self.take_handshake_message(span, buffer, buffer_progress);
            return Ok(Some(Decrypted {
                plaintext: decrypted.plaintext,
                want_close_before_decrypt,
            }));
        }
    }

    /// Take a TLS message `msg` and map it into an `Input`
    ///
    /// `Input` is the input to our state machine.
    ///
    /// The message is mapped into `None` if it should be dropped with no further
    /// action.
    ///
    /// Otherwise the caller must present the returned `Input` to the state machine to
    /// progress the connection.
    pub(crate) fn receive_message<'a>(
        &mut self,
        msg: EncodedMessage<&'a [u8]>,
        aligned_handshake: Option<HandshakeAlignedProof>,
        send: &mut dyn SendOutput,
    ) -> Result<Option<Input<'a>>, Error> {
        // Drop CCS messages during handshake in TLS1.3
        if msg.typ == ContentType::ChangeCipherSpec && self.drop_tls13_ccs(&msg)? {
            trace!("Dropping CCS");
            return Ok(None);
        }

        // Now we can fully parse the message payload.
        let message = Message::try_from(msg)?;

        // For alerts, we have separate logic.
        if let MessagePayload::Alert(alert) = &message.payload {
            self.process_alert(alert)?;
            return Ok(None);
        }

        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.reject_renegotiation_request(&message, send)? {
            return Ok(None);
        }

        Ok(Some(Input {
            message,
            aligned_handshake,
        }))
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

    fn reject_renegotiation_request(
        &mut self,
        msg: &Message<'_>,
        send: &mut dyn SendOutput,
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
        send.send_alert(AlertLevel::Warning, desc);
        Ok(true)
    }

    fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        // Reject unknown AlertLevels.
        if AlertLevelName::try_from(alert.level).is_err() {
            return Err(PeerMisbehaved::IllegalAlertLevel(alert.level.0, alert.description).into());
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

struct CaptureAppData<'a, 'j, 'm> {
    recv: &'a mut ReceivePath,
    other: &'a mut JoinOutput<'j>,
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
    _message_lifetime: PhantomData<&'m ()>,
}

impl<'m> Output<'m> for CaptureAppData<'_, '_, 'm> {
    fn emit(&mut self, ev: Event<'_>) {
        self.other.side.emit(ev)
    }

    fn output(&mut self, ev: OutputEvent<'_>) {
        if let OutputEvent::ProtocolVersion(ver) = ev {
            self.recv.negotiated_version = Some(ver);
            self.other.send.negotiated_version(ver);
        }
        self.other.outputs.handle(ev);
    }

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        match self.other.quic.as_deref_mut() {
            Some(quic) => quic.send_msg(m, must_encrypt),
            None => self
                .other
                .send
                .send_msg(m, must_encrypt),
        }
    }

    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        match &mut self.other.quic {
            Some(quic) => Some(*quic),
            None => None,
        }
    }

    fn received_plaintext(&mut self, payload: Payload<'m>) {
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

    fn start_traffic(&mut self) {
        self.recv.may_receive_application_data = true;
        self.other.send.start_traffic();
    }

    fn receive(&mut self) -> &mut ReceivePath {
        self.recv
    }

    fn send(&mut self) -> &mut dyn SendOutput {
        self.other.send
    }
}

pub(super) struct JoinOutput<'a> {
    pub(super) outputs: &'a mut ConnectionOutputs,
    pub(super) quic: Option<&'a mut dyn QuicOutput>,
    pub(super) send: &'a mut dyn SendOutput,
    pub(super) side: &'a mut dyn SideOutput,
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
