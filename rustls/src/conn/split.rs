use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;
use std::sync::MutexGuard;

use super::receive::{Discard, JoinOutput};
use crate::client::ClientSide;
use crate::common_state::UnborrowedPayload;
use crate::conn::kernel::KernelConnection;
use crate::conn::{
    ConnectionCommon, MessageIter, ReceivePath, SendOutput, SendPath, TlsInputBuffer,
};
use crate::crypto::cipher::{MessageEncrypter, OutboundPlain};
use crate::enums::ProtocolVersion;
use crate::error::AlertDescription;
use crate::lock::Mutex;
use crate::msgs::{AlertLevel, Delocator, Message};
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::{ConnectionOutputs, Error, ExtractedSecrets, SideData};

/// A post-handshake connection which has been split by direction.
///
/// Typically you will immediately destructure this type, and give the components
/// to different threads/handlers to progress separately.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct SplitConnection<Side: SideData> {
    /// The ability to encrypt data to be sent.
    pub send: SendTraffic,
    /// The ability to decrypt received data.
    pub receive: ReceiveTraffic<Side>,
    /// Facts about the connection established during the handshake.
    pub outputs: ConnectionOutputs,
}

impl<Side: SideData> SplitConnection<Side> {
    /// Extract secrets and a [`KernelConnection`], so they can be used when
    /// configuring kTLS, for example.
    ///
    /// Should be used with care as it exposes secret key material.
    ///
    /// The returned [`KernelConnection`] continues to own the connection's
    /// secrets, so it can compute new traffic secrets on key update and (for
    /// client connections) accept session tickets.  See the [`kernel`] module
    /// documentation for the details.
    ///
    /// This fails if the connection was not made with [`enable_secret_extraction`] set.
    ///
    /// [`kernel`]: crate::kernel
    /// [`enable_secret_extraction`]: crate::ClientConfig::enable_secret_extraction
    pub fn dangerous_into_kernel_connection(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Side>), Error> {
        let Self {
            send,
            receive,
            outputs,
        } = self;

        // drop our handle on the send path, so `receive` holds the only one.
        drop(send);

        let ReceiveTraffic {
            state, recv, send, ..
        } = receive;

        ConnectionCommon::<Side>::from_parts_into_kernel_connection(
            &mut send.lock().unwrap().send,
            recv,
            outputs,
            state,
        )
    }
}

impl<Side: SideData> TryFrom<ConnectionCommon<Side>> for SplitConnection<Side> {
    type Error = Error;

    fn try_from(conn: ConnectionCommon<Side>) -> Result<Self, Error> {
        let send = Arc::new(Mutex::new(SendInner {
            send: conn.common.send,
            aside_buffer: Vec::new(),
        }));
        let state = conn.state?;

        Ok(Self {
            send: SendTraffic(send.clone()),
            receive: ReceiveTraffic {
                state,
                recv: conn.common.recv,
                send,
                pending_flush_sender: false,
            },
            outputs: conn.common.outputs,
        })
    }
}

/// The send-side of a connection, after a successful handshake.
///
/// You can use this object to send data to the peer.
pub struct SendTraffic(pub(super) Arc<Mutex<SendInner>>);

impl SendTraffic {
    /// Write application data to the peer.
    ///
    /// The TLS data to send to the peer is written into `tls`. This data should then be
    /// communicated to the peer.
    ///
    /// When you need to handle a [`ReceiveTrafficState::FlushSender`] state, you can call this
    /// method with [`OutboundPlain::new_empty()`] to flush any pending TLS data to the peer.
    pub fn write(&mut self, application_data: OutboundPlain<'_>, tls: &mut Vec<u8>) {
        let mut inner = self.0.lock().unwrap();
        inner.pump(tls);
        inner
            .send
            .send_appdata_encrypt(application_data, tls);
    }

    /// Conclude sending traffic by sending a `close_notify` alert.
    ///
    /// The alert is written into `tls` along with any pending data.
    /// This data should then be communicated to the peer.
    ///
    /// This is the final possible operation with a [`SendTraffic`].
    pub fn close(self, tls: &mut Vec<u8>) {
        let mut inner = self.0.lock().unwrap();
        inner.pump(tls);
        inner.send.send_close_notify(tls);
        drop(inner);
    }

    /// Writes a TLS 1.3 `key_update` message into `tls` to refresh a connection's keys.
    ///
    /// The main reason to call this manually is to roll keys when it is known
    /// a connection will be idle for a long period.
    ///
    /// rustls implicitly and automatically refreshes traffic keys when needed
    /// according to the selected cipher suite's cryptographic constraints. There
    /// is therefore no need to call this manually to avoid cryptographic keys
    /// "wearing out".
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// This returns an error if a version prior to TLS1.3 is negotiated.
    ///
    /// # Usage advice
    /// Note that other implementations (including rustls) may enforce limits on
    /// the number of `key_update` messages allowed on a given connection to prevent
    /// denial of service. Therefore, this should be called sparingly.
    ///
    /// rustls only allows one outstanding request at a time; this function succeeds
    /// but sends nothing if a request is already in-flight.
    pub fn refresh_traffic_keys(&mut self, tls: &mut Vec<u8>) -> Result<(), Error> {
        let mut inner = self.0.lock().unwrap();
        inner.pump(tls);
        inner.send.refresh_traffic_keys(tls)
    }
}

impl fmt::Debug for SendTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SendTraffic")
            .finish_non_exhaustive()
    }
}

pub(super) struct SendInner {
    send: SendPath,
    aside_buffer: Vec<u8>,
}

impl SendInner {
    fn pump(&mut self, tls: &mut Vec<u8>) {
        tls.extend_from_slice(&self.aside_buffer);
        self.aside_buffer.clear();
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        self.send
            .send_alert(level, desc, &mut self.aside_buffer);
    }

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        self.send
            .send_msg(m, must_encrypt, &mut self.aside_buffer);
    }
}

/// The receive-side of a connection, after a successful handshake.
///
/// You can use this object to receive data from the peer.
pub struct ReceiveTraffic<Side: SideData> {
    pub(crate) state: Side::State,
    pub(crate) recv: ReceivePath,
    pub(super) send: Arc<Mutex<SendInner>>,
    pub(crate) pending_flush_sender: bool,
}

impl<Side: SideData> ReceiveTraffic<Side> {
    /// Receive application data from the peer.
    ///
    /// `received_tls` is an instance of the receive buffer abstraction containing
    /// TLS-protected data received from the peer.
    ///
    /// A [`ReceiveTrafficState`] is returned on success.
    ///
    /// An error from this function permanently breaks the ability to receive
    /// data from the peer. The error may be accompanied by a TLS alert,
    /// which is sent through the associated [`SendTraffic`].  Callers should
    /// treat errors received from this function in the same way as
    /// [`ReceiveTrafficState::FlushSender`] for this reason.
    pub fn read<'a>(
        self,
        input: &'a mut impl TlsInputBuffer,
    ) -> Result<ReceiveTrafficState<'a, Side>, Error> {
        let Self {
            state,
            mut recv,
            send,
            mut pending_flush_sender,
        } = self;

        let mut tls_unused = Vec::new();
        let mut send_adapter = SendAdapter::Unlocked(&send);
        let mut state = Ok(state);
        let output = JoinOutput {
            outputs: &mut Discard,
            quic: None,
            send: &mut send_adapter,
            side: &mut Discard,
        };

        let mut iter = MessageIter::<Side, _>::receive(
            input,
            &mut tls_unused,
            &mut state,
            &mut recv,
            output,
            true,
        );
        let received_plain = match iter.next() {
            Some(Ok(payload)) => Some(payload),
            Some(Err(error)) => return Err(error),
            None => None,
        };

        // nb. state consumed only on error.
        let state = state.unwrap();

        if let Some(unborrowed) = received_plain {
            let pending_discard = recv.deframer.take_discard();
            let UnborrowedPayload::Unborrowed(range) = unborrowed else {
                return Err(Error::Unreachable("decrypted data should be borrowed"));
            };

            if let SendAdapter::Locked { send_required, .. } = send_adapter {
                pending_flush_sender |= send_required;
            }

            drop(send_adapter);
            return Ok(ReceiveTrafficState::Available(ReceivedApplicationData {
                range,
                input,
                pending_discard,
                rt: Self {
                    state,
                    recv,
                    send,
                    pending_flush_sender,
                },
            }));
        }

        input.discard(recv.deframer.take_discard());

        // `SendAdapter` records whether a send-side action may be needed after the above
        // receive-side processing.  If the sender was not locked no change could be made to it.
        if let SendAdapter::Locked { send_required, .. } = send_adapter {
            pending_flush_sender |= send_required;
        }

        drop(send_adapter);

        let mut rt = Self {
            state,
            recv,
            send,
            pending_flush_sender,
        };

        if core::mem::take(&mut rt.pending_flush_sender) {
            return Ok(ReceiveTrafficState::FlushSender(FlushSender { rt }));
        }

        Ok(match rt.recv.has_received_close_notify {
            true => ReceiveTrafficState::CloseNotify,
            false => ReceiveTrafficState::ReadMore(rt),
        })
    }
}

impl ReceiveTraffic<ClientSide> {
    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.recv.tls13_tickets_received
    }
}

impl<Side: SideData> fmt::Debug for ReceiveTraffic<Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveTraffic")
            .finish_non_exhaustive()
    }
}

/// A state machine that cycles between requiring further received TLS data
/// and discharging received application data.
///
/// Each call to [`ReceiveTraffic::read()`] returns one of these states, and each
/// non-terminal state lets you obtain the next one: [`ReadMore`] by supplying more
/// input and calling [`read()`] again, and [`FlushSender`] / [`Available`]
/// through their `into_next()` methods. [`CloseNotify`] is terminal.
///
/// ```text
///            ╭────────────────╮
///   ╭───────▶│ ReceiveTraffic │
///   │        ╰───────┬────────╯
/// ReadMore           │ read(&mut input)
///   │                ▼
///   ╰────╭───────────────────────╮
///        │  ReceiveTrafficState  │──── CloseNotify ────▶ (terminal)
///   ╭───▶╰──┬────────────────────╯
///   │       │              │
///   │  FlushSender      Available
///   │  .into_next()    .into_next()
///   │       │              │
///   ╰───────┴──────────────╯
/// ```
///
/// - [`ReadMore`]: more TLS input is required. The variant holds the
///   `ReceiveTraffic`; collect more input and call [`read()`] on it again.
/// - [`FlushSender`]: receiving may have produced data to send. Make a note to
///   perform IO with the matching [`SendTraffic`], and then call
///   [`FlushSender::into_next()`] for the next state.
/// - [`Available`]: application data was received. Read it via
///   [`ReceivedApplicationData::data()`], then call
///   [`ReceivedApplicationData::into_next()`]: this discards the consumed input
///   and returns the next state.
/// - [`CloseNotify`]: the peer closed the receive direction cleanly. Terminal.
///
/// [`read()`]: ReceiveTraffic::read
/// [`ReadMore`]: ReceiveTrafficState::ReadMore
/// [`FlushSender`]: ReceiveTrafficState::FlushSender
/// [`Available`]: ReceiveTrafficState::Available
/// [`CloseNotify`]: ReceiveTrafficState::CloseNotify
#[expect(clippy::exhaustive_enums)]
pub enum ReceiveTrafficState<'a, Side: SideData> {
    /// More input is required.
    ///
    /// Collect it into your input buffer, and then call [`ReceiveTraffic::read()`] again.
    ReadMore(ReceiveTraffic<Side>),

    /// The sender may have new data to send.
    FlushSender(FlushSender<Side>),

    /// Some application data has been received.
    Available(ReceivedApplicationData<'a, Side>),

    /// We received a `close_notify` alert from the peer.
    ///
    /// This means the receive path is closed cleanly.
    CloseNotify,
}

impl<Side: SideData> fmt::Debug for ReceiveTrafficState<'_, Side> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadMore(_) => f
                .debug_tuple("ReadMore")
                .finish_non_exhaustive(),
            Self::FlushSender(_) => f
                .debug_tuple("FlushSender")
                .finish_non_exhaustive(),
            Self::Available(_) => f
                .debug_tuple("Available")
                .finish_non_exhaustive(),
            Self::CloseNotify => write!(f, "CloseNotify"),
        }
    }
}

/// Received application data.
pub struct ReceivedApplicationData<'a, Side: SideData> {
    /// The source buffer for the data.
    input: &'a mut dyn TlsInputBuffer,

    /// The span within the `received_tls` buffer holding the received data.
    range: Range<usize>,

    /// How many bytes on the front of the original input buffer are associated
    /// with this data.
    ///
    /// This value is added to the discard count of the original input
    /// buffer via [`TlsInputBuffer::discard()`].
    pending_discard: usize,

    rt: ReceiveTraffic<Side>,
}

impl<Side: SideData> ReceivedApplicationData<'_, Side> {
    /// Return the application data bytes.
    pub fn data(&mut self) -> &[u8] {
        Delocator::new(self.input.slice_mut()).slice_from_range(&self.range)
    }

    /// Finish processing this received data.
    ///
    /// This acts upon the source buffer (used with the [`ReceiveTraffic::read()`] call) to
    /// discard the received data.
    ///
    /// Returns the next [`ReceiveTrafficState`] state.
    pub fn into_next(mut self) -> ReceiveTrafficState<'static, Side> {
        self.input.discard(self.pending_discard);

        if core::mem::take(&mut self.rt.pending_flush_sender) {
            return ReceiveTrafficState::FlushSender(FlushSender { rt: self.rt });
        }

        match self.rt.recv.has_received_close_notify {
            true => ReceiveTrafficState::CloseNotify,
            false => ReceiveTrafficState::ReadMore(self.rt),
        }
    }
}

/// Notification that receiving data may have changed the state of the associated [`SendTraffic`]
///
/// The caller may wish to check whether there is any IO necessary on the send side. If it does
/// not, and ignores this state, any pending new data to send will be included in the next
/// attempt to send data.
pub struct FlushSender<Side: SideData> {
    rt: ReceiveTraffic<Side>,
}

impl<Side: SideData> FlushSender<Side> {
    /// Obtain the next receive-side state.
    pub fn into_next(self) -> ReceiveTrafficState<'static, Side> {
        match self.rt.recv.has_received_close_notify {
            true => ReceiveTrafficState::CloseNotify,
            false => ReceiveTrafficState::ReadMore(self.rt),
        }
    }
}

/// Allows the receive-side of the connection to manipulate the send-side.
///
/// It is important for performance and concurrency that the receive-side
/// does not regularly lock the send-side, so this is delayed until this
/// proves to be actually required (via [`SendOutput`] methods).
///
/// It is important for analysis that the lock, once taken, remains taken
/// for the remainder of the processing. This means that, for example,
/// a sequence of sent messages is not interleaved with others from another
/// thread.
pub(super) enum SendAdapter<'a> {
    Unlocked(&'a Mutex<SendInner>),
    Locked {
        guard: MutexGuard<'a, SendInner>,
        send_required: bool,
    },
}

impl<'a> SendAdapter<'a> {
    fn as_locked<'b>(&'b mut self, may_send: bool) -> &'b mut MutexGuard<'a, SendInner> {
        if let Self::Unlocked(m) = self {
            *self = Self::Locked {
                guard: m.lock().unwrap(),
                send_required: false,
            };
        }
        let Self::Locked {
            guard,
            send_required,
        } = self
        else {
            unreachable!();
        };
        *send_required |= may_send;
        guard
    }
}

impl SendOutput for SendAdapter<'_> {
    fn negotiated_version(&mut self, version: ProtocolVersion) {
        self.as_locked(false)
            .send
            .negotiated_version(version);
    }

    fn queue_requested_key_update(&mut self) {
        // waking the sender here is a policy decision to encourage timely execution of
        // the write-side key update, it is not strictly required at a protocol level.
        self.as_locked(true)
            .send
            .queue_requested_key_update();
    }

    fn note_key_update_response(&mut self) {
        self.as_locked(false)
            .send
            .note_key_update_response();
    }

    fn set_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>, max_messages: u64) {
        self.as_locked(false)
            .send
            .set_encrypter(cipher, max_messages);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        self.as_locked(false)
            .send
            .update_key_schedule(schedule);
    }

    fn send_alert(
        &mut self,
        level: AlertLevel,
        desc: AlertDescription,
        _wrong_thread_tls: &mut Vec<u8>,
    ) {
        self.as_locked(true)
            .send_alert(level, desc);
    }

    fn start_traffic(&mut self) {
        self.as_locked(false)
            .send
            .start_traffic();
    }

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool, _wrong_thread_tls: &mut Vec<u8>) {
        self.as_locked(true)
            .send_msg(m, must_encrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_provider::Tls13Cipher;

    #[test]
    fn send_adapter_flag() {
        let mut tls = Vec::new();
        assert!(!send_flag_for(
            |adapter| adapter.negotiated_version(ProtocolVersion::TLSv1_3)
        ));
        assert!(send_flag_for(|adapter| adapter.queue_requested_key_update()));
        assert!(!send_flag_for(|adapter| adapter.note_key_update_response()));
        assert!(!send_flag_for(
            |adapter| adapter.set_encrypter(Box::new(Tls13Cipher), 1234)
        ));
        // update_key_schedule too hard
        assert!(send_flag_for(|adapter| adapter.send_alert(
            AlertLevel::Fatal,
            AlertDescription::CertificateUnknown,
            &mut tls,
        )));
        assert!(!send_flag_for(|adapter| adapter.start_traffic()));
        assert!(send_flag_for(|adapter| adapter.send_msg(
            Message::build_key_update_notify(),
            false,
            &mut tls,
        )));
    }

    fn send_flag_for(f: impl FnOnce(&mut SendAdapter<'_>)) -> bool {
        let mut send = SendPath::default();
        send.set_encrypter(Box::new(Tls13Cipher), 1234);

        let send = Mutex::new(SendInner {
            send,
            aside_buffer: Vec::new(),
        });

        let mut adapter = SendAdapter::Unlocked(&send);
        f(&mut adapter);
        let SendAdapter::Locked { send_required, .. } = adapter else {
            panic!("expected to find SendAdapter::Locked");
        };
        send_required
    }
}
