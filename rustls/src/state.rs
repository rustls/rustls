use alloc::vec::Vec;
use core::ops::DerefMut;
use std::sync::MutexGuard;

use crate::common_state::{Output, ReceivePath, SendPath};
use crate::conn::ConnectionProcessor;
use crate::conn::unbuffered::{EncryptError, InsufficientSizeError};
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::error::ErrorWithAlert;
use crate::lock::Mutex;
use crate::msgs::Delocator;
pub use crate::msgs::{
    DeframerSliceBuffer as SliceInput, DeframerVecBuffer as BufferedInput, TlsInputBuffer,
};
use crate::sync::Arc;
use crate::{Error, SideData};

pub struct SendTraffic(pub(crate) Arc<Mutex<SendPath>>);

impl SendTraffic {
    /// Write application data to the peer.
    ///
    /// The TLS data to send to the peer is written into `output_buffer` and
    /// the number of bytes written are returned.  This data should then
    /// be communicated to the peer.
    pub fn write(
        &mut self,
        application_data: &[u8],
        output_buffer: &mut [u8],
    ) -> Result<usize, EncryptError> {
        let mut inner = self.0.lock().unwrap();
        inner.maybe_refresh_traffic_keys();
        inner.write_plaintext(application_data.into(), output_buffer)
    }

    /// Write application data to the peer.
    ///
    /// The TLS data to send to the peer is returned.  This data should then
    /// be communicated to the peer.
    pub fn write_into_vec(
        &mut self,
        application_data: OutboundPlain<'_>,
    ) -> Result<Vec<u8>, EncryptError> {
        let mut inner = self.0.lock().unwrap();
        let mut buffer = Vec::with_capacity(inner.predict_required_len(application_data.clone()));
        let len = match inner.write_plaintext(application_data.clone(), &mut buffer) {
            Ok(len) => len,
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                buffer.resize(required_size, 0);
                inner.write_plaintext(application_data, &mut buffer)?
            }
            Err(e) => return Err(e),
        };
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Obtain any pending data to write to the peer.
    ///
    /// The TLS data to send to the peer is returned.  This data should then
    /// be communicated to the peer.
    pub fn take_data(&mut self) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .sendable_tls
            .pop()
    }

    /// Conclude sending traffic by sending a `close_notify` alert.
    ///
    /// The alert is written into a Vec which is returned.
    pub fn close(mut self) -> Result<Vec<u8>, EncryptError> {
        let mut inner = self.0.lock().unwrap();
        inner.send_close_notify();
        drop(inner);
        self.write_into_vec(OutboundPlain::Single(&[]))
    }

    /// Sends a TLS1.3 `key_update` message to refresh a connection's keys.
    ///
    /// This call refreshes our encryption keys. Once the peer receives the message,
    /// it refreshes _its_ encryption and decryption keys and sends a response.
    /// Once we receive that response, we refresh our decryption keys to match.
    /// At the end of this process, keys in both directions have been refreshed.
    ///
    /// Note that this process does not happen synchronously: this call just
    /// arranges that the `key_update` message will be included in the next
    /// `write()` output.
    ///
    /// This returns an error if a version prior to TLS1.3 is negotiated.
    ///
    /// # Usage advice
    /// Note that other implementations (including rustls) may enforce limits on
    /// the number of `key_update` messages allowed on a given connection to prevent
    /// denial of service.  Therefore, this should be called sparingly.
    ///
    /// rustls implicitly and automatically refreshes traffic keys when needed
    /// according to the selected cipher suite's cryptographic constraints.  There
    /// is therefore no need to call this manually to avoid cryptographic keys
    /// "wearing out".
    ///
    /// The main reason to call this manually is to roll keys when it is known
    /// a connection will be idle for a long period.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.0
            .lock()
            .unwrap()
            .refresh_traffic_keys()
    }
}

pub struct ReceiveTraffic<Side: SideData> {
    pub(crate) state: Side::StateMachine,
    pub(crate) recv: ReceivePath,
    pub(crate) send: Arc<Mutex<SendPath>>,
    pub(crate) pending_wake_sender: bool,
}

impl<Side: SideData> ReceiveTraffic<Side> {
    /// Receive application data from the peer.
    ///
    /// `received_tls` is an instance of the receive buffer abstraction containing
    /// TLS-protected data received from the peer.
    ///
    /// A [`ReceivedTrafficState`] is returned on success:
    ///
    /// - [`ReceivedTrafficState::Available`] if an application data message
    ///   has been received.
    /// - [`ReceivedTrafficState::Await`] if more IO is required.
    /// - [`ReceivedTrafficState::CloseNotify`] if the peer has cleanly
    ///   closed the receive direction of the connection.
    ///
    /// An error from this function permanently breaks the ability to receive
    /// data from the peer.  The error may be accompanied by a TLS alert,
    /// which can be obtained from the returned [`ErrorWithAlert`] and sent
    /// to the peer.  Following this, the underlying IO medium should be
    /// closed by the application.
    pub fn read<'a>(
        mut self,
        received_tls: &'a mut impl TlsInputBuffer,
    ) -> Result<ReceivedTrafficState<'a, Side>, ErrorWithAlert> {
        let mut send = SendAdapter::Unlocked(&self.send.as_ref());
        let mut proc = ConnectionProcessor::<Side> {
            state: Ok(self.state),
            recv: &mut self.recv,
            other: &mut send,
        };
        let received_plain = match proc.process_new_packets(received_tls, usize::MAX) {
            Ok(received_plain) => received_plain,
            Err(err) => {
                return Err(ErrorWithAlert::new(err, send.into_guard().deref_mut()));
            }
        };
        self.state = proc.state?;

        if let Some((unborrowed, mut progress)) = received_plain {
            let pending_discard = progress.take_discard();
            let Payload::Borrowed(data) =
                unborrowed.reborrow(&Delocator::new(received_tls.slice_mut()))
            else {
                return Err(Error::Unreachable("decrypted data should be borrowed").into());
            };
            drop(send);
            return Ok(ReceivedTrafficState::Available(ReceivedApplicationData {
                data,
                pending_discard,
                rt: self,
            }));
        }

        // If we locked the sender during that, it is still locked and we can provide
        // a hint to the caller they should pump the send side.
        if let SendAdapter::Locked(_) = send {
            self.pending_wake_sender = true;
        }

        drop(send);
        Ok(self.into_next_state())
    }

    pub fn tls13_tickets_received(&self) -> u32 {
        self.recv.tls13_tickets_received
    }

    fn into_next_state(mut self) -> ReceivedTrafficState<'static, Side> {
        if core::mem::take(&mut self.pending_wake_sender) {
            return ReceivedTrafficState::WakeSender(WakeSender { rt: self });
        }

        match self.recv.has_received_close_notify {
            true => ReceivedTrafficState::CloseNotify,
            false => ReceivedTrafficState::Await(self),
        }
    }
}

enum SendAdapter<'a> {
    Unlocked(&'a Mutex<SendPath>),
    Locked(MutexGuard<'a, SendPath>),
}

impl<'a> SendAdapter<'a> {
    fn ensure_locked(&mut self) {
        if let Self::Unlocked(m) = self {
            *self = Self::Locked(m.lock().unwrap());
        }
    }

    fn into_guard(mut self) -> MutexGuard<'a, SendPath> {
        self.ensure_locked();

        let Self::Locked(guard) = self else {
            unreachable!();
        };
        guard
    }
}

impl Output for SendAdapter<'_> {
    fn emit(&mut self, ev: crate::common_state::Event<'_>) {
        self.ensure_locked();
        let Self::Locked(guard) = self else {
            unreachable!();
        };
        guard.emit(ev)
    }
}

/// A state machine as a cycle between requiring further received TLS data,
/// and discharging received application data.
#[expect(clippy::exhaustive_enums)]
pub enum ReceivedTrafficState<'a, Side: SideData> {
    /// More input is required.
    ///
    /// Collect it into your input buffer, and then call [`ReceiveTraffic::read()`] again.
    Await(ReceiveTraffic<Side>),

    /// The sender may have new data to send.
    WakeSender(WakeSender<Side>),

    /// Some application data has been received.
    Available(ReceivedApplicationData<'a, Side>),

    /// We received a `close_notify` alert from the peer.
    ///
    /// This means the receive path is closed cleanly.
    CloseNotify,
}

/// Received application data.
pub struct ReceivedApplicationData<'a, Side: SideData> {
    /// The application data bytes.
    pub data: &'a [u8],

    /// How many bytes on the front of the original input buffer are associated
    /// with this data.
    ///
    /// This value should be added to the discard count of the original input
    /// buffer via [`ReceivedData::discard()`].
    ///
    /// Use [`ReceivedApplicationData::into_next()`] to obtain it while releasing
    /// the borrow on `data` (from the original input buffer).
    pending_discard: usize,

    rt: ReceiveTraffic<Side>,
}

impl<Side: SideData> ReceivedApplicationData<'_, Side> {
    /// Finish processing this received data.
    ///
    /// This yields the discard value that should now be applied to the originating
    /// buffer, and the next `ReceiveTraffic` state.
    pub fn into_next(self) -> (usize, ReceiveTraffic<Side>) {
        (self.pending_discard, self.rt)
    }
}

/// Notification that receiving data may have changed the state of the associated [`SendTraffic`]
///
/// The caller may wish to check whether there is any IO necessary on the send side.  If it does
/// not, and ignores this state, any pending new data to send will be included in the next
/// attempt to send data.
pub struct WakeSender<Side: SideData> {
    rt: ReceiveTraffic<Side>,
}

impl<Side: SideData> WakeSender<Side> {
    /// Continue receiving more data.
    pub fn into_next(self) -> ReceiveTraffic<Side> {
        self.rt
    }
}
