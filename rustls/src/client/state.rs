use core::mem;
use core::ops::Deref;
use std::vec::Vec;

use pki_types::ServerName;

use crate::client::ClientConnectionData;
use crate::common_state::{MidState, Protocol};
use crate::conn::ConnectionCore;
use crate::crypto::cipher::Payload;
use crate::error::{ApiMisuse, ErrorWithAlert};
use crate::lock::Mutex;
use crate::msgs::deframer::{Delocator, ReceivedData};
use crate::msgs::handshake::ClientExtensionsInput;
use crate::sync::Arc;
use crate::unbuffered::EncryptError;
use crate::{ClientConfig, ConnectionCommon, ConnectionOutputs, Error, KeyingMaterialExporter};

/// "Mid-level" state-based Client TLS API.
#[non_exhaustive]
pub enum ClientState {
    /// Handshake data should be transmitted to the peer.
    SendClientFlight(SendClientFlight),

    /// Early data capability is available for this peer and can be input into this object.
    SendEarlyData(SendEarlyData),

    /// We are awaiting handshake data from the peer.
    AwaitServerFlight(AwaitServerFlight),

    /// The peer's identity should be verified.
    VerifyServerIdentity(VerifyServerIdentity),

    /// Our credentials should be selected and supplied for this peer.
    ProvideCredential(ProvideCredential),

    /// The handshake has completed and application data may now flow.
    Traffic(SendTraffic, ReceiveTraffic, ConnectionOutputs),
}

impl ClientState {
    /// Create a new client connection.
    ///
    /// If `alpn_protocols` is [`None`], then the ALPN settings are obtained
    /// from [`ClientConfig::alpn_protocols`].
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Option<Vec<Vec<u8>>>,
    ) -> Result<Self, Error> {
        let input = ClientExtensionsInput::from_alpn(
            alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone()),
        );
        let inner = ConnectionCommon::from(ConnectionCore::for_client(
            config,
            name,
            input,
            Protocol::Tcp,
        )?);

        let next = match inner.core.side.early_data_is_enabled() {
            true => |inner| Self::SendEarlyData(SendEarlyData { inner }),
            false => |inner| Self::AwaitServerFlight(AwaitServerFlight { inner }),
        };

        Ok(Self::SendClientFlight(SendClientFlight { inner, next }))
    }
}

impl Deref for ClientState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SendClientFlight(st) => &st.inner.outputs,
            Self::SendEarlyData(st) => &st.inner.outputs,
            Self::AwaitServerFlight(st) => &st.inner.outputs,
            Self::VerifyServerIdentity(_) => todo!(),
            Self::ProvideCredential(_) => todo!(),
            Self::Traffic(_, _, outputs) => outputs,
        }
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendClientFlight {
    inner: ConnectionCommon<ClientConnectionData>,
    next: fn(ConnectionCommon<ClientConnectionData>) -> ClientState,
}

impl SendClientFlight {
    /// Obtain one TLS message that should be sent to the peer.
    ///
    /// If you wish to use vectored IO, call this function repeatedly
    /// to collect all messages before doing the IO.
    pub fn take_data(&mut self) -> Option<Vec<u8>> {
        self.inner.send.sendable_tls.pop()
    }

    /// Move to the next state, if possible.
    ///
    /// This returns the current state if there is remaining data to write.
    pub fn into_next(self) -> ClientState {
        match self.inner.send.sendable_tls.is_empty() {
            true => (self.next)(self.inner),
            false => ClientState::SendClientFlight(self),
        }
    }
}

/// A handshake state where we are awaiting handshake data from the peer.
pub struct AwaitServerFlight {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl AwaitServerFlight {
    /// Receive some data.
    ///
    /// Return the next state if reached, the current state if not, and an error if things are permenantly
    /// broken.  If an error occurs here is is fatal to the connection.
    pub fn input_data(mut self, input: &mut dyn ReceivedData) -> Result<ClientState, Error> {
        self.inner
            .core
            .process_new_packets(input)?;

        if !self.inner.send.sendable_tls.is_empty() {
            return Ok(ClientState::SendClientFlight(SendClientFlight {
                inner: self.inner,
                next: next_state,
            }));
        }

        Ok(next_state(self.inner))
    }
}

/// An opportunity exists to send early data.
pub struct SendEarlyData {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl SendEarlyData {
    /// Write `data` as early data.
    ///
    /// The number of written bytes is returned.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let early_data = &mut self.inner.core.side.early_data;
        early_data
            .check_write(data.len())
            .map(|sz| {
                self.inner
                    .send
                    .send_early_plaintext(&data[..sz])
            })
            .unwrap_or_default()
    }

    /// How many bytes may be sent as early data.
    pub fn bytes_left(&self) -> usize {
        self.inner
            .core
            .side
            .early_data
            .bytes_left()
    }

    /// TODO: copy docs
    pub fn early_exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self.inner.outputs.early_exporter.take() {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }

    /// Move to the next state, concluding writing of Early Data.
    pub fn into_next(self) -> ClientState {
        ClientState::AwaitServerFlight(AwaitServerFlight { inner: self.inner })
    }
}

/// TODO
pub struct VerifyServerIdentity;

/// TODO
pub struct ProvideCredential;

/// TODO: should be `SendTraffic(SendPath)`.
pub struct SendTraffic(Arc<Mutex<ConnectionCommon<ClientConnectionData>>>);

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
        inner.core.maybe_refresh_traffic_keys();
        inner
            .send
            .write_plaintext(application_data.into(), output_buffer)
    }

    /// Conclude sending traffic by sending a `close_notify` alert.
    ///
    /// The alert is written into `output_buffer` and the number of bytes written
    /// is returned.
    pub fn close(self, output_buffer: &mut [u8]) -> Result<usize, EncryptError> {
        let mut inner = self.0.lock().unwrap();
        inner
            .send
            .eager_send_close_notify(output_buffer)
    }
}

/// TODO: should be `ReceiveTraffic(ReceivePath)`.
pub struct ReceiveTraffic(Arc<Mutex<ConnectionCommon<ClientConnectionData>>>);

impl ReceiveTraffic {
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
        self,
        received_tls: &'a mut impl ReceivedData,
    ) -> Result<ReceivedTrafficState<'a>, ErrorWithAlert> {
        let mut inner = self.0.lock().unwrap();

        let received_plain = match inner
            .core
            .process_new_packets(received_tls)
        {
            Ok(received_plain) => received_plain,
            Err(err) => return Err(ErrorWithAlert::new(err, &mut inner.core.common_state.send)),
        };

        if let Some((unborrowed, mut progress)) = received_plain {
            let pending_discard = progress.take_discard();
            let Payload::Borrowed(data) =
                unborrowed.reborrow(&Delocator::new(received_tls.slice_mut()))
            else {
                return Err(Error::Unreachable("decrypted data should be borrowed").into());
            };
            drop(inner);
            return Ok(ReceivedTrafficState::Available(ReceivedApplicationData {
                data,
                pending_discard,
                rt: self,
            }));
        }

        let closed = inner.recv.has_received_close_notify;
        drop(inner);

        Ok(match closed {
            true => ReceivedTrafficState::CloseNotify,
            false => ReceivedTrafficState::Await(self),
        })
    }
}

/// A state machine as a cycle between requiring further received TLS data,
/// and discharging received application data.
#[expect(clippy::exhaustive_enums)]
pub enum ReceivedTrafficState<'a> {
    /// More input is required.
    ///
    /// Collect it into your input buffer, and then call [`ReceiveTraffic::read()`] again.
    Await(ReceiveTraffic),

    /// Some application data has been received.
    Available(ReceivedApplicationData<'a>),

    /// We received a `close_notify` alert from the peer.
    ///
    /// This means the receive path is closed cleanly.
    CloseNotify,
}

/// Received application data.
pub struct ReceivedApplicationData<'a> {
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

    rt: ReceiveTraffic,
}

impl ReceivedApplicationData<'_> {
    /// Finish processing this received data.
    ///
    /// This yields the discard value that should now be applied to the originating
    /// buffer, and the next `ReceiveTraffic` state.
    pub fn into_next(self) -> (usize, ReceiveTraffic) {
        (self.pending_discard, self.rt)
    }
}

fn next_state(mut inner: ConnectionCommon<ClientConnectionData>) -> ClientState {
    match inner
        .core
        .state
        .as_ref()
        .map(|s| s.mid_state())
        .expect("TODO: withdraw error fusing in state box")
    {
        MidState::AwaitPeerFlight => ClientState::AwaitServerFlight(AwaitServerFlight { inner }),
        MidState::Traffic => {
            /*
             * TODO: here we should deconstruct `inner` into two direction-specific objects,
             * forming the interior of `SendTraffic` and `ReceiveTraffic`. At the moment this is
             * difficult because we only have one `state: impl State` and both the send and
             * receive directions interact with this.
             *

            let CommonState {
                outputs,
                send,
                recv,
                ..
            } = inner.core.common_state;

             * Once we achieve that, we can also return `outputs` here (giving the caller ultimate
             * control over the lifetime of the large allocations hung off this.)  For now, we
             * steal its contents which achieves the same goal but risks someone seeing the empty
             * husk left behind.
             */
            let outputs = mem::take(&mut inner.outputs);
            let mutex = Arc::new(Mutex::new(inner));
            ClientState::Traffic(SendTraffic(mutex.clone()), ReceiveTraffic(mutex), outputs)
        }
    }
}
