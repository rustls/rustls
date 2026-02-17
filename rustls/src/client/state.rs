use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};

use pki_types::ServerName;

use crate::client::{ClientSide, EchStatus, hs, tls12, tls13};
use crate::common_state::Protocol;
use crate::conn::{ConnectionCore, ProcessFinishCondition};
use crate::crypto::cipher::OutboundPlain;
use crate::enums::ApplicationProtocol;
use crate::error::{ApiMisuse, ErrorWithAlert};
use crate::kernel::KernelConnection;
use crate::lock::Mutex;
use crate::msgs::{ClientExtensionsInput, TlsInputBuffer};
use crate::state::{ReceiveTraffic, SendTraffic};
use crate::sync::Arc;
use crate::{
    ClientConfig, CommonState, ConnectionOutputs, Error, ExtractedSecrets, KeyingMaterialExporter,
};

/// State-based Client TLS API.
#[non_exhaustive]
pub enum ClientState {
    /// Handshake data should be transmitted to the peer.
    SendClientFlight(SendClientFlight),

    /// We are awaiting handshake data from the peer.
    AwaitServerFlight(AwaitServerFlight),

    /// The handshake has completed and application data may now flow.
    Traffic(Box<ClientTraffic>),
}

impl ClientState {
    /// Create a new client connection.
    ///
    /// If `alpn_protocols` is [`None`], then the ALPN settings are obtained
    /// from [`ClientConfig::alpn_protocols`].
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Option<Vec<ApplicationProtocol<'static>>>,
    ) -> Result<Self, Error> {
        let input = ClientExtensionsInput::from_alpn(
            alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone()),
        );
        let inner = Box::new(ConnectionCore::for_client(
            config,
            name,
            input,
            Protocol::Tcp,
        )?);

        Ok(Self::SendClientFlight(SendClientFlight {
            inner,
            next: next_state,
        }))
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        match self {
            Self::SendClientFlight(st) => st.inner.side.ech_status(),
            Self::AwaitServerFlight(st) => st.inner.side.ech_status(),
            Self::Traffic(traffic) => traffic.ech_status,
        }
    }

    /// Returns true if the connection is currently reassembling a handshake message.
    ///
    /// This can be used to alter the caller's buffering strategy, as a larger
    /// buffer is required to reassemble a handshake message.
    pub fn joining_handshake_fragments(&self) -> bool {
        match self {
            Self::SendClientFlight(_) => false,
            Self::AwaitServerFlight(st) => st
                .inner
                .common
                .recv
                .hs_deframer
                .is_active(),
            Self::Traffic(st) => st
                .receive
                .as_ref()
                .map(|st| st.recv.hs_deframer.is_active())
                .unwrap_or_default(),
        }
    }
}

impl Deref for ClientState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SendClientFlight(st) => &st.inner.common.outputs,
            Self::AwaitServerFlight(st) => &st.inner.common.outputs,
            Self::Traffic(traffic) => &traffic.outputs,
        }
    }
}

impl DerefMut for ClientState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::SendClientFlight(st) => &mut st.inner.common.outputs,
            Self::AwaitServerFlight(st) => &mut st.inner.common.outputs,
            Self::Traffic(traffic) => &mut traffic.outputs,
        }
    }
}

impl fmt::Debug for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendClientFlight(_) => f
                .debug_tuple("SendClientFlight")
                .finish_non_exhaustive(),
            Self::AwaitServerFlight(_) => f
                .debug_tuple("AwaitServerFlight")
                .finish_non_exhaustive(),
            Self::Traffic(_) => f
                .debug_tuple("Traffic")
                .finish_non_exhaustive(),
        }
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendClientFlight {
    inner: Box<ConnectionCore<ClientSide>>,
    next: fn(Box<ConnectionCore<ClientSide>>) -> ClientState,
}

impl SendClientFlight {
    /// Obtain one TLS message that should be sent to the peer.
    ///
    /// If you wish to use vectored IO, call this function repeatedly
    /// to collect all messages before doing the IO.
    pub fn take_data(&mut self) -> Option<Vec<u8>> {
        self.inner
            .common
            .send
            .sendable_tls
            .pop()
    }

    /// Move to the next state, if possible.
    ///
    /// This returns the current state if there is remaining data to write.
    pub fn into_next(self) -> ClientState {
        match self
            .inner
            .common
            .send
            .sendable_tls
            .is_empty()
        {
            true => (self.next)(self.inner),
            false => ClientState::SendClientFlight(self),
        }
    }
}

/// A handshake state where we are awaiting handshake data from the peer.
pub struct AwaitServerFlight {
    inner: Box<ConnectionCore<ClientSide>>,
}

impl AwaitServerFlight {
    /// Receive some data.
    ///
    /// On success, the return value says whether any progress was made, and the next state.
    /// Not all the data is necessarily
    ///  is the number of bytes consumed from `input` (which is
    /// already communicated to the object via `discard()`) and the next state.
    ///
    /// Return the next state if reached, the current state if not, and an error if things are permenantly
    /// broken.  If an error occurs here is is fatal to the connection.
    pub fn input_data(
        mut self,
        input: &mut dyn TlsInputBuffer,
    ) -> Result<ClientState, ErrorWithAlert> {
        self.inner
            .process_new_packets(input, ProcessFinishCondition::Handshake)
            .map_err(|err| ErrorWithAlert::new(err, &mut self.inner.common.send))?;

        Ok(next_state(self.inner))
    }

    /// If it is currently possible to send early data, swap this object for that ability.
    ///
    /// If sending early data is not possible, `None` is returned.
    pub fn try_send_early_data(&mut self) -> Option<SendEarlyData<'_>> {
        match self.inner.side.early_data_is_enabled() {
            true => Some(SendEarlyData {
                inner: &mut self.inner,
            }),
            false => None,
        }
    }
}

/// An opportunity exists to send early data.
pub struct SendEarlyData<'a> {
    inner: &'a mut ConnectionCore<ClientSide>,
}

impl SendEarlyData<'_> {
    /// Write early data to the peer.
    ///
    /// The return value is the number of plaintext bytes written, and the TLS
    /// data. This data should then be communicated to the peer.
    pub fn write_into_vecs(&mut self, data: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
        let early_data = &mut self.inner.side.early_data;
        let Ok(plain_len @ 1..) = early_data.check_write(data.len()) else {
            return None;
        };
        let send = &mut self.inner.common.send;
        let application_data = OutboundPlain::from(&data[..plain_len]);
        let buffers = send
            .write_plaintext(application_data.clone())
            .ok()?;
        Some((plain_len, buffers))
    }

    /// How many bytes may be sent as early data.
    pub fn bytes_left(&self) -> usize {
        self.inner.side.early_data.bytes_left()
    }

    /// Returns the "early" exporter that can derive key material for use in early data
    ///
    /// See [RFC5705][] for general details on what exporters are, and [RFC8446 S7.5][] for
    /// specific details on the "early" exporter.
    ///
    /// **Beware** that the early exporter requires care, as it is subject to the same
    /// potential for replay as early data itself.  See [RFC8446 appendix E.5.1][] for
    /// more detail.
    ///
    /// This function can be called at most once per connection. This function will error:
    /// if called more than once per connection.
    ///
    /// If you are looking for the normal exporter, this is available from
    /// [`ConnectionOutputs::exporter()`].
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    /// [RFC8446 S7.5]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
    /// [RFC8446 appendix E.5.1]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5.1
    /// [`ConnectionOutputs::exporter()`]: crate::conn::ConnectionOutputs::exporter()
    pub fn early_exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match self
            .inner
            .common
            .outputs
            .early_exporter
            .take()
        {
            Some(inner) => Ok(KeyingMaterialExporter { inner }),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }
}

/// The handshake is complete and data may flow in both directions.
pub struct ClientTraffic {
    /// The receive side of the connection.
    ///
    /// This starts out as `Some()`, and callers may `take()` or insert `None`
    /// to denote closure of the send side.
    pub send: Option<SendTraffic>,

    /// The receive side of the connection.
    ///
    /// This starts out as `Some()`, and callers may `take()` or insert `None`
    /// to denote closure of the receive side (whether cleanly or otherwise).
    pub receive: Option<ReceiveTraffic<ClientSide>>,

    /// Facts about the connection established during the handshake.
    pub outputs: ConnectionOutputs,

    early_data_was_accepted: bool,
    ech_status: EchStatus,
}

impl ClientTraffic {
    /// Converts the connection into a [`KernelConnection`] for use with KTLS.
    pub fn dangerous_into_kernel_connection(
        mut self,
    ) -> Result<(ExtractedSecrets, KernelConnection<ClientSide>), Error> {
        let receive = self
            .receive
            .take()
            .ok_or_else(|| Error::ApiMisuse(ApiMisuse::ReceiveSideAlreadyClosed))?;
        let send = self
            .send
            .take()
            .ok_or_else(|| Error::ApiMisuse(ApiMisuse::SendSideAlreadyClosed))?;
        let c = ConnectionCore::from_parts_into_kernel_connection(
            &mut send.0.lock().unwrap(),
            receive.recv,
            self.outputs,
            receive.state,
        );
        c
    }

    pub(crate) fn is_early_data_accepted(&self) -> bool {
        self.early_data_was_accepted
    }
}

impl From<Box<ConnectionCore<ClientSide>>> for Box<ClientTraffic> {
    fn from(inner: Box<ConnectionCore<ClientSide>>) -> Self {
        let early_data_was_accepted = inner.side.early_data.is_accepted();
        let ech_status = inner.side.ech_status();

        let CommonState {
            recv,
            send,
            outputs,
            ..
        } = inner.common;
        let send_mutex = Arc::new(Mutex::new(send));

        Self::new(ClientTraffic {
            send: Some(SendTraffic(send_mutex.clone())),
            receive: Some(ReceiveTraffic {
                state: inner.state.unwrap(), // TODO
                recv,
                send: send_mutex,
                pending_wake_sender: false,
            }),
            outputs,
            early_data_was_accepted,
            ech_status,
        })
    }
}

fn next_state(inner: Box<ConnectionCore<ClientSide>>) -> ClientState {
    match inner.state.as_ref() {
        Ok(_)
            if !inner
                .common
                .send
                .sendable_tls
                .is_empty() =>
        {
            ClientState::SendClientFlight(SendClientFlight {
                inner,
                next: next_state,
            })
        }

        Ok(
            hs::StateMachine::Tls12(tls12::StateMachine::ExpectTraffic(_))
            | hs::StateMachine::Tls13(tls13::StateMachine::ExpectTraffic(_)),
        ) => ClientState::Traffic(inner.into()),

        Ok(_) => ClientState::AwaitServerFlight(AwaitServerFlight { inner }),
        Err(_) => panic!("TODO: withdraw error fusing in core.state"),
    }
}
