use core::fmt;
use core::ops::{Deref, DerefMut};
use std::vec::Vec;

use pki_types::ServerName;

use crate::client::{ClientSide, EchStatus, hs, tls12, tls13};
use crate::common_state::Protocol;
use crate::conn::ConnectionCore;
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

    /// Early data capability is available for this peer and can be input into this object.
    SendEarlyData(SendEarlyData),

    /// We are awaiting handshake data from the peer.
    AwaitServerFlight(AwaitServerFlight),

    /// The peer's identity should be verified.
    VerifyServerIdentity(VerifyServerIdentity),

    /// Our credentials should be selected and supplied for this peer.
    ProvideCredential(ProvideCredential),

    /// The handshake has completed and application data may now flow.
    Traffic(ClientTraffic),
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
        let inner = ConnectionCore::for_client(config, name, input, Protocol::Tcp)?;

        let next = match inner.side.early_data_is_enabled() {
            true => |inner| Self::SendEarlyData(SendEarlyData { inner }),
            false => |inner| Self::AwaitServerFlight(AwaitServerFlight { inner }),
        };

        Ok(Self::SendClientFlight(SendClientFlight { inner, next }))
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        match self {
            Self::SendClientFlight(st) => st.inner.side.ech_status(),
            Self::SendEarlyData(st) => st.inner.side.ech_status(),
            Self::AwaitServerFlight(st) => st.inner.side.ech_status(),
            Self::VerifyServerIdentity(_) => todo!(),
            Self::ProvideCredential(_) => todo!(),
            Self::Traffic(traffic) => traffic.ech_status,
        }
    }
}

impl Deref for ClientState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SendClientFlight(st) => &st.inner.common.outputs,
            Self::SendEarlyData(st) => &st.inner.common.outputs,
            Self::AwaitServerFlight(st) => &st.inner.common.outputs,
            Self::VerifyServerIdentity(_) => todo!(),
            Self::ProvideCredential(_) => todo!(),
            Self::Traffic(traffic) => &traffic.outputs,
        }
    }
}

impl DerefMut for ClientState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::SendClientFlight(st) => &mut st.inner.common.outputs,
            Self::SendEarlyData(st) => &mut st.inner.common.outputs,
            Self::AwaitServerFlight(st) => &mut st.inner.common.outputs,
            Self::VerifyServerIdentity(_) => todo!(),
            Self::ProvideCredential(_) => todo!(),
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
            Self::SendEarlyData(_) => f
                .debug_tuple("SendEarlyData")
                .finish_non_exhaustive(),
            Self::AwaitServerFlight(_) => f
                .debug_tuple("AwaitServerFlight")
                .finish_non_exhaustive(),
            Self::VerifyServerIdentity(_) => f
                .debug_tuple("VerifyServerIdentity")
                .finish_non_exhaustive(),
            Self::ProvideCredential(_) => f
                .debug_tuple("ProvideCredential")
                .finish_non_exhaustive(),
            Self::Traffic(_) => f
                .debug_tuple("Traffic")
                .finish_non_exhaustive(),
        }
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendClientFlight {
    inner: ConnectionCore<ClientSide>,
    next: fn(ConnectionCore<ClientSide>) -> ClientState,
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
    inner: ConnectionCore<ClientSide>,
}

impl AwaitServerFlight {
    /// Receive some data.
    ///
    /// Return the next state if reached, the current state if not, and an error if things are permenantly
    /// broken.  If an error occurs here is is fatal to the connection.
    pub fn input_data(
        mut self,
        input: &mut dyn TlsInputBuffer,
    ) -> Result<ClientState, ErrorWithAlert> {
        self.inner
            .process_new_packets(input, 1)
            .map_err(|err| ErrorWithAlert::new(err, &mut self.inner.common.send))?;

        if !self
            .inner
            .common
            .send
            .sendable_tls
            .is_empty()
        {
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
    inner: ConnectionCore<ClientSide>,
}

impl SendEarlyData {
    /// Write `data` as early data.
    ///
    /// The number of written bytes is returned.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let early_data = &mut self.inner.side.early_data;
        early_data
            .check_write(data.len())
            .map(|sz| {
                self.inner
                    .common
                    .send
                    .send_early_plaintext(&data[..sz])
            })
            .unwrap_or_default()
    }

    /// How many bytes may be sent as early data.
    pub fn bytes_left(&self) -> usize {
        self.inner.side.early_data.bytes_left()
    }

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

    /// Move to the next state, concluding writing of Early Data.
    pub fn into_next(self) -> ClientState {
        ClientState::AwaitServerFlight(AwaitServerFlight { inner: self.inner })
    }
}

pub struct VerifyServerIdentity;

pub struct ProvideCredential;

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

    pub outputs: ConnectionOutputs,

    early_data_was_accepted: bool,
    ech_status: EchStatus,
}

impl ClientTraffic {
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

impl From<ConnectionCore<ClientSide>> for ClientTraffic {
    fn from(inner: ConnectionCore<ClientSide>) -> Self {
        let early_data_was_accepted = inner.side.early_data.is_accepted();
        let ech_status = inner.side.ech_status();

        let CommonState {
            recv,
            send,
            outputs,
            ..
        } = inner.common;
        let send_mutex = Arc::new(Mutex::new(send));

        Self {
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
        }
    }
}

fn next_state(inner: ConnectionCore<ClientSide>) -> ClientState {
    match inner.state.as_ref() {
        Ok(
            hs::StateMachine::Tls12(tls12::StateMachine::ExpectTraffic(_))
            | hs::StateMachine::Tls13(tls13::StateMachine::ExpectTraffic(_)),
        ) => ClientState::Traffic(inner.into()),
        Ok(_) => ClientState::AwaitServerFlight(AwaitServerFlight { inner }),
        Err(_) => panic!("TODO: withdraw error fusing in core.state"),
    }
}
