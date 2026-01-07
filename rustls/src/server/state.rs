use core::ops::Deref;
use std::vec::Vec;

use crate::common_state::Protocol;
use crate::conn::ConnectionCore;
use crate::error::ApiMisuse;
use crate::lock::Mutex;
use crate::msgs::{ReceivedData, ServerExtensionsInput};
use crate::server::{ServerSide, hs, tls12, tls13};
use crate::state::{ReceiveTraffic, SendTraffic};
use crate::sync::Arc;
use crate::{CommonState, ConnectionOutputs, Error, KeyingMaterialExporter, ServerConfig};

/// State-based TLS Server API.
#[non_exhaustive]
pub enum ServerState {
    /// Handshake data should be transmitted to the peer.
    SendServerFlight(SendServerFlight),

    /// Early data is available to be read or rejected.
    ReceiveEarlyData(ReceiveEarlyData),

    /// We are awaiting handshake data from the peer.
    AwaitClientFlight(AwaitClientFlight),

    /// The peer's identity should be verified.
    VerifyClientIdentity(VerifyClientIdentity),

    /// Our credentials should be selected and supplied for this peer.
    ProvideCredential(ProvideCredential),

    /// The handshake has completed and application data may now flow.
    Traffic(ServerTraffic),
}

impl ServerState {
    /// Create a new server connection.
    ///
    /// If `alpn_protocols` is [`None`], then the ALPN settings are obtained
    /// from [`ClientConfig::alpn_protocols`].
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        let inner =
            ConnectionCore::for_server(config, ServerExtensionsInput::default(), Protocol::Tcp)?;

        Ok(Self::AwaitClientFlight(AwaitClientFlight { inner }))
    }
}

impl Deref for ServerState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SendServerFlight(st) => &st.inner.common.outputs,
            Self::ReceiveEarlyData(st) => &st.inner.common.outputs,
            Self::AwaitClientFlight(st) => &st.inner.common.outputs,
            Self::VerifyClientIdentity(_) => todo!(),
            Self::ProvideCredential(_) => todo!(),
            Self::Traffic(traffic) => &traffic.outputs,
        }
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendServerFlight {
    inner: ConnectionCore<ServerSide>,
    next: fn(ConnectionCore<ServerSide>) -> ServerState,
}

impl SendServerFlight {
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
    pub fn into_next(self) -> ServerState {
        match self
            .inner
            .common
            .send
            .sendable_tls
            .is_empty()
        {
            true => (self.next)(self.inner),
            false => ServerState::SendServerFlight(self),
        }
    }
}

/// A handshake state where we are awaiting handshake data from the peer.
pub struct AwaitClientFlight {
    inner: ConnectionCore<ServerSide>,
}

impl AwaitClientFlight {
    /// Receive some data.
    ///
    /// Return the next state if reached, the current state if not, and an error if things are permenantly
    /// broken.  If an error occurs here is is fatal to the connection.
    pub fn input_data(mut self, input: &mut dyn ReceivedData) -> Result<ServerState, Error> {
        self.inner.process_new_packets(input)?;

        if !self
            .inner
            .common
            .send
            .sendable_tls
            .is_empty()
        {
            return Ok(ServerState::SendServerFlight(SendServerFlight {
                inner: self.inner,
                next: next_state,
            }));
        }

        Ok(next_state(self.inner))
    }
}

/// An opportunity exists to receive early data.
pub struct ReceiveEarlyData {
    inner: ConnectionCore<ServerSide>,
}

impl ReceiveEarlyData {
    /// Obtain one chunk of early data received from the peer.
    ///
    /// Like TLS generally, early data is stream-based rather than message-based.
    /// So you should avoid depending on the record separation implied in this
    /// API.
    ///
    /// To obtain all the data, call this function repeatedly until it
    /// returns `None`.
    pub fn take_data(&mut self) -> Option<Vec<u8>> {
        self.inner.side.early_data.pop()
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

    /// Move to the next state, concluding reading of Early Data.
    ///
    /// Unread early data is discarded.
    pub fn into_next(mut self) -> ServerState {
        self.inner.side.early_data.retire();
        ServerState::AwaitClientFlight(AwaitClientFlight { inner: self.inner })
    }
}

pub struct VerifyClientIdentity;

pub struct ProvideCredential;

pub struct ServerTraffic {
    /// The receive side of the connection.
    ///
    /// This starts out as `Some()`, and callers may `take()` or insert `None`
    /// to denote closure of the send side.
    pub send: Option<SendTraffic>,

    /// The receive side of the connection.
    ///
    /// This starts out as `Some()`, and callers may `take()` or insert `None`
    /// to denote closure of the receive side (whether cleanly or otherwise).
    pub receive: Option<ReceiveTraffic<ServerSide>>,

    pub outputs: ConnectionOutputs,
}

impl From<ConnectionCore<ServerSide>> for ServerTraffic {
    fn from(inner: ConnectionCore<ServerSide>) -> Self {
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
            }),
            outputs,
        }
    }
}

fn next_state(inner: ConnectionCore<ServerSide>) -> ServerState {
    if inner.side.early_data.peek().is_some() {
        return ServerState::ReceiveEarlyData(ReceiveEarlyData { inner });
    }

    match inner.state.as_ref() {
        Ok(
            hs::StateMachine::Tls12(tls12::StateMachine::ExpectTraffic(_))
            | hs::StateMachine::Tls13(tls13::StateMachine::ExpectTraffic(_)),
        ) => ServerState::Traffic(inner.into()),
        Ok(_) => ServerState::AwaitClientFlight(AwaitClientFlight { inner }),
        Err(_) => panic!("TODO: withdraw error fusing in core.state"),
    }
}
