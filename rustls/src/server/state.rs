use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use pki_types::DnsName;

use crate::common_state::Protocol;
use crate::conn::{CaptureAppData, ConnectionCore, JoinOutput, SendPath};
use crate::crypto::cipher::OutboundPlain;
use crate::error::{ApiMisuse, ErrorWithAlert};
use crate::kernel::KernelConnection;
use crate::lock::Mutex;
use crate::log::trace;
use crate::msgs::{Locator, ServerExtensionsInput, TlsInputBuffer};
use crate::server::{ClientHello, ServerSide, hs, tls12, tls13};
use crate::state::{ReceiveTraffic, SendTraffic};
use crate::sync::Arc;
use crate::{
    CommonState, ConnectionOutputs, Error, ExtractedSecrets, KeyingMaterialExporter, ServerConfig,
};

/// State-based TLS server API.
#[non_exhaustive]
pub enum ServerHandshake {
    /// We are awaiting handshake data from the peer.
    AwaitClientFlight(AwaitClientFlight),

    /// We have received a `ClientHello` and it is time to choose a `ServerConfig` for this connection.
    ChooseConfig(ChooseConfig),

    /// Handshake data should be transmitted to the peer.
    SendServerFlight(SendServerFlight),

    /// Early data is available to be read or rejected.
    ReceiveEarlyData(ReceiveEarlyData),

    /// The handshake has completed and application data may now flow.
    Complete(Box<ServerTraffic>),
}

impl ServerHandshake {
    /// Create a new server connection.
    ///
    /// This starts out by reading a `ClientHello` using the [`ServerHandshake::AwaitClientFlight`] state.
    pub fn new() -> Self {
        let inner = Box::new(ConnectionCore::for_acceptor(Protocol::Tcp));
        Self::AwaitClientFlight(AwaitClientFlight { inner })
    }

    /// Retrieves the server name, if any, used to select the certificate and
    /// private key.
    ///
    /// This returns `None` until some time after the client's server name indication
    /// (SNI) extension value is processed during the handshake. It will never be
    /// `None` when the connection is ready to send or process application data,
    /// unless the client does not support SNI.
    ///
    /// This is useful for application protocols that need to enforce that the
    /// server name matches an application layer protocol hostname. For
    /// example, HTTP/1.1 servers commonly expect the `Host:` header field of
    /// every request on a connection to match the hostname in the SNI extension
    /// when the client provides the SNI extension.
    ///
    /// The server name is also used to match sessions during session resumption.
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        match self {
            Self::AwaitClientFlight(st) => st.inner.side.server_name(),
            Self::ChooseConfig(st) => st.inner.side.server_name(),
            Self::SendServerFlight(st) => st.inner.side.server_name(),
            Self::ReceiveEarlyData(st) => st.inner.side.server_name(),
            Self::Complete(st) => st.outputs.server_name.as_ref(),
        }
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        match self {
            Self::AwaitClientFlight(st) => st.inner.side.received_resumption_data(),
            Self::ChooseConfig(st) => st.inner.side.received_resumption_data(),
            Self::SendServerFlight(st) => st.inner.side.received_resumption_data(),
            Self::ReceiveEarlyData(st) => st.inner.side.received_resumption_data(),
            Self::Complete(st) => st
                .outputs
                .received_resumption_data
                .as_deref(),
        }
    }

    /// Set the resumption data to embed in future resumption tickets supplied to the client.
    ///
    /// Defaults to the empty byte string. Must be less than 2^15 bytes to allow room for other
    /// data. Should be called while `is_handshaking` returns true to ensure all transmitted
    /// resumption tickets are affected.
    ///
    /// Integrity will be assured by rustls, but the data will be visible to the client. If secrecy
    /// from the client is desired, encrypt the data separately.
    pub fn set_resumption_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let state = match self {
            Self::AwaitClientFlight(st) => st.inner.state.as_mut(),
            Self::ChooseConfig(st) => st.inner.state.as_mut(),
            Self::SendServerFlight(st) => st.inner.state.as_mut(),
            Self::ReceiveEarlyData(st) => st.inner.state.as_mut(),
            Self::Complete(_) => return Err(ApiMisuse::ResumptionDataProvidedTooLate.into()),
        };

        match state {
            Ok(st) => st.set_resumption_data(data),
            Err(err) => Err(err.clone()),
        }
    }
}

impl Deref for ServerHandshake {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::AwaitClientFlight(st) => &st.inner.common.outputs,
            Self::ChooseConfig(st) => &st.inner.common.outputs,
            Self::SendServerFlight(st) => &st.inner.common.outputs,
            Self::ReceiveEarlyData(st) => &st.inner.common.outputs,
            Self::Complete(traffic) => &traffic.outputs.outputs,
        }
    }
}

impl DerefMut for ServerHandshake {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::AwaitClientFlight(st) => &mut st.inner.common.outputs,
            Self::ChooseConfig(st) => &mut st.inner.common.outputs,
            Self::SendServerFlight(st) => &mut st.inner.common.outputs,
            Self::ReceiveEarlyData(st) => &mut st.inner.common.outputs,
            Self::Complete(traffic) => &mut traffic.outputs.outputs,
        }
    }
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitClientFlight(_) => f
                .debug_tuple("AwaitClientFlight")
                .finish_non_exhaustive(),
            Self::ChooseConfig(_) => f
                .debug_tuple("ChooseConfig")
                .finish_non_exhaustive(),
            Self::SendServerFlight(_) => f
                .debug_tuple("SendServerFlight")
                .finish_non_exhaustive(),
            Self::ReceiveEarlyData(_) => f
                .debug_tuple("ReceiveEarlyData")
                .finish_non_exhaustive(),
            Self::Complete(_) => f
                .debug_tuple("Traffic")
                .finish_non_exhaustive(),
        }
    }
}

/// A handshake state where we are awaiting handshake data from the peer.
pub struct AwaitClientFlight {
    inner: Box<ConnectionCore<ServerSide>>,
}

impl AwaitClientFlight {
    /// Receive some data.
    ///
    /// Return the next state or an error if things are permanently broken.  If an error occurs
    /// here it is fatal to the connection.  The error is returned as a [`ErrorWithAlert`], and
    /// the contained alert should be communicated to the peer if possible.  A [`ServerOutputs`]
    /// object is also returned on error, allowing presumptive (but unauthenticated) data
    /// learned about the peer to be inspected later.
    ///
    /// The number of bytes consumed from `input` is communicated to the object via `discard()`.
    pub fn input_data(
        mut self,
        input: &mut dyn TlsInputBuffer,
    ) -> Result<ServerHandshake, (ErrorWithAlert, Box<ServerOutputs>)> {
        if let Err(err) = self
            .inner
            .process_handshake(input, None)
        {
            return Err((
                ErrorWithAlert::new(err, &mut self.inner.common.send),
                Box::new(self.inner.into()),
            ));
        }

        Ok(next_state(self.inner))
    }

    /// If it is currently possible to send half-RTT data, obtain an object for that ability.
    ///
    /// This requires that [`ServerConfig::send_half_rtt_data`] is enabled and the constraints
    /// documented there are met.
    pub fn try_send_half_rtt(&mut self) -> Option<SendHalfRttTraffic<'_>> {
        match self
            .inner
            .common
            .send
            .may_send_half_rtt_data
        {
            true => Some(SendHalfRttTraffic {
                send: &mut self.inner.common.send,
            }),
            false => None,
        }
    }
}

/// We have received a `ClientHello` and it is time to choose a `ServerConfig` for this connection.
pub struct ChooseConfig {
    // invariant: `inner.state` is `Err(_)` with a meaningless error,
    // it should be reinserted before further use.
    inner: Box<ConnectionCore<ServerSide>>,
    choose_config: Box<hs::ChooseConfig>,
}

impl ChooseConfig {
    /// Expose the received `ClientHello`
    ///
    /// You can use this function to view a parsed and user-friendly subset of the
    /// information in the ClientHello, allowing you to make a decision on which
    /// `ServerConfig` to continue the connection with via [`ChooseConfig::with_config()`].
    pub fn client_hello(&self) -> ClientHello<'_> {
        let ch = ClientHello::new_from_payload(self.choose_config.client_hello());
        trace!("ChooseConfig::client_hello(): {ch:#?}");
        ch
    }

    /// Continue the connection with a selected [`ServerConfig`].
    ///
    /// This continues and concludes handling of the `ClientHello`.  If this fails, it is
    /// fatal and the error has the TLS alert (if any) attached.  This should be communicated
    /// to the peer.
    pub fn with_config(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerHandshake, (ErrorWithAlert, Box<ServerOutputs>)> {
        if let Err(err) = self
            .inner
            .common
            .send
            .set_max_fragment_size(config.max_fragment_size)
        {
            // We have a connection here, but it won't contain an alert since the error
            // is with the fragment size configured in the `ServerConfig`.
            return Err((
                ErrorWithAlert::new(err, &mut self.inner.common.send),
                Box::new(self.inner.into()),
            ));
        }

        let mut absent = None;
        let state = match self.choose_config.use_config(
            config,
            ServerExtensionsInput::default(),
            &mut CaptureAppData {
                recv: &mut self.inner.common.recv,
                other: &mut JoinOutput {
                    outputs: &mut self.inner.common.outputs,
                    quic: None,
                    send: &mut self.inner.common.send,
                    side: &mut self.inner.side,
                },
                plaintext_locator: &Locator::new(&[]),
                received_plaintext: &mut absent,
                _message_lifetime: PhantomData,
            },
        ) {
            Ok(state) => state,
            Err(err) => {
                return Err((
                    ErrorWithAlert::new(err, &mut self.inner.common.send),
                    Box::new(self.inner.into()),
                ));
            }
        };
        self.inner.state = Ok(state);

        Ok(ServerHandshake::SendServerFlight(SendServerFlight {
            inner: self.inner,
        }))
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendServerFlight {
    inner: Box<ConnectionCore<ServerSide>>,
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
    pub fn into_next(self) -> ServerHandshake {
        next_state(self.inner)
    }
}

/// An opportunity exists to receive early data.
pub struct ReceiveEarlyData {
    inner: Box<ConnectionCore<ServerSide>>,
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

    /// Returns the "early" exporter that can derive key material for use in early data
    ///
    /// See [RFC5705][] for general details on what exporters are, and [RFC8446 S7.5][] for
    /// specific details on the "early" exporter.
    ///
    /// **Beware** that the early exporter requires care, as it is subject to the same
    /// potential for replay as early data itself.  See [RFC8446 appendix E.5.1][] for
    /// more detail.
    ///
    /// This function can be called at most once per connection. This function will error
    /// if called more than once per connection.
    ///
    /// If you are looking for the normal exporter, this is available from
    /// [`Connection::exporter()`].
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    /// [RFC8446 S7.5]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
    /// [RFC8446 appendix E.5.1]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5.1
    /// [`Connection::exporter()`]: crate::Connection::exporter()
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
    pub fn into_next(mut self) -> ServerHandshake {
        self.inner.side.early_data.retire();
        ServerHandshake::AwaitClientFlight(AwaitClientFlight { inner: self.inner })
    }
}

/// An opportunity to send half-RTT data.
pub struct SendHalfRttTraffic<'a> {
    send: &'a mut SendPath,
}

impl SendHalfRttTraffic<'_> {
    /// Write half-RTT application data to the peer, after the server's handshake has completed.
    ///
    /// The TLS data to send to the peer is returned.  This data should then
    /// be communicated to the peer, in order.
    pub fn write(&mut self, application_data: OutboundPlain<'_>) -> Result<Vec<Vec<u8>>, Error> {
        self.send
            .write_plaintext(application_data)
    }
}

/// The handshake is complete and data may flow in both directions.
///
/// When you reach this state, you should destructure it into its parts
/// and then progress them separately.
///
/// For example:
///
/// - if you do not require any information from `outputs`, you can drop it
///   now to save memory.
/// - if you are only receiving data, you can drop `send` now.  That is best done
///   by calling [`SendTraffic::close()`].
///
/// Note that for good behavior, it is usually necessary to service `receive`.  This
/// covers receipt of TLS1.3 tickets and key-update requests.
#[expect(clippy::exhaustive_structs)]
pub struct ServerTraffic {
    /// The send side of the connection.
    pub send: SendTraffic,

    /// The receive side of the connection.
    pub receive: ReceiveTraffic<ServerSide>,

    /// Facts about the connection established during the handshake.
    pub outputs: ServerOutputs,
}

impl ServerTraffic {
    // precondition: `inner.state` is Ok(x) where x is a traffic state
    fn new(inner: Box<ConnectionCore<ServerSide>>) -> Box<Self> {
        let CommonState {
            recv,
            send,
            outputs,
            ..
        } = inner.common;
        let send_mutex = Arc::new(Mutex::new(send));
        let (server_name, received_resumption_data) = inner.side.into_parts();
        // SAFETY: by precondition
        let state = inner.state.unwrap();

        Box::new(Self {
            send: SendTraffic(send_mutex.clone()),
            receive: ReceiveTraffic {
                state,
                recv,
                send: send_mutex,
                pending_wake_sender: false,
            },
            outputs: ServerOutputs {
                outputs,
                server_name,
                received_resumption_data,
            },
        })
    }

    /// Converts the connection into a [`KernelConnection`] for use with KTLS.
    pub fn dangerous_into_kernel_connection(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<ServerSide>), Error> {
        let c = ConnectionCore::from_parts_into_kernel_connection(
            &mut self.send.0.lock().unwrap(),
            self.receive.recv,
            self.outputs.outputs,
            self.receive.state,
        );
        c
    }
}

/// Facts about the connection established during the handshake.
#[derive(Debug)]
pub struct ServerOutputs {
    /// Facts about the connection established during the handshake.
    pub outputs: ConnectionOutputs,

    server_name: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
}

impl ServerOutputs {
    /// Retrieves the server name, if any, used to select the certificate and
    /// private key.
    ///
    /// This returns `None` until some time after the client's server name indication
    /// (SNI) extension value is processed during the handshake. It will never be
    /// `None` when the connection is ready to send or process application data,
    /// unless the client does not support SNI.
    ///
    /// This is useful for application protocols that need to enforce that the
    /// server name matches an application layer protocol hostname. For
    /// example, HTTP/1.1 servers commonly expect the `Host:` header field of
    /// every request on a connection to match the hostname in the SNI extension
    /// when the client provides the SNI extension.
    ///
    /// The server name is also used to match sessions during session resumption.
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        self.server_name.as_ref()
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }
}

impl From<Box<ConnectionCore<ServerSide>>> for ServerOutputs {
    fn from(inner: Box<ConnectionCore<ServerSide>>) -> Self {
        let (server_name, received_resumption_data) = inner.side.into_parts();

        Self {
            outputs: inner.common.outputs,
            server_name,
            received_resumption_data,
        }
    }
}

impl Deref for ServerOutputs {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.outputs
    }
}

impl DerefMut for ServerOutputs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.outputs
    }
}

fn next_state(mut inner: Box<ConnectionCore<ServerSide>>) -> ServerHandshake {
    if inner.side.early_data.peek().is_some() {
        return ServerHandshake::ReceiveEarlyData(ReceiveEarlyData { inner });
    }

    if !inner
        .common
        .send
        .sendable_tls
        .is_empty()
    {
        return ServerHandshake::SendServerFlight(SendServerFlight { inner });
    }

    match &inner.state {
        Ok(
            hs::ServerState::Tls12(tls12::Tls12State::Traffic(_))
            | hs::ServerState::Tls13(tls13::Tls13State::Traffic(_)),
        ) => ServerHandshake::Complete(ServerTraffic::new(inner)),

        Ok(hs::ServerState::ChooseConfig(_)) => {
            let Ok(hs::ServerState::ChooseConfig(choose_config)) = core::mem::replace(
                &mut inner.state,
                Err(Error::Unreachable("restore state after ChooseConfig")),
            ) else {
                unreachable!();
            };
            ServerHandshake::ChooseConfig(ChooseConfig {
                inner,
                choose_config,
            })
        }

        Ok(_) => ServerHandshake::AwaitClientFlight(AwaitClientFlight { inner }),

        Err(_) => panic!("TODO: withdraw error fusing in core.state"),
    }
}
