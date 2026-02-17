use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut};
use std::borrow::Cow;

use pki_types::DnsName;

use crate::common_state::Protocol;
use crate::conn::unbuffered::EncryptError;
use crate::conn::{ConnectionCore, ProcessFinishCondition};
use crate::crypto::cipher::OutboundPlain;
use crate::error::{ApiMisuse, ErrorWithAlert};
use crate::kernel::KernelConnection;
use crate::lock::Mutex;
use crate::log::trace;
use crate::msgs::{ServerExtensionsInput, ServerNamePayload, TlsInputBuffer};
use crate::server::{ClientHello, ServerSide, hs, tls12, tls13};
use crate::state::{ReceiveTraffic, SendTraffic};
use crate::sync::Arc;
use crate::{
    CommonState, ConnectionOutputs, Error, ExtractedSecrets, KeyingMaterialExporter, ServerConfig,
};

/// State-based TLS server API.
#[non_exhaustive]
pub enum ServerState {
    /// We are awaiting handshake data from the peer.
    AwaitClientFlight(AwaitClientFlight),

    /// We have received a `ClientHello` and it is time to choose a `ServerConfig` for this connection.
    ChooseConfig(ChooseConfig),

    /// Handshake data should be transmitted to the peer.
    SendServerFlight(SendServerFlight),

    /// Early data is available to be read or rejected.
    ReceiveEarlyData(ReceiveEarlyData),

    /// The handshake has completed and application data may now flow.
    Traffic(Box<ServerTraffic>),
}

impl ServerState {
    /// Create a new server connection.
    ///
    /// This starts out by reading a `ClientHello` using the [`ServerState::AwaitClientFlight`] state.
    pub fn new() -> Self {
        let inner = Box::new(ConnectionCore::for_server_acceptor(Protocol::Tcp));
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
            Self::Traffic(st) => st.outputs.server_name.as_ref(),
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
            Self::Traffic(st) => st
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
            Self::Traffic(_) => return Err(ApiMisuse::ResumptionDataProvidedTooLate.into()),
        };

        match state {
            Ok(st) => st.set_resumption_data(data),
            Err(err) => Err(err.clone()),
        }
    }

    /// Returns true if the connection is currently reassembling a handshake message.
    ///
    /// This can be used to alter the caller's buffering strategy, as a larger
    /// buffer is required to reassemble a handshake message.
    pub fn joining_handshake_fragments(&self) -> bool {
        match self {
            Self::AwaitClientFlight(st) => st
                .inner
                .common
                .recv
                .hs_deframer
                .is_active(),
            Self::ChooseConfig(_) => false,
            Self::SendServerFlight(_) => false,
            Self::ReceiveEarlyData(st) => st
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

impl Deref for ServerState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::AwaitClientFlight(st) => &st.inner.common.outputs,
            Self::ChooseConfig(st) => &st.inner.common.outputs,
            Self::SendServerFlight(st) => &st.inner.common.outputs,
            Self::ReceiveEarlyData(st) => &st.inner.common.outputs,
            Self::Traffic(traffic) => &traffic.outputs.outputs,
        }
    }
}

impl DerefMut for ServerState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::AwaitClientFlight(st) => &mut st.inner.common.outputs,
            Self::ChooseConfig(st) => &mut st.inner.common.outputs,
            Self::SendServerFlight(st) => &mut st.inner.common.outputs,
            Self::ReceiveEarlyData(st) => &mut st.inner.common.outputs,
            Self::Traffic(traffic) => &mut traffic.outputs.outputs,
        }
    }
}

impl fmt::Debug for ServerState {
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
            Self::Traffic(_) => f
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
    /// Return the next state if reached, the current state if not, and an error if things are permenantly
    /// broken.  If an error occurs here is is fatal to the connection.
    pub fn input_data(
        mut self,
        input: &mut dyn TlsInputBuffer,
    ) -> Result<ServerState, (ErrorWithAlert, Box<ServerOutputs>)> {
        if let Err(err) = self
            .inner
            .process_new_packets(input, ProcessFinishCondition::Handshake)
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
                inner: &mut self.inner,
            }),
            false => None,
        }
    }
}

/// We have received a `ClientHello` and it is time to choose a `ServerConfig` for this connection.
pub struct ChooseConfig {
    // invariant: `inner.state` is `Ok(hs::StateMachine::ChooseConfig)`
    inner: Box<ConnectionCore<ServerSide>>,
}

impl ChooseConfig {
    /// Expose the received `ClientHello`
    ///
    /// You can use this function to view a parsed and user-friendly subset of the
    /// information in the ClientHello, allowing you to make a decision on which
    /// `ServerConfig` to continue the connection with via [`ChooseConfig::with_config()`].
    pub fn client_hello(&self) -> ClientHello<'_> {
        let Ok(hs::StateMachine::ChooseConfig(choose_config)) = &self.inner.state else {
            unreachable!(); // invariant
        };

        let client_hello = choose_config.client_hello();
        let server_name = client_hello
            .server_name
            .as_ref()
            .and_then(ServerNamePayload::to_dns_name_normalized)
            .map(Cow::Owned);
        let ch = ClientHello {
            server_name,
            signature_schemes: client_hello
                .signature_schemes
                .as_deref()
                .unwrap_or_default(),
            alpn: client_hello.protocols.as_ref(),
            server_cert_types: client_hello
                .server_certificate_types
                .as_deref(),
            client_cert_types: client_hello
                .client_certificate_types
                .as_deref(),
            cipher_suites: &client_hello.cipher_suites,
            certificate_authorities: client_hello
                .certificate_authority_names
                .as_deref(),
            named_groups: client_hello.named_groups.as_deref(),
        };

        trace!("ChooseConfig::client_hello(): {ch:#?}");
        ch
    }

    /// Expose the raw received `ClientHello` bytes.
    ///
    /// This is the reassembled and complete `ClientHello` handshake message as specified
    /// in (eg) RFC8446.  In other words, the bytes start with `legacy_version`.  There is
    /// no header or length prefix.
    ///
    /// Rustls has parsed and checked the structure of this encoding, but full processing
    /// of the message only completes later so callers of this function should be defensive.
    pub fn client_hello_bytes(&self) -> &[u8] {
        let Ok(hs::StateMachine::ChooseConfig(choose_config)) = &self.inner.state else {
            unreachable!(); // invariant
        };
        choose_config.client_hello_bytes()
    }

    /// Continue the connection with a selected [`ServerConfig`].
    ///
    /// This continues and concludes handling of the `ClientHello`.  If this fails, it is
    /// fatal and the error has the TLS alert (if any) attached.  This should be communicated
    /// to the peer.
    pub fn with_config(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerState, (ErrorWithAlert, Box<ServerOutputs>)> {
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

        let state = core::mem::replace(&mut self.inner.state, Err(Error::HandshakeNotComplete));

        let Ok(hs::StateMachine::ChooseConfig(choose_config)) = state else {
            unreachable!(); // invariant
        };

        let state = match choose_config.use_config(
            config,
            ServerExtensionsInput::default(),
            &mut self.inner.output(),
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

        Ok(ServerState::SendServerFlight(SendServerFlight {
            inner: self.inner,
            next: next_state,
        }))
    }
}

/// A handshake state where we are required to send data to the peer.
pub struct SendServerFlight {
    inner: Box<ConnectionCore<ServerSide>>,
    next: fn(Box<ConnectionCore<ServerSide>>) -> ServerState,
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

    /// Move to the next state, concluding reading of Early Data.
    ///
    /// Unread early data is discarded.
    pub fn into_next(mut self) -> ServerState {
        self.inner.side.early_data.retire();
        ServerState::AwaitClientFlight(AwaitClientFlight { inner: self.inner })
    }
}

/// An opportunity to send half-RTT data.
pub struct SendHalfRttTraffic<'a> {
    inner: &'a mut ConnectionCore<ServerSide>,
}

impl SendHalfRttTraffic<'_> {
    /// Write half-RTT application data to the peer, after the server's handshake has completed.
    ///
    /// The TLS data to send to the peer is returned.  This data should then
    /// be communicated to the peer, in order.
    pub fn write(&mut self, application_data: OutboundPlain<'_>) -> Result<Vec<Vec<u8>>, Error> {
        self.inner
            .common
            .send
            .write_plaintext(application_data)
    }
}

/// The handshake is complete and data may flow in both directions.
#[expect(clippy::exhaustive_structs)]
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

    /// Facts about the connection established during the handshake.
    pub outputs: ServerOutputs,
}

impl ServerTraffic {
    /// Converts the connection into a [`KernelConnection`] for use with KTLS.
    pub fn dangerous_into_kernel_connection(
        mut self,
    ) -> Result<(ExtractedSecrets, KernelConnection<ServerSide>), Error> {
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
            self.outputs.outputs,
            receive.state,
        );
        c
    }
}

impl From<Box<ConnectionCore<ServerSide>>> for Box<ServerTraffic> {
    fn from(inner: Box<ConnectionCore<ServerSide>>) -> Self {
        let CommonState {
            recv,
            send,
            outputs,
            ..
        } = inner.common;
        let send_mutex = Arc::new(Mutex::new(send));
        let (server_name, received_resumption_data) = inner.side.into_parts();

        Self::new(ServerTraffic {
            send: Some(SendTraffic(send_mutex.clone())),
            receive: Some(ReceiveTraffic {
                state: inner.state.unwrap(), // TODO
                recv,
                send: send_mutex,
                pending_wake_sender: false,
            }),
            outputs: ServerOutputs {
                outputs,
                server_name,
                received_resumption_data,
            },
        })
    }
}

/// Facts about the connection established during the handshake.
pub struct ServerOutputs {
    /// Facts about the connection established during the handshake.
    pub outputs: ConnectionOutputs,

    server_name: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
}

impl ServerOutputs {
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        self.server_name.as_ref()
    }

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

impl fmt::Debug for ServerOutputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerOutputs")
            .finish_non_exhaustive()
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

fn next_state(inner: Box<ConnectionCore<ServerSide>>) -> ServerState {
    if inner.side.early_data.peek().is_some() {
        return ServerState::ReceiveEarlyData(ReceiveEarlyData { inner });
    }

    match &inner.state {
        Ok(_)
            if !inner
                .common
                .send
                .sendable_tls
                .is_empty() =>
        {
            ServerState::SendServerFlight(SendServerFlight {
                inner,
                next: next_state,
            })
        }

        Ok(
            hs::StateMachine::Tls12(tls12::StateMachine::ExpectTraffic(_))
            | hs::StateMachine::Tls13(tls13::StateMachine::ExpectTraffic(_)),
        ) => ServerState::Traffic(inner.into()),

        Ok(hs::StateMachine::ChooseConfig(_)) => ServerState::ChooseConfig(ChooseConfig { inner }),

        Ok(_) => ServerState::AwaitClientFlight(AwaitClientFlight { inner }),

        Err(_) => panic!("TODO: withdraw error fusing in core.state"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_enum_sz() {
        std::println!("yo {:?}", size_of::<AwaitClientFlight>());
    }
}
