use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Deref;
use core::{fmt, mem};
use std::io;

use pki_types::{DnsName, FipsStatus};

use super::config::{ClientHello, ServerConfig};
use crate::common_state::{
    CommonState, ConnectionOutputs, EarlyDataEvent, Event, Protocol, Side, maybe_send_fatal_alert,
};
use crate::conn::private::SideOutput;
use crate::conn::split::SplitConnection;
use crate::conn::{
    Connection, ConnectionCommon, ConnectionCore, KeyingMaterialExporter, MessageHandler,
    MessageIter, SideData, StateMachine, TlsInputBuffer, Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::Payload;
use crate::error::Error;
use crate::log::trace;
use crate::msgs::ServerExtensionsInput;
use crate::server::hs::{ChooseConfig, ExpectClientHello, ReadClientHello, ServerState};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// This represents a single TLS server connection.
///
/// Send TLS-protected data to the peer using the `io::Write` trait implementation.
/// Read data from the peer using the `io::Read` trait implementation.
pub struct ServerConnection {
    pub(super) inner: ConnectionCommon<ServerSide>,
}

impl ServerConnection {
    /// Make a new ServerConnection.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCommon::new(ConnectionCore::for_server(
                config,
                ServerExtensionsInput::default(),
                Protocol::Tcp,
            )?),
        })
    }

    /// Split a post-handshake connection into a [`SplitConnection`].
    ///
    /// This allows the two directions (transmit and receive) of the connection to be progressed
    /// separately (including by different threads, which would allow dedicating a CPU core for each
    /// direction rather than one per connection; this can dramatically improve performance for
    /// full-duplex protocols).
    ///
    /// It also separates out the [`ConnectionOutputs`] which gives the application direct control
    /// of how long this is kept.
    ///
    /// This fails if:
    ///
    /// - the handshake is not complete. Check with [`Connection::is_handshaking()`].
    /// - there is any buffered TLS data to send.  Obtain it first with [`Connection::write_tls()`].
    pub fn split(self) -> Result<SplitConnection<ServerSide>, Error> {
        self.inner.split()
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
        self.inner.core.side.server_name()
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        self.inner
            .core
            .side
            .received_resumption_data()
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
        assert!(data.len() < 2usize.pow(15));
        match &mut self.inner.core.state {
            Ok(st) => st.set_resumption_data(data),
            Err(e) => Err(e.clone()),
        }
    }

    /// Returns an `io::Read` implementer you can read bytes from that are
    /// received from a client as TLS1.3 0RTT/"early" data, during the handshake.
    ///
    /// This returns `None` in many circumstances, such as :
    ///
    /// - Early data is disabled if [`ServerConfig::max_early_data_size`] is zero (the default).
    /// - The session negotiated with the client is not TLS1.3.
    /// - The client just doesn't support early data.
    /// - The connection doesn't resume an existing session.
    /// - The client hasn't sent a full ClientHello yet.
    pub fn early_data(&mut self) -> Option<ReadEarlyData<'_>> {
        if self
            .inner
            .core
            .side
            .early_data
            .was_accepted()
        {
            Some(ReadEarlyData::new(&mut self.inner))
        } else {
            None
        }
    }
}

impl Connection<ServerSide> for ServerConnection {
    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.inner.write_tls(wr)
    }

    fn wants_read(&self) -> bool {
        self.inner.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.inner.wants_write()
    }

    fn writer(&mut self) -> Writer<'_> {
        self.inner.writer()
    }

    fn process_new_packets<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
    ) -> MessageHandler<'a, 'm, ServerSide> {
        self.inner.process_new_packets(input)
    }

    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.inner.exporter()
    }

    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }

    fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.inner.set_buffer_limit(limit)
    }

    fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.inner.refresh_traffic_keys()
    }

    fn send_close_notify(&mut self) {
        self.inner.send_close_notify();
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn fips(&self) -> FipsStatus {
        self.inner.fips
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .finish_non_exhaustive()
    }
}

/// An in-progress TLS server handshake.
#[non_exhaustive]
#[derive(Debug)]
pub enum ServerHandshake {
    /// More data needs to be received to make progress.
    NeedsInput(NeedsInput),

    /// A complete `ClientHello` has been received.
    ///
    /// The handshake can be progressed by choosing a [`ServerConfig`] based on
    /// [`Accepted::client_hello()`] and providing it to [`Accepted::choose_config()`].
    Accepted(Accepted),

    /// The handshake is complete.
    ///
    /// Now see [`SplitConnection`] to continue the connection.
    Complete(SplitConnection<ServerSide>),
}

impl ServerHandshake {
    /// Creates a new [`ServerHandshake`] via the payload of the [`ServerHandshake::NeedsInput`] variant.
    ///
    /// It is a fundamental fact of server TLS connections that the server reads first; this is reflected
    /// in the returned type.
    ///
    /// You may wrap this in the [`ServerHandshake::NeedsInput`] variant to generalise the type to a
    /// [`ServerHandshake`].
    ///
    /// The returned object should be fed data from a single potential client.
    pub fn start() -> NeedsInput {
        NeedsInput {
            inner: ConnectionCore::for_acceptor(Protocol::Tcp),
        }
    }
}

impl TryFrom<ConnectionCore<ServerSide>> for ServerHandshake {
    type Error = Error;

    fn try_from(mut inner: ConnectionCore<ServerSide>) -> Result<Self, Error> {
        const MISUSED: Error = Error::Unreachable("forgot to restore state");

        Ok(match mem::replace(&mut inner.state, Err(MISUSED))? {
            ServerState::ChooseConfig(choose_config) => Self::Accepted(Accepted {
                inner,
                choose_config,
            }),

            state if state.is_traffic() => {
                inner.state = Ok(state);
                Self::Complete(SplitConnection::try_from(inner)?)
            }

            state => {
                inner.state = Ok(state);
                Self::NeedsInput(NeedsInput { inner })
            }
        })
    }
}

/// More data needs to be received to make progress.
///
/// Provide this to [`Self::process()`].
pub struct NeedsInput {
    inner: ConnectionCore<ServerSide>,
}

impl NeedsInput {
    /// Progress the handshake by receiving further data.
    ///
    /// The data is obtained via `input`.  Any output produced is appended to `output` and
    /// should be sent to the peer (including if this function returns an error, because
    /// the `output` may contain an alert.)
    ///
    /// An error from this function is otherwise fatal to the connection, as it consumes
    /// the [`NeedsInput`] object.
    ///
    /// On success, this returns:
    ///
    /// - a [`ServerHandshake::NeedsInput`] if more data is required.
    /// - a [`ServerHandshake::Accepted`] if a whole `ClientHello` has been received, requiring
    ///   and a choice of [`ServerConfig`] is required to continue.
    /// - a [`ServerHandshake::Complete`] if the handshake is complete.
    pub fn process(
        mut self,
        input: &mut dyn TlsInputBuffer,
        output: &mut Vec<Vec<u8>>,
    ) -> Result<ServerHandshake, Error> {
        let mut iter = MessageIter::new(input, None, &mut self.inner);
        let r = loop {
            match iter.next() {
                Some(Ok(_)) => {}
                Some(Err(e)) => break Err(e),
                None => break Ok(()),
            };

            // end loop as soon as traffic state is entered, as the above loop drops
            // incoming appdata.
            if iter
                .state()
                .as_ref()
                .map(|st| st.is_traffic())
                .unwrap_or_default()
            {
                break Ok(());
            }
        };

        input.discard(
            self.inner
                .common
                .recv
                .deframer
                .take_discard(),
        );

        while let Some(chunk) = self
            .inner
            .common
            .send
            .sendable_tls
            .pop()
        {
            output.push(chunk);
        }
        r?;
        ServerHandshake::try_from(self.inner)
    }

    /// Temporary escape hatch during migration to new API.
    pub fn into_buffered_connection(self) -> ServerConnection {
        ServerConnection {
            inner: ConnectionCommon::new(self.inner),
        }
    }
}

impl fmt::Debug for NeedsInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NeedsInput")
            .finish_non_exhaustive()
    }
}

/// Represents a `ClientHello` message.
///
/// The handshake can be progressed by choosing a [`ServerConfig`] based on
/// [`Accepted::client_hello()`] and providing it to [`Accepted::choose_config()`].
pub struct Accepted {
    // invariant: `inner.state` is `Err(_)` and requires restoring
    inner: ConnectionCore<ServerSide>,
    choose_config: Box<ChooseConfig>,
}

impl Accepted {
    /// Get the [`ClientHello`] for this connection.
    pub fn client_hello(&self) -> ClientHello<'_> {
        let ch = self.choose_config.client_hello();
        trace!("Accepted::client_hello(): {ch:#?}");
        ch
    }

    /// Choose a [`ServerConfig`] to progress the handshake.
    ///
    /// Output to send to the peer is appended to `output`.  Typically, this is the `ServerHello`,
    /// but it may also be an `Alert` if an error is returned.
    ///
    /// Returns an error if configuration-dependent validation of the received `ClientHello` message fails.
    pub fn choose_config(
        mut self,
        config: Arc<ServerConfig>,
        output: &mut Vec<Vec<u8>>,
    ) -> Result<ServerHandshake, Error> {
        let result = self.inner.accepted(
            self.choose_config,
            ServerExtensionsInput::default(),
            None,
            config,
        );

        let send_path = &mut self.inner.common.send;

        if let Err(err) = &result {
            maybe_send_fatal_alert(send_path, err);
        }

        while let Some(chunk) = send_path.sendable_tls.pop() {
            output.push(chunk);
        }

        result?;

        Ok(ServerHandshake::NeedsInput(NeedsInput {
            inner: self.inner,
        }))
    }
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .finish_non_exhaustive()
    }
}

/// Allows reading of early data in resumed TLS1.3 connections.
///
/// "Early data" is also known as "0-RTT data".
///
/// This type implements [`io::Read`].
pub struct ReadEarlyData<'a> {
    common: &'a mut ConnectionCommon<ServerSide>,
}

impl<'a> ReadEarlyData<'a> {
    fn new(common: &'a mut ConnectionCommon<ServerSide>) -> Self {
        ReadEarlyData { common }
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
    /// [`Connection::exporter()`].
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    /// [RFC8446 S7.5]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
    /// [RFC8446 appendix E.5.1]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5.1
    /// [`Connection::exporter()`]: crate::conn::Connection::exporter()
    pub fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.common.core.early_exporter()
    }
}

impl io::Read for ReadEarlyData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common
            .core
            .side
            .early_data
            .read(buf)
    }
}

#[derive(Default)]
pub(super) enum EarlyDataState {
    #[default]
    New,
    Accepted {
        received: ChunkVecBuffer,
    },
}

impl EarlyDataState {
    fn accept(&mut self) {
        *self = Self::Accepted {
            received: ChunkVecBuffer::new(None),
        };
    }

    fn was_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    #[expect(dead_code)]
    fn peek(&self) -> Option<&[u8]> {
        match self {
            Self::Accepted { received, .. } => received.peek(),
            _ => None,
        }
    }

    #[expect(dead_code)]
    fn pop(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Accepted { received, .. } => received.pop(),
            _ => None,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Accepted { received, .. } => received.read(buf),
            _ => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
        let Self::Accepted { received } = self else {
            return;
        };

        received.append(bytes.into_vec());
    }
}

impl ConnectionCore<ServerSide> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, config.fips());
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        Ok(Self::new(
            Box::new(ExpectClientHello::new(
                config,
                extra_exts,
                Vec::new(),
                protocol,
            ))
            .into(),
            ServerConnectionData::default(),
            common,
        ))
    }

    pub(crate) fn for_acceptor(protocol: Protocol) -> Self {
        Self::new(
            ReadClientHello::new(protocol).into(),
            ServerConnectionData::default(),
            CommonState::new(Side::Server, FipsStatus::Unvalidated),
        )
    }
}

/// State associated with a server connection.
#[derive(Default)]
pub(crate) struct ServerConnectionData {
    sni: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
    early_data: EarlyDataState,
}

impl ServerConnectionData {
    pub(crate) fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }

    pub(crate) fn server_name(&self) -> Option<&DnsName<'static>> {
        self.sni.as_ref()
    }
}

impl SideOutput for ServerConnectionData {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::EarlyApplicationData(data) => self
                .early_data
                .take_received_plaintext(data),
            Event::EarlyData(EarlyDataEvent::Accepted) => self.early_data.accept(),
            Event::ReceivedServerName(sni) => self.sni = sni,
            Event::ResumptionData(data) => self.received_resumption_data = Some(data),
            _ => unreachable!(),
        }
    }
}

/// State associated with a server connection.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct ServerSide;

impl SideData for ServerSide {}

impl crate::conn::private::Side for ServerSide {
    type Data = ServerConnectionData;
    type State = ServerState;
}

#[cfg(test)]
mod tests {
    use std::format;

    use super::*;

    // these branches not reachable externally, unless something else goes wrong.
    #[test]
    fn test_read_in_new_state() {
        assert_eq!(
            format!("{:?}", EarlyDataState::default().read(&mut [0u8; 5])),
            "Err(Kind(BrokenPipe))"
        );
    }
}
