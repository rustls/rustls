use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};
use std::io;

use pki_types::{DnsName, FipsStatus};

use super::config::{ClientHello, ServerConfig};
use super::hs;
use crate::IoState;
use crate::common_state::{
    CommonState, ConnectionOutputs, EarlyDataEvent, Event, Output, Protocol, Side,
};
use crate::conn::{
    Connection, ConnectionBuffers, ConnectionCore, KeyingMaterialExporter, PlaintextSink, Reader,
    Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::{OutboundPlain, Payload};
use crate::error::{ApiMisuse, Error};
use crate::msgs::ServerExtensionsInput;
use crate::server::{ServerOutputs, ServerState};
use crate::state::ReceiveTrafficState;
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// This represents a single TLS server connection.
///
/// Send TLS-protected data to the peer using the `io::Write` trait implementation.
/// Read data from the peer using the `io::Read` trait implementation.
pub struct ServerConnection {
    state: Result<ServerState, Error>,
    buffers: ConnectionBuffers,
    config: Option<Arc<ServerConfig>>, // pending ServerState::ChooseConfig

    fips: FipsStatus,
    err_outputs: Option<Box<ServerOutputs>>,
    early_data_received: bool,
    received_early_data: ChunkVecBuffer,
    early_exporter: Option<KeyingMaterialExporter>,
}

impl ServerConnection {
    /// Make a new ServerConnection.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        let fips = config.fips();
        Ok(Self {
            state: Ok(ServerState::new()),
            buffers: ConnectionBuffers::new(),
            config: Some(config),
            err_outputs: None,
            early_data_received: false,
            received_early_data: ChunkVecBuffer::default(),
            early_exporter: None,
            fips,
        })
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
        match &self.state {
            Ok(st) => st.server_name(),
            Err(_) => self
                .err_outputs
                .as_ref()
                .unwrap()
                .server_name(),
        }
    }

    /// Application-controlled portion of the resumption ticket supplied by the client, if any.
    ///
    /// Recovered from the prior session's `set_resumption_data`. Integrity is guaranteed by rustls.
    ///
    /// Returns `Some` if and only if a valid resumption ticket has been received from the client.
    pub fn received_resumption_data(&self) -> Option<&[u8]> {
        match &self.state {
            Ok(st) => st.received_resumption_data(),
            Err(_) => self
                .err_outputs
                .as_ref()
                .unwrap()
                .received_resumption_data(),
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
        assert!(data.len() < 2usize.pow(15));
        match &mut self.state {
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
        if self.early_data_received {
            Some(ReadEarlyData::new(self))
        } else {
            None
        }
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.buffers.sendable_tls.len(),
            plaintext_bytes_to_read: self.buffers.received_plaintext.len(),
            peer_has_closed: self.has_received_close_notify(),
        }
    }

    fn has_received_close_notify(&self) -> bool {
        match &self.state {
            Ok(ServerState::Traffic(traffic)) => traffic.receive.is_none(),
            _ => false,
        }
    }

    fn write_or_buffer_appdata(&mut self, data: OutboundPlain<'_>) -> io::Result<usize> {
        Ok(match &mut self.state {
            Ok(ServerState::Traffic(st)) => {
                let Some(send) = &mut st.send else {
                    return Ok(0);
                };
                let len = data.len();

                let len = self
                    .buffers
                    .sendable_tls
                    .apply_limit(len);
                if len == 0 {
                    // Don't send empty fragments.
                    return Ok(0);
                }

                if let Ok(chunks) = send.write(data.split_at(len).0) {
                    for c in chunks {
                        self.buffers.sendable_tls.append(c);
                    }
                }
                while let Some(chunk) = send.take_data() {
                    self.buffers.sendable_tls.append(chunk);
                }
                len
            }
            Ok(ServerState::AwaitClientFlight(acf)) => {
                if let Some(mut half) = acf.try_send_half_rtt() {
                    let len = data.len();
                    if let Ok(chunks) = half.write(data) {
                        for c in chunks {
                            self.buffers.sendable_tls.append(c);
                        }
                    }
                    len
                } else {
                    self.buffers
                        .sendable_plaintext
                        .append_limited_copy(data)
                }
            }
            _ => self
                .buffers
                .sendable_plaintext
                .append_limited_copy(data),
        })
    }

    /// Act on a potential state transition from a handshake-related state to `new`.
    fn post_handshake_state(&mut self, mut new: ServerState) -> ServerState {
        if let ServerState::Traffic(traffic) = &mut new {
            // Release unsent buffered plaintext.
            while let Some(chunk) = self.buffers.sendable_plaintext.pop() {
                let Some(send) = traffic.send.as_mut() else {
                    continue;
                };
                let Ok(chunks) = send.write(chunk.as_slice().into()) else {
                    continue;
                };
                for c in chunks {
                    self.buffers.sendable_tls.append(c);
                }
            }
        }

        new
    }
}

impl Connection for ServerConnection {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        if self
            .buffers
            .received_plaintext
            .is_full()
        {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if self.has_received_close_notify() {
            return Ok(0);
        }

        let res = self.buffers.deframer_buffer.read(
            rd,
            self.state
                .as_ref()
                .map(|st| st.joining_handshake_fragments())
                .unwrap_or_default(),
        );
        if let Ok(0) = res {
            self.buffers.has_seen_eof = true;
        }

        res
    }

    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.buffers.sendable_tls.write_to(wr)
    }

    fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        self.buffers
            .received_plaintext
            .is_empty()
            && !self
                .current_io_state()
                .peer_has_closed()
            && (!self.is_handshaking() || self.buffers.sendable_tls.is_empty())
    }

    fn wants_write(&self) -> bool {
        !self.buffers.sendable_tls.is_empty()
    }

    fn reader(&mut self) -> Reader<'_> {
        let has_received_close_notify = self.has_received_close_notify();
        Reader {
            received_plaintext: &mut self.buffers.received_plaintext,
            // Are we done? i.e., have we processed all received messages, and received a
            // close_notify to indicate that no new messages will arrive?
            has_received_close_notify,
            has_seen_eof: self.buffers.has_seen_eof,
        }
    }

    fn writer(&mut self) -> Writer<'_> {
        Writer::new(self)
    }

    fn process_new_packets(&mut self) -> Result<IoState, Error> {
        loop {
            let state = match mem::replace(
                &mut self.state,
                Err(ApiMisuse::PreviousConnectionError.into()),
            ) {
                Ok(state) => state,
                Err(e) => {
                    self.state = Err(e.clone());
                    return Err(e);
                }
            };

            match state {
                ServerState::SendServerFlight(mut scf) => {
                    while let Some(chunk) = scf.take_data() {
                        self.buffers.sendable_tls.append(chunk);
                    }
                    self.state = Ok(self.post_handshake_state(scf.into_next()));
                }
                ServerState::ChooseConfig(cc) if self.config.is_some() => {
                    match cc.with_config(self.config.take().unwrap()) {
                        Ok(state) => self.state = Ok(self.post_handshake_state(state)),
                        Err((mut err, outputs)) => {
                            while let Some(chunk) = err.take_tls_data() {
                                self.buffers.sendable_tls.append(chunk);
                            }

                            self.err_outputs = Some(outputs);
                            self.state = Err(err.error.clone());
                            return Err(err.error);
                        }
                    }
                }
                ServerState::ChooseConfig(ch) => {
                    self.state = Ok(ServerState::ChooseConfig(ch));
                    break;
                }
                ServerState::ReceiveEarlyData(mut sed) => {
                    self.early_data_received = true;
                    while let Some(chunk) = sed.take_data() {
                        self.received_early_data.append(chunk);
                    }
                    self.early_exporter = sed.early_exporter().ok();
                    self.state = Ok(sed.into_next());
                }
                ServerState::AwaitClientFlight(mut asf) => {
                    // try half-rtt if required
                    if !self
                        .buffers
                        .sendable_plaintext
                        .is_empty()
                    {
                        if let Some(mut send) = asf.try_send_half_rtt() {
                            // Release unsent buffered plaintext.
                            while let Some(chunk) = self.buffers.sendable_plaintext.pop() {
                                let Ok(chunks) = send.write(chunk.as_slice().into()) else {
                                    continue;
                                };
                                for c in chunks {
                                    self.buffers.sendable_tls.append(c);
                                }
                            }
                        }
                    }

                    if self.buffers.deframer_buffer.is_empty() {
                        self.state = Ok(ServerState::AwaitClientFlight(asf));
                        break;
                    }
                    match asf.input_data(&mut self.buffers.deframer_buffer) {
                        Ok(state) => {
                            self.state = Ok(self.post_handshake_state(state));
                            if matches!(self.state, Ok(ServerState::AwaitClientFlight(_))) {
                                break;
                            }
                        }
                        Err((mut err, outputs)) => {
                            while let Some(chunk) = err.take_tls_data() {
                                self.buffers.sendable_tls.append(chunk);
                            }

                            self.err_outputs = Some(outputs);
                            self.state = Err(err.error.clone());
                            return Err(err.error);
                        }
                    };
                }
                ServerState::Traffic(mut traffic) => {
                    let mut progress = true;

                    while progress {
                        progress = false;

                        // Processed received data.
                        if !self.buffers.deframer_buffer.is_empty() {
                            let Some(recv) = traffic.receive.take() else {
                                break;
                            };
                            match recv.read(&mut self.buffers.deframer_buffer) {
                                Ok(ReceiveTrafficState::Available(received)) => {
                                    progress = true;
                                    self.buffers
                                        .received_plaintext
                                        .append(received.data.to_vec());
                                    let (used, next) = received.into_next();
                                    self.buffers
                                        .deframer_buffer
                                        .discard(used);
                                    traffic.receive = Some(next);
                                }
                                Ok(ReceiveTrafficState::WakeSender(state)) => {
                                    if let Some(send) = &mut traffic.send {
                                        while let Some(chunk) = send.take_data() {
                                            self.buffers.sendable_tls.append(chunk);
                                        }
                                    }
                                    traffic.receive = Some(state.into_next());
                                }
                                Ok(ReceiveTrafficState::Await(state)) => {
                                    traffic.receive = Some(state)
                                }
                                Ok(ReceiveTrafficState::CloseNotify) => traffic.receive = None,
                                Err(mut e) => {
                                    while let Some(chunk) = e.take_tls_data() {
                                        self.buffers.sendable_tls.append(chunk);
                                    }
                                    self.state = Err(e.error.clone());
                                    return Err(e.error);
                                }
                            }
                        }
                    }

                    self.state = Ok(ServerState::Traffic(traffic));
                    break;
                }
            }
        }

        Ok(self.current_io_state())
    }

    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match &mut self.state {
            Ok(ServerState::Traffic(traffic)) => traffic.outputs.take_exporter(),
            _ => Err(Error::HandshakeNotComplete),
        }
    }

    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        match self.state {
            Ok(ServerState::Traffic(traffic)) => Ok(traffic
                .dangerous_into_kernel_connection()?
                .0),
            _ => Err(Error::HandshakeNotComplete),
        }
    }

    fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.buffers
            .sendable_plaintext
            .set_limit(limit);
        self.buffers
            .sendable_tls
            .set_limit(limit);
    }

    fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>) {
        self.buffers
            .received_plaintext
            .set_limit(limit);
    }

    fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        match &mut self.state {
            Ok(ServerState::Traffic(st)) => match &mut st.send {
                Some(send) => send.refresh_traffic_keys(),
                None => Err(ApiMisuse::ReceiveSideAlreadyClosed.into()),
            },
            _ => Err(Error::HandshakeNotComplete),
        }
    }

    fn send_close_notify(&mut self) {
        let Ok(ServerState::Traffic(traffic)) = &mut self.state else {
            return;
        };

        let Some(send) = traffic.send.take() else {
            return;
        };

        self.buffers
            .sendable_tls
            .append(send.close());
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, Ok(ServerState::Traffic(_)))
    }

    fn fips(&self) -> FipsStatus {
        self.fips
    }
}

impl PlaintextSink for ServerConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_or_buffer_appdata(buf.into())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let payload_owner: Vec<&[u8]>;
        let payload = match bufs.len() {
            0 => return Ok(0),
            1 => OutboundPlain::Single(bufs[0].deref()),
            _ => {
                payload_owner = bufs
                    .iter()
                    .map(|io_slice| io_slice.deref())
                    .collect();

                OutboundPlain::new(&payload_owner)
            }
        };
        self.write_or_buffer_appdata(payload)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        match &self.state {
            Ok(st) => st,
            Err(_) => self.err_outputs.as_ref().unwrap(),
        }
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.state {
            Ok(st) => st,
            Err(_) => self.err_outputs.as_mut().unwrap(),
        }
    }
}

impl Debug for ServerConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .finish_non_exhaustive()
    }
}

/// Handle a server-side connection before configuration is available.
///
/// `Acceptor` allows the caller to choose a [`ServerConfig`] after reading
/// the [`ClientHello`] of an incoming connection. This is useful for
/// servers that choose different certificates or cipher suites based on the
/// characteristics of the `ClientHello`. In particular it is useful for
/// servers that need to do some I/O to load a certificate and its private key
/// and don't want to use the blocking interface provided by
/// [`ServerCredentialResolver`][crate::server::ServerCredentialResolver].
///
/// Create an Acceptor with [`Acceptor::default()`].
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "aws-lc-rs")] {
/// # fn choose_server_config(
/// #     _: rustls::server::ClientHello,
/// # ) -> std::sync::Arc<rustls::ServerConfig> {
/// #     unimplemented!();
/// # }
/// # #[allow(unused_variables)]
/// # fn main() {
/// use rustls::server::{Acceptor, ServerConfig};
/// let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
/// for stream in listener.incoming() {
///     let mut stream = stream.unwrap();
///     let mut acceptor = Acceptor::default();
///     let accepted = loop {
///         acceptor.read_tls(&mut stream).unwrap();
///         if let Some(accepted) = acceptor.accept().unwrap() {
///             break accepted;
///         }
///     };
///
///     // For some user-defined choose_server_config:
///     let config = choose_server_config(accepted.client_hello());
///     let conn = accepted
///         .into_connection(config)
///         .unwrap();
///
///     // Proceed with handling the ServerConnection.
/// }
/// # }
/// # }
/// ```
pub struct Acceptor {
    inner: Option<ServerConnection>,
}

impl Default for Acceptor {
    /// Return an empty Acceptor, ready to receive bytes from a new client connection.
    fn default() -> Self {
        Self {
            inner: Some(ServerConnection {
                state: Ok(ServerState::new()),
                buffers: ConnectionBuffers::new(),
                config: None,
                err_outputs: None,
                early_data_received: false,
                received_early_data: ChunkVecBuffer::default(),
                early_exporter: None,
                fips: FipsStatus::Unvalidated,
            }),
        }
    }
}

impl Acceptor {
    /// Read TLS content from `rd`.
    ///
    /// Returns an error if this `Acceptor` has already yielded an [`Accepted`]. For more details,
    /// refer to [`Connection::read_tls()`].
    ///
    /// [`Connection::read_tls()`]: crate::Connection::read_tls
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(io::Error::other(
                "acceptor cannot read after successful acceptance",
            )),
        }
    }

    /// Check if a `ClientHello` message has been received.
    ///
    /// Returns `Ok(None)` if the complete `ClientHello` has not yet been received.
    /// Do more I/O and then call this function again.
    ///
    /// Returns `Ok(Some(accepted))` if the connection has been accepted. Call
    /// `accepted.into_connection()` to continue. Do not call this function again.
    ///
    /// Returns `Err((err, alert))` if an error occurred. If an alert is returned, the
    /// application should call `alert.write()` to send the alert to the client. It should
    /// not call `accept()` again.
    pub fn accept(&mut self) -> Result<Option<Accepted>, (Error, AcceptedAlert)> {
        let Some(mut connection) = self.inner.take() else {
            return Err((
                ApiMisuse::AcceptorPolledAfterCompletion.into(),
                AcceptedAlert::empty(),
            ));
        };

        if let Err(e) = connection.process_new_packets() {
            return Err((e, AcceptedAlert(connection.buffers.sendable_tls)));
        }

        let Ok(ServerState::ChooseConfig(_)) = connection.state else {
            self.inner = Some(connection);
            return Ok(None);
        };

        Ok(Some(Accepted { connection }))
    }
}

/// Represents a TLS alert resulting from handling the client's `ClientHello` message.
///
/// When [`Acceptor::accept()`] returns an error, it yields an `AcceptedAlert` such that the
/// application can communicate failure to the client via [`AcceptedAlert::write()`].
pub struct AcceptedAlert(ChunkVecBuffer);

impl AcceptedAlert {
    pub(super) fn empty() -> Self {
        Self(ChunkVecBuffer::new(None))
    }

    /// Send the alert to the client.
    ///
    /// To account for short writes this function should be called repeatedly until it
    /// returns `Ok(0)` or an error.
    pub fn write(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.0.write_to(wr)
    }

    /// Send the alert to the client.
    ///
    /// This function will invoke the writer until the buffer is empty.
    pub fn write_all(&mut self, wr: &mut dyn io::Write) -> Result<(), io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

impl Debug for AcceptedAlert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedAlert")
            .finish_non_exhaustive()
    }
}

/// Allows reading of early data in resumed TLS1.3 connections.
///
/// "Early data" is also known as "0-RTT data".
///
/// This type implements [`io::Read`].
pub struct ReadEarlyData<'a> {
    conn: &'a mut ServerConnection,
}

impl<'a> ReadEarlyData<'a> {
    fn new(conn: &'a mut ServerConnection) -> Self {
        ReadEarlyData { conn }
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
        match self.conn.early_exporter.take() {
            Some(exporter) => Ok(exporter),
            None => Err(ApiMisuse::ExporterAlreadyUsed.into()),
        }
    }
}

impl io::Read for ReadEarlyData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.conn.received_early_data.read(buf)
    }
}

/// Represents a `ClientHello` message received through the [`Acceptor`].
///
/// Contains the state required to resume the connection through [`Accepted::into_connection()`].
pub struct Accepted {
    // invariant: `connection.core.state` is `Ok(hs::StateMachine::ChooseConfig)`
    connection: ServerConnection,
}

impl Accepted {
    /// Get the [`ClientHello`] for this connection.
    pub fn client_hello(&self) -> ClientHello<'_> {
        let Ok(ServerState::ChooseConfig(choose_config)) = &self.connection.state else {
            unreachable!(); // invariant
        };
        choose_config.client_hello()
    }

    /// Convert the [`Accepted`] into a [`ServerConnection`].
    ///
    /// Takes the state returned from [`Acceptor::accept()`] as well as the [`ServerConfig`] that
    /// should be used for the session. Returns an error if configuration-dependent validation of
    /// the received `ClientHello` message fails.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<ServerConnection, (Error, AcceptedAlert)> {
        self.connection.fips = config.fips();
        self.connection.config = Some(config);
        match self.connection.process_new_packets() {
            Ok(_) => Ok(self.connection),
            Err(err) => Err((err, AcceptedAlert(self.connection.buffers.sendable_tls))),
        }
    }
}

impl Debug for Accepted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub(super) enum EarlyDataState {
    #[default]
    New,
    Accepted {
        received: ChunkVecBuffer,
    },
    Retired,
}

impl EarlyDataState {
    fn accept(&mut self) {
        *self = Self::Accepted {
            received: ChunkVecBuffer::new(None),
        };
    }

    pub(super) fn peek(&self) -> Option<&[u8]> {
        match self {
            Self::Accepted { received, .. } => received.peek(),
            _ => None,
        }
    }

    pub(super) fn pop(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Accepted { received, .. } => received.pop(),
            _ => None,
        }
    }

    pub(super) fn retire(&mut self) {
        *self = Self::Retired;
    }

    fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
        let Self::Accepted { received } = self else {
            return;
        };

        received.append(bytes.into_vec());
    }
}

impl Debug for EarlyDataState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "EarlyDataState::New"),
            Self::Accepted { received } => write!(
                f,
                "EarlyDataState::Accepted {{ received: {} }}",
                received.len(),
            ),
            Self::Retired => write!(f, "EarlyDataState::Retired"),
        }
    }
}

impl ConnectionCore<ServerSide> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, protocol);
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        Ok(Self::new(
            Box::new(hs::ExpectClientHello::new(
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

    pub(crate) fn for_server_acceptor(protocol: Protocol) -> Self {
        Self::new(
            hs::ReadClientHello::new(protocol).into(),
            ServerConnectionData::default(),
            CommonState::new(Side::Server, protocol),
        )
    }
}

/// State associated with a server connection.
#[derive(Debug, Default)]
pub(crate) struct ServerConnectionData {
    sni: Option<DnsName<'static>>,
    received_resumption_data: Option<Vec<u8>>,
    pub(super) early_data: EarlyDataState,
}

impl ServerConnectionData {
    pub(crate) fn received_resumption_data(&self) -> Option<&[u8]> {
        self.received_resumption_data.as_deref()
    }

    pub(crate) fn server_name(&self) -> Option<&DnsName<'static>> {
        self.sni.as_ref()
    }

    pub(crate) fn into_parts(self) -> (Option<DnsName<'static>>, Option<Vec<u8>>) {
        (self.sni, self.received_resumption_data)
    }
}

impl Output for ServerConnectionData {
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

impl crate::conn::SideData for ServerSide {}

impl crate::conn::private::SideData for ServerSide {
    type Data = ServerConnectionData;
    type StateMachine = hs::StateMachine;
}
