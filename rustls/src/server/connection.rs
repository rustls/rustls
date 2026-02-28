use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::ops::{Deref, DerefMut};
use std::io;

use pki_types::DnsName;

use super::config::{ClientHello, ServerConfig};
use super::hs;
use super::hs::ClientHelloInput;
use crate::common_state::{
    CommonState, ConnectionOutputs, EarlyDataEvent, Event, Input, Output, Protocol, ReceivePath,
    SendPath, Side, State, maybe_send_fatal_alert,
};
use crate::conn::{
    Connection, ConnectionCommon, ConnectionCore, KeyingMaterialExporter, Reader, SideCommonOutput,
    Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::SignatureScheme;
use crate::crypto::cipher::Payload;
use crate::error::{ApiMisuse, Error};
use crate::log::trace;
use crate::msgs::{
    ClientHelloPayload, HandshakePayload, Message, MessagePayload, ServerExtensionsInput,
    ServerNamePayload,
};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// This represents a single TLS server connection.
///
/// Send TLS-protected data to the peer using the `io::Write` trait implementation.
/// Read data from the peer using the `io::Read` trait implementation.
pub struct ServerConnection {
    pub(super) inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new ServerConnection.  `config` controls how
    /// we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: ConnectionCommon::from(ConnectionCore::for_server(
                config,
                ServerExtensionsInput::default(),
                Protocol::Tcp,
            )?),
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

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    /// Should be used with care as it exposes secret key material.
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }
}

impl Connection for ServerConnection {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        self.inner.read_tls(rd)
    }

    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.inner.write_tls(wr)
    }

    fn wants_read(&self) -> bool {
        self.inner.wants_read()
    }

    fn wants_write(&self) -> bool {
        self.inner.wants_write()
    }

    fn reader(&mut self) -> Reader<'_> {
        self.inner.reader()
    }

    fn writer(&mut self) -> Writer<'_> {
        self.inner.writer()
    }

    fn process_new_packets(&mut self) -> Result<crate::IoState, Error> {
        self.inner.process_new_packets()
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

    fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>) {
        self.inner
            .set_plaintext_buffer_limit(limit)
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
}

impl Deref for ServerConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
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
    inner: Option<ConnectionCommon<ServerConnectionData>>,
}

impl Default for Acceptor {
    /// Return an empty Acceptor, ready to receive bytes from a new client connection.
    fn default() -> Self {
        Self {
            inner: Some(
                ConnectionCore::new(
                    Box::new(Accepting),
                    ServerConnectionData::default(),
                    CommonState::new(Side::Server),
                )
                .into(),
            ),
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

        let input = match connection.first_handshake_message() {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                self.inner = Some(connection);
                return Ok(None);
            }
            Err(err) => return Err(AcceptedAlert::from_error(err, connection.core.common.send)),
        };

        let sig_schemes = match ClientHelloInput::from_input(&input) {
            Ok(ClientHelloInput { sig_schemes, .. }) => sig_schemes,
            Err(err) => {
                return Err(AcceptedAlert::from_error(err, connection.core.common.send));
            }
        };

        Ok(Some(Accepted {
            connection,
            input,
            sig_schemes,
        }))
    }
}

/// Represents a TLS alert resulting from handling the client's `ClientHello` message.
///
/// When [`Acceptor::accept()`] returns an error, it yields an `AcceptedAlert` such that the
/// application can communicate failure to the client via [`AcceptedAlert::write()`].
pub struct AcceptedAlert(ChunkVecBuffer);

impl AcceptedAlert {
    pub(super) fn from_error(error: Error, mut send: SendPath) -> (Error, Self) {
        maybe_send_fatal_alert(&mut send, &error);
        (error, Self(send.sendable_tls))
    }

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
    common: &'a mut ConnectionCommon<ServerConnectionData>,
}

impl<'a> ReadEarlyData<'a> {
    fn new(common: &'a mut ConnectionCommon<ServerConnectionData>) -> Self {
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

/// Represents a `ClientHello` message received through the [`Acceptor`].
///
/// Contains the state required to resume the connection through [`Accepted::into_connection()`].
pub struct Accepted {
    connection: ConnectionCommon<ServerConnectionData>,
    input: Input<'static>,
    sig_schemes: Vec<SignatureScheme>,
}

impl Accepted {
    /// Get the [`ClientHello`] for this connection.
    pub fn client_hello(&self) -> ClientHello<'_> {
        let payload = Self::client_hello_payload(&self.input.message);
        let server_name = payload
            .server_name
            .as_ref()
            .and_then(ServerNamePayload::to_dns_name_normalized)
            .map(Cow::Owned);
        let ch = ClientHello {
            server_name,
            signature_schemes: &self.sig_schemes,
            alpn: payload.protocols.as_ref(),
            server_cert_types: payload
                .server_certificate_types
                .as_deref(),
            client_cert_types: payload
                .client_certificate_types
                .as_deref(),
            cipher_suites: &payload.cipher_suites,
            certificate_authorities: payload
                .certificate_authority_names
                .as_deref(),
            named_groups: payload.named_groups.as_deref(),
        };

        trace!("Accepted::client_hello(): {ch:#?}");
        ch
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
        if let Err(err) = self
            .connection
            .send
            .set_max_fragment_size(config.max_fragment_size)
        {
            // We have a connection here, but it won't contain an alert since the error
            // is with the fragment size configured in the `ServerConfig`.
            return Err((err, AcceptedAlert::empty()));
        }

        let state =
            hs::ExpectClientHello::new(config, ServerExtensionsInput::default(), Protocol::Tcp);
        let proof = match self.input.check_aligned_handshake() {
            Ok(proof) => proof,
            Err(err) => {
                return Err(AcceptedAlert::from_error(
                    err,
                    self.connection.core.common.send,
                ));
            }
        };

        let input = ClientHelloInput {
            message: &self.input.message,
            client_hello: Self::client_hello_payload(&self.input.message),
            sig_schemes: self.sig_schemes,
            proof,
        };

        let mut output = SideCommonOutput {
            side: &mut self.connection.core.side,
            quic: None,
            common: &mut self.connection.core.common,
        };

        let new = match state.with_input(input, &mut output) {
            Ok(new) => new,
            Err(err) => {
                return Err(AcceptedAlert::from_error(
                    err,
                    self.connection.core.common.send,
                ));
            }
        };

        self.connection.replace_state(new);
        Ok(ServerConnection {
            inner: self.connection,
        })
    }

    fn client_hello_payload<'a>(message: &'a Message<'_>) -> &'a ClientHelloPayload {
        match &message.payload {
            MessagePayload::Handshake { parsed, .. } => match &parsed.0 {
                HandshakePayload::ClientHello(ch) => ch,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

impl Debug for Accepted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .finish_non_exhaustive()
    }
}

struct Accepting;

impl State for Accepting {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle<'m>(
        self: Box<Self>,
        _input: Input<'m>,
        _output: &mut dyn Output,
    ) -> Result<Box<dyn State>, Error> {
        Err(Error::Unreachable("unreachable state"))
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

impl Debug for EarlyDataState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "EarlyDataState::New"),
            Self::Accepted { received } => write!(
                f,
                "EarlyDataState::Accepted {{ received: {} }}",
                received.len(),
            ),
        }
    }
}

impl ConnectionCore<ServerConnectionData> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server);
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        common.fips = config.fips();
        Ok(Self::new(
            Box::new(hs::ExpectClientHello::new(config, extra_exts, protocol)),
            ServerConnectionData::default(),
            common,
        ))
    }
}

/// State associated with a server connection.
#[derive(Debug, Default)]
pub struct ServerConnectionData {
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

    fn send_msg(&mut self, _: Message<'_>, _: bool) {
        unreachable!();
    }

    fn start_traffic(&mut self) {
        unreachable!();
    }

    fn receive(&mut self) -> &mut ReceivePath {
        unreachable!()
    }

    fn send(&mut self) -> &mut SendPath {
        unreachable!()
    }
}

impl crate::conn::SideData for ServerConnectionData {}

impl crate::conn::private::SideData for ServerConnectionData {}

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
