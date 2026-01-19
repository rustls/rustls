#[cfg(feature = "std")]
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use std::io;

use pki_types::DnsName;

#[cfg(feature = "std")]
use super::config::ClientHello;
use super::config::ServerConfig;
use super::hs;
#[cfg(feature = "std")]
use super::hs::ClientHelloInput;
use crate::common_state::{CommonState, Protocol, Side};
#[cfg(feature = "std")]
use crate::common_state::{Input, State};
#[cfg(feature = "std")]
use crate::conn::ConnectionCommon;
use crate::conn::{ConnectionCore, UnbufferedConnectionCommon};
#[cfg(doc)]
use crate::crypto;
#[cfg(feature = "std")]
use crate::crypto::SignatureScheme;
use crate::crypto::cipher::Payload;
use crate::error::Error;
use crate::kernel::KernelConnection;
#[cfg(feature = "std")]
use crate::log::trace;
use crate::msgs::ServerExtensionsInput;
#[cfg(feature = "std")]
use crate::msgs::{
    ClientHelloPayload, HandshakePayload, Locator, Message, MessagePayload, ServerNamePayload,
};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

#[cfg(feature = "std")]
mod buffered {
    use alloc::boxed::Box;
    use core::fmt;
    use core::fmt::{Debug, Formatter};
    use core::ops::{Deref, DerefMut};
    use std::io;

    use pki_types::{DnsName, FipsStatus};

    use super::{
        Accepted, Accepting, Protocol, ServerConfig, ServerConnectionData, ServerExtensionsInput,
    };
    use crate::KeyingMaterialExporter;
    use crate::common_state::{CommonState, Side};
    use crate::conn::private::SideData;
    use crate::conn::{ConnectionCommon, ConnectionCore};
    use crate::error::{ApiMisuse, Error};
    use crate::msgs::Locator;
    use crate::server::hs::{ClientHelloInput, ServerContext};
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
            self.inner.core.side.sni.as_ref()
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
                .received_resumption_data
                .as_ref()
                .map(|x| &x[..])
        }

        /// Set the resumption data to embed in future resumption tickets supplied to the client.
        ///
        /// Defaults to the empty byte string. Must be less than 2^15 bytes to allow room for other
        /// data. Should be called while `is_handshaking` returns true to ensure all transmitted
        /// resumption tickets are affected.
        ///
        /// Integrity will be assured by rustls, but the data will be visible to the client. If secrecy
        /// from the client is desired, encrypt the data separately.
        pub fn set_resumption_data(&mut self, data: &[u8]) {
            assert!(data.len() < 2usize.pow(15));
            self.inner.core.side.resumption_data = data.into();
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

        /// Return the FIPS validation status of the connection's `ServerConfig`.
        ///
        /// This is different from [`crate::crypto::CryptoProvider::fips()`]:
        /// it is concerned only with cryptography, whereas this _also_ covers TLS-level
        /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
        pub fn fips(&self) -> FipsStatus {
            self.inner.core.side.fips
        }

        /// Extract secrets, so they can be used when configuring kTLS, for example.
        /// Should be used with care as it exposes secret key material.
        pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
            self.inner.dangerous_extract_secrets()
        }
    }

    impl Debug for ServerConnection {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("ServerConnection")
                .finish()
        }
    }

    impl Deref for ServerConnection {
        type Target = ConnectionCommon<ServerConnectionData>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for ServerConnection {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl From<ServerConnection> for crate::Connection {
        fn from(conn: ServerConnection) -> Self {
            Self::Server(conn)
        }
    }

    /// Handle a server-side connection before configuration is available.
    ///
    /// `Acceptor` allows the caller to choose a [`ServerConfig`] after reading
    /// the [`ClientHello`][super::ClientHello] of an incoming connection. This is useful for
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
                        ServerConnectionData::new(CommonState::new(Side::Server, Protocol::Tcp)),
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
                Err(err) => return Err(AcceptedAlert::from_error(err, connection.core.side)),
            };

            let cx = ServerContext {
                data: &mut connection.core.side,
                // `ClientHelloInput::from_message` won't read borrowed plaintext
                plaintext_locator: &Locator::new(&[]),
                received_plaintext: &mut None,
            };

            let sig_schemes = match ClientHelloInput::from_input(&input, false, &cx) {
                Ok(ClientHelloInput { sig_schemes, .. }) => sig_schemes,
                Err(err) => {
                    return Err(AcceptedAlert::from_error(err, connection.core.side));
                }
            };
            debug_assert!(cx.received_plaintext.is_none(), "read plaintext");

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
        pub(super) fn from_error(error: Error, side: ServerConnectionData) -> (Error, Self) {
            let mut common = side.into_common();
            common.maybe_send_fatal_alert(&error);
            (error, Self(common.sendable_tls))
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
            f.debug_struct("AcceptedAlert").finish()
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
        /// [`ConnectionCommon::exporter()`].
        ///
        /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
        /// [RFC8446 S7.5]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
        /// [RFC8446 appendix E.5.1]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5.1
        /// [`ConnectionCommon::exporter()`]: crate::conn::ConnectionCommon::exporter()
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
}
#[cfg(feature = "std")]
pub use buffered::{AcceptedAlert, Acceptor, ReadEarlyData, ServerConnection};

/// Unbuffered version of `ServerConnection`
///
/// See the [`crate::unbuffered`] module docs for more details
pub struct UnbufferedServerConnection {
    inner: UnbufferedConnectionCommon<ServerConnectionData>,
}

impl UnbufferedServerConnection {
    /// Make a new ServerConnection. `config` controls how we behave in the TLS protocol.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            inner: UnbufferedConnectionCommon::from(ConnectionCore::for_server(
                config,
                ServerExtensionsInput::default(),
                Protocol::Tcp,
            )?),
        })
    }

    /// Extract secrets, so they can be used when configuring kTLS, for example.
    /// Should be used with care as it exposes secret key material.
    #[deprecated = "dangerous_extract_secrets() does not support session tickets or \
                    key updates, use dangerous_into_kernel_connection() instead"]
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.inner.dangerous_extract_secrets()
    }

    /// Extract secrets and an [`KernelConnection`] object.
    ///
    /// This allows you use rustls to manage keys and then manage encryption and
    /// decryption yourself (e.g. for kTLS).
    ///
    /// Should be used with care as it exposes secret key material.
    ///
    /// See the [`crate::kernel`] documentations for details on prerequisites
    /// for calling this method.
    pub fn dangerous_into_kernel_connection(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<ServerConnectionData>), Error> {
        self.inner
            .core
            .dangerous_into_kernel_connection()
    }
}

impl Deref for UnbufferedServerConnection {
    type Target = UnbufferedConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UnbufferedServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl UnbufferedConnectionCommon<ServerConnectionData> {
    pub(crate) fn pop_early_data(&mut self) -> Option<Vec<u8>> {
        self.core.side.early_data.pop()
    }

    pub(crate) fn peek_early_data(&self) -> Option<&[u8]> {
        self.core.side.early_data.peek()
    }
}

/// Represents a `ClientHello` message received through the [`Acceptor`].
///
/// Contains the state required to resume the connection through [`Accepted::into_connection()`].
#[cfg(feature = "std")]
pub struct Accepted {
    connection: ConnectionCommon<ServerConnectionData>,
    input: Input<'static>,
    sig_schemes: Vec<SignatureScheme>,
}

#[cfg(feature = "std")]
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
                return Err(AcceptedAlert::from_error(err, self.connection.core.side));
            }
        };
        let mut cx = hs::ServerContext {
            data: &mut self.connection.core.side,
            // `ExpectClientHello::with_input` won't read borrowed plaintext
            plaintext_locator: &Locator::new(&[]),
            received_plaintext: &mut None,
        };

        let input = ClientHelloInput {
            message: &self.input.message,
            client_hello: Self::client_hello_payload(&self.input.message),
            sig_schemes: self.sig_schemes,
            proof,
        };

        let new = match state.with_input(input, &mut cx) {
            Ok(new) => new,
            Err(err) => return Err(AcceptedAlert::from_error(err, self.connection.core.side)),
        };
        debug_assert!(cx.received_plaintext.is_none(), "read plaintext");

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

#[cfg(feature = "std")]
impl Debug for Accepted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted").finish()
    }
}

#[cfg(feature = "std")]
struct Accepting;

#[cfg(feature = "std")]
impl State<ServerConnectionData> for Accepting {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle<'m>(
        self: Box<Self>,
        _cx: &mut hs::ServerContext<'_>,
        _input: Input<'m>,
    ) -> Result<Box<dyn State<ServerConnectionData>>, Error> {
        Err(Error::Unreachable("unreachable state"))
    }
}

#[derive(Default)]
pub(super) enum EarlyDataState {
    #[default]
    New,
    Accepted {
        received: ChunkVecBuffer,
        left: usize,
    },
    Rejected,
}

impl EarlyDataState {
    pub(super) fn reject(&mut self) {
        *self = Self::Rejected;
    }

    pub(super) fn accept(&mut self, max_size: usize) {
        *self = Self::Accepted {
            received: ChunkVecBuffer::new(Some(max_size)),
            left: max_size,
        };
    }

    #[cfg(feature = "std")]
    fn was_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub(super) fn was_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }

    fn peek(&self) -> Option<&[u8]> {
        match self {
            Self::Accepted { received, .. } => received.peek(),
            _ => None,
        }
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Accepted { received, .. } => received.pop(),
            _ => None,
        }
    }

    #[cfg(feature = "std")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Accepted { received, .. } => received.read(buf),
            _ => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    pub(super) fn take_received_plaintext(&mut self, bytes: Payload<'_>) -> bool {
        let available = bytes.bytes().len();
        let Self::Accepted { received, left } = self else {
            return false;
        };

        if received.apply_limit(available) != available || available > *left {
            return false;
        }

        received.append(bytes.into_vec());
        *left -= available;
        true
    }
}

impl Debug for EarlyDataState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "EarlyDataState::New"),
            Self::Accepted { received, left } => write!(
                f,
                "EarlyDataState::Accepted {{ received: {}, left: {} }}",
                received.len(),
                left
            ),
            Self::Rejected => write!(f, "EarlyDataState::Rejected"),
        }
    }
}

impl ConnectionCore<ServerConnectionData> {
    pub(crate) fn for_server(
        config: Arc<ServerConfig>,
        extra_exts: ServerExtensionsInput,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, protocol);
        common.set_max_fragment_size(config.max_fragment_size)?;
        common.fips = config.fips();
        Ok(Self::new(
            Box::new(hs::ExpectClientHello::new(config, extra_exts, protocol)),
            ServerConnectionData::new(common),
        ))
    }
}

/// State associated with a server connection.
#[derive(Debug)]
pub struct ServerConnectionData {
    common: CommonState,
    pub(crate) sni: Option<DnsName<'static>>,
    pub(crate) received_resumption_data: Option<Vec<u8>>,
    pub(crate) resumption_data: Vec<u8>,
    pub(super) early_data: EarlyDataState,
}

impl ServerConnectionData {
    pub(crate) fn new(common: CommonState) -> Self {
        Self {
            common,
            sni: None,
            received_resumption_data: None,
            resumption_data: Vec::new(),
            early_data: EarlyDataState::default(),
        }
    }
}

impl crate::conn::SideData for ServerConnectionData {}

impl crate::conn::private::SideData for ServerConnectionData {
    fn into_common(self) -> CommonState {
        self.common
    }
}

impl Deref for ServerConnectionData {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for ServerConnectionData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[cfg(feature = "std")]
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
