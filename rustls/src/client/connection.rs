use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};

use pki_types::ServerName;

use super::config::ClientConfig;
use super::hs::{self, ClientHelloInput};
use crate::client::EchStatus;
use crate::common_state::{CommonState, Event, Output, Protocol, Side};
use crate::conn::{ConnectionCore, UnbufferedConnectionCommon};
#[cfg(doc)]
use crate::crypto;
use crate::enums::ApplicationProtocol;
use crate::error::Error;
use crate::kernel::KernelConnection;
use crate::log::trace;
use crate::msgs::{ClientExtensionsInput, Locator};
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;
use crate::unbuffered::{EncryptError, TransmitTlsData};

#[cfg(feature = "std")]
mod buffered {
    use alloc::vec::Vec;
    use core::fmt;
    use core::ops::{Deref, DerefMut};
    use std::io;

    use pki_types::{FipsStatus, ServerName};

    use super::{ClientConnectionData, ClientExtensionsInput};
    use crate::KeyingMaterialExporter;
    use crate::client::EchStatus;
    use crate::client::config::ClientConfig;
    use crate::common_state::Protocol;
    use crate::conn::{ConnectionCommon, ConnectionCore};
    use crate::enums::ApplicationProtocol;
    use crate::error::Error;
    use crate::suites::ExtractedSecrets;
    use crate::sync::Arc;

    /// This represents a single TLS client connection.
    pub struct ClientConnection {
        inner: ConnectionCommon<ClientConnectionData>,
    }

    impl fmt::Debug for ClientConnection {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientConnection")
                .finish()
        }
    }

    impl ClientConnection {
        /// Make a new ClientConnection.  `config` controls how
        /// we behave in the TLS protocol, `name` is the
        /// name of the server we want to talk to.
        pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
            Self::new_with_alpn(config.clone(), name, config.alpn_protocols.clone())
        }

        /// Make a new ClientConnection with custom ALPN protocols.
        pub fn new_with_alpn(
            config: Arc<ClientConfig>,
            name: ServerName<'static>,
            alpn_protocols: Vec<ApplicationProtocol<'static>>,
        ) -> Result<Self, Error> {
            Ok(Self {
                inner: ConnectionCommon::from(ConnectionCore::for_client(
                    config,
                    name,
                    ClientExtensionsInput::from_alpn(alpn_protocols),
                    Protocol::Tcp,
                )?),
            })
        }

        /// Returns an `io::Write` implementer you can write bytes to
        /// to send TLS1.3 early data (a.k.a. "0-RTT data") to the server.
        ///
        /// This returns None in many circumstances when the capability to
        /// send early data is not available, including but not limited to:
        ///
        /// - The server hasn't been talked to previously.
        /// - The server does not support resumption.
        /// - The server does not support early data.
        /// - The resumption data for the server has expired.
        ///
        /// The server specifies a maximum amount of early data.  You can
        /// learn this limit through the returned object, and writes through
        /// it will process only this many bytes.
        ///
        /// The server can choose not to accept any sent early data --
        /// in this case the data is lost but the connection continues.  You
        /// can tell this happened using `is_early_data_accepted`.
        pub fn early_data(&mut self) -> Option<WriteEarlyData<'_>> {
            if self
                .inner
                .core
                .side
                .early_data
                .is_enabled()
            {
                Some(WriteEarlyData::new(self))
            } else {
                None
            }
        }

        /// Returns True if the server signalled it will process early data.
        ///
        /// If you sent early data and this returns false at the end of the
        /// handshake then the server will not process the data.  This
        /// is not an error, but you may wish to resend the data.
        pub fn is_early_data_accepted(&self) -> bool {
            self.inner.core.is_early_data_accepted()
        }

        /// Extract secrets, so they can be used when configuring kTLS, for example.
        /// Should be used with care as it exposes secret key material.
        pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
            self.inner.dangerous_extract_secrets()
        }

        /// Return the connection's Encrypted Client Hello (ECH) status.
        pub fn ech_status(&self) -> EchStatus {
            self.inner.core.side.ech_status
        }

        /// Returns the number of TLS1.3 tickets that have been received.
        pub fn tls13_tickets_received(&self) -> u32 {
            self.inner.tls13_tickets_received
        }

        /// Return the FIPS validation status of the connection's `ClientConfig`.
        ///
        /// This is different from [`crate::crypto::CryptoProvider::fips()`]:
        /// it is concerned only with cryptography, whereas this _also_ covers TLS-level
        /// configuration that NIST recommends, as well as ECH HPKE suites if applicable.
        pub fn fips(&self) -> FipsStatus {
            self.inner.core.side.fips
        }

        fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
            self.inner
                .core
                .side
                .early_data
                .check_write(data.len())
                .map(|sz| {
                    self.inner
                        .send_early_plaintext(&data[..sz])
                })
        }
    }

    impl Deref for ClientConnection {
        type Target = ConnectionCommon<ClientConnectionData>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for ClientConnection {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    #[doc(hidden)]
    impl<'a> TryFrom<&'a mut crate::Connection> for &'a mut ClientConnection {
        type Error = ();

        fn try_from(value: &'a mut crate::Connection) -> Result<Self, Self::Error> {
            use crate::Connection::*;
            match value {
                Client(conn) => Ok(conn),
                Server(_) => Err(()),
            }
        }
    }

    impl From<ClientConnection> for crate::Connection {
        fn from(conn: ClientConnection) -> Self {
            Self::Client(conn)
        }
    }

    /// Allows writing of early data in resumed TLS 1.3 connections.
    ///
    /// "Early data" is also known as "0-RTT data".
    ///
    /// This type implements [`io::Write`].
    pub struct WriteEarlyData<'a> {
        sess: &'a mut ClientConnection,
    }

    impl<'a> WriteEarlyData<'a> {
        fn new(sess: &'a mut ClientConnection) -> Self {
            WriteEarlyData { sess }
        }

        /// How many bytes you may send.  Writes will become short
        /// once this reaches zero.
        pub fn bytes_left(&self) -> usize {
            self.sess
                .inner
                .core
                .side
                .early_data
                .bytes_left()
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
            self.sess.core.early_exporter()
        }
    }

    impl io::Write for WriteEarlyData<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sess.write_early_data(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl super::EarlyData {
        fn check_write(&mut self, sz: usize) -> io::Result<usize> {
            self.check_write_opt(sz)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        }

        fn bytes_left(&self) -> usize {
            self.left
        }
    }
}

#[cfg(feature = "std")]
pub use buffered::{ClientConnection, WriteEarlyData};

impl ConnectionCore<ClientConnectionData> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extra_exts: ClientExtensionsInput,
        proto: Protocol,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client, proto);
        common_state.set_max_fragment_size(config.max_fragment_size)?;
        common_state.fips = config.fips();
        let mut data = ClientConnectionData::new(common_state);

        let mut cx = hs::ClientContext {
            data: &mut data,
            // `start_handshake` won't read plaintext
            plaintext_locator: &Locator::new(&[]),
            received_plaintext: &mut None,
        };

        let input = ClientHelloInput::new(name, &extra_exts, proto, &mut cx, config)?;
        let state = input.start_handshake(extra_exts, &mut cx)?;
        debug_assert!(cx.received_plaintext.is_none(), "read plaintext");

        Ok(Self::new(state, data))
    }

    #[cfg(feature = "std")]
    pub(crate) fn is_early_data_accepted(&self) -> bool {
        self.side.early_data.is_accepted()
    }
}

/// Unbuffered version of `ClientConnection`
///
/// See the [`crate::unbuffered`] module docs for more details
pub struct UnbufferedClientConnection {
    inner: UnbufferedConnectionCommon<ClientConnectionData>,
}

impl UnbufferedClientConnection {
    /// Make a new ClientConnection. `config` controls how we behave in the TLS protocol, `name` is
    /// the name of the server we want to talk to.
    pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
        Self::new_with_extensions(
            config.clone(),
            name,
            ClientExtensionsInput::from_alpn(config.alpn_protocols.clone()),
        )
    }

    /// Make a new UnbufferedClientConnection with custom ALPN protocols.
    pub fn new_with_alpn(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        alpn_protocols: Vec<ApplicationProtocol<'static>>,
    ) -> Result<Self, Error> {
        Self::new_with_extensions(
            config,
            name,
            ClientExtensionsInput::from_alpn(alpn_protocols.clone()),
        )
    }

    fn new_with_extensions(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extensions: ClientExtensionsInput,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: UnbufferedConnectionCommon::from(ConnectionCore::for_client(
                config,
                name,
                extensions,
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

    /// Extract secrets and a [`KernelConnection`] object.
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
    ) -> Result<(ExtractedSecrets, KernelConnection<ClientConnectionData>), Error> {
        self.inner
            .core
            .dangerous_into_kernel_connection()
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner.tls13_tickets_received
    }
}

impl Deref for UnbufferedClientConnection {
    type Target = UnbufferedConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UnbufferedClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl TransmitTlsData<'_, ClientConnectionData> {
    /// returns an adapter that allows encrypting early (RTT-0) data before transmitting the
    /// already encoded TLS data
    ///
    /// IF allowed by the protocol
    pub fn may_encrypt_early_data(&mut self) -> Option<MayEncryptEarlyData<'_>> {
        if self
            .conn
            .core
            .side
            .early_data
            .is_enabled()
        {
            Some(MayEncryptEarlyData { conn: self.conn })
        } else {
            None
        }
    }
}

/// Allows encrypting early (RTT-0) data
pub struct MayEncryptEarlyData<'c> {
    conn: &'c mut UnbufferedConnectionCommon<ClientConnectionData>,
}

impl MayEncryptEarlyData<'_> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. In the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        early_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EarlyDataError> {
        let Some(allowed) = self
            .conn
            .core
            .side
            .early_data
            .check_write_opt(early_data.len())
        else {
            return Err(EarlyDataError::ExceededAllowedEarlyData);
        };

        self.conn
            .core
            .side
            .write_plaintext(early_data[..allowed].into(), outgoing_tls)
            .map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub(super) struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new() -> Self {
        Self {
            state: EarlyDataState::Disabled,
            left: 0,
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted
        )
    }

    pub(crate) fn is_sending(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Sending | EarlyDataState::Accepted
        )
    }

    #[cfg(feature = "std")]
    fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    pub(super) fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    pub(crate) fn start(&mut self) {
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Sending;
    }

    pub(super) fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    pub(super) fn accepted(&mut self) {
        trace!("EarlyData accepted");
        assert_eq!(self.state, EarlyDataState::Sending);
        self.state = EarlyDataState::Accepted;
    }

    pub(super) fn finished(&mut self) {
        trace!("EarlyData finished");
        self.state = match self.state {
            EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
            _ => panic!("bad EarlyData state"),
        }
    }

    fn check_write_opt(&mut self, sz: usize) -> Option<usize> {
        match self.state {
            EarlyDataState::Disabled => unreachable!(),
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted => {
                let take = if self.left < sz {
                    mem::replace(&mut self.left, 0)
                } else {
                    self.left -= sz;
                    sz
                };

                Some(take)
            }
            EarlyDataState::Rejected | EarlyDataState::AcceptedFinished => None,
        }
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Disabled,
    Ready,
    Sending,
    Accepted,
    AcceptedFinished,
    Rejected,
}

/// Errors that may arise when encrypting early (RTT-0) data
#[non_exhaustive]
#[derive(Debug)]
pub enum EarlyDataError {
    /// Cannot encrypt more early data due to imposed limits
    ExceededAllowedEarlyData,
    /// Encryption error
    Encrypt(EncryptError),
}

impl From<EncryptError> for EarlyDataError {
    fn from(v: EncryptError) -> Self {
        Self::Encrypt(v)
    }
}

impl fmt::Display for EarlyDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceededAllowedEarlyData => f.write_str("cannot send any more early data"),
            Self::Encrypt(e) => fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for EarlyDataError {}

/// State associated with a client connection.
#[derive(Debug)]
pub struct ClientConnectionData {
    common: CommonState,
    pub(super) early_data: EarlyData,
    pub(super) ech_status: EchStatus,
}

impl ClientConnectionData {
    fn new(common: CommonState) -> Self {
        Self {
            common,
            early_data: EarlyData::new(),
            ech_status: EchStatus::NotOffered,
        }
    }
}

impl crate::conn::SideData for ClientConnectionData {}

impl crate::conn::private::SideData for ClientConnectionData {
    fn into_common(self) -> CommonState {
        self.common
    }
}

impl Output for ClientConnectionData {
    fn emit(&mut self, _ev: Event<'_>) {}
}

impl Deref for ClientConnectionData {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for ClientConnectionData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}
