use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};
use std::io;

use pki_types::ServerName;

use super::config::ClientConfig;
use super::hs::ClientHelloInput;
use crate::client::EchStatus;
use crate::common_state::{
    CommonState, ConnectionOutputs, EarlyDataEvent, Event, Output, Protocol, Side,
};
use crate::conn::unbuffered::EncryptError;
use crate::conn::{
    Connection, ConnectionCommon, ConnectionCore, IoState, KeyingMaterialExporter, Reader,
    SideCommonOutput, Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::enums::ApplicationProtocol;
use crate::error::Error;
use crate::log::trace;
use crate::msgs::ClientExtensionsInput;
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;

/// This represents a single TLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientSide>,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .finish_non_exhaustive()
    }
}

impl ClientConnection {
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

    fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
        self.inner
            .core
            .side
            .early_data
            .check_write(data.len())
            .map(|sz| {
                self.inner
                    .send
                    .send_early_plaintext(&data[..sz])
            })
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.inner
            .core
            .common
            .recv
            .tls13_tickets_received
    }
}

impl Connection for ClientConnection {
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

    fn process_new_packets(&mut self) -> Result<IoState, Error> {
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

impl Deref for ClientConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Builder for [`ClientConnection`] values.
///
/// Create one with [`ClientConfig::connect()`].
pub struct ClientConnectionBuilder {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) name: ServerName<'static>,
    pub(crate) alpn_protocols: Option<Vec<ApplicationProtocol<'static>>>,
}

impl ClientConnectionBuilder {
    /// Specify the ALPN protocols to use for this connection.
    pub fn with_alpn(mut self, alpn_protocols: Vec<ApplicationProtocol<'static>>) -> Self {
        self.alpn_protocols = Some(alpn_protocols);
        self
    }

    /// Finalize the builder and create the `ClientConnection`.
    pub fn build(self) -> Result<ClientConnection, Error> {
        let Self {
            config,
            name,
            alpn_protocols,
        } = self;

        let alpn_protocols = alpn_protocols.unwrap_or_else(|| config.alpn_protocols.clone());
        Ok(ClientConnection {
            inner: ConnectionCommon::from(ConnectionCore::for_client(
                config,
                name,
                ClientExtensionsInput::from_alpn(alpn_protocols),
                Protocol::Tcp,
            )?),
        })
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
    /// [`Connection::exporter()`].
    ///
    /// [RFC5705]: https://datatracker.ietf.org/doc/html/rfc5705
    /// [RFC8446 S7.5]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.5
    /// [RFC8446 appendix E.5.1]: https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.5.1
    /// [`Connection::exporter()`]: crate::conn::Connection::exporter()
    pub fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.sess.inner.core.early_exporter()
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

impl ConnectionCore<ClientSide> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extra_exts: ClientExtensionsInput,
        proto: Protocol,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client, proto);
        common_state
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        common_state.fips = config.fips();
        let mut data = ClientSide::new();

        let mut output = SideCommonOutput {
            side: &mut data,
            common: &mut common_state,
        };

        let input = ClientHelloInput::new(name, &extra_exts, proto, &mut output, config)?;
        let state = input.start_handshake(extra_exts, &mut output)?;

        Ok(Self::new(state, data, common_state))
    }

    pub(crate) fn is_early_data_accepted(&self) -> bool {
        self.side.early_data.is_accepted()
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

    fn is_enabled(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Ready | EarlyDataState::Sending | EarlyDataState::Accepted
        )
    }

    fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    fn start(&mut self) {
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Sending;
    }

    fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    fn accepted(&mut self) {
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

    fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        self.check_write_opt(sz)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
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

    fn bytes_left(&self) -> usize {
        self.left
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

impl core::error::Error for EarlyDataError {}

/// State associated with a client connection.
#[derive(Debug)]
pub struct ClientSide {
    early_data: EarlyData,
    ech_status: EchStatus,
}

impl ClientSide {
    fn new() -> Self {
        Self {
            early_data: EarlyData::new(),
            ech_status: EchStatus::default(),
        }
    }
}

impl crate::conn::SideData for ClientSide {}

impl crate::conn::private::SideData for ClientSide {}

impl Output for ClientSide {
    fn emit(&mut self, ev: Event<'_>) {
        match ev {
            Event::EchStatus(ech) => self.ech_status = ech,
            Event::EarlyData(EarlyDataEvent::Accepted) => self.early_data.accepted(),
            Event::EarlyData(EarlyDataEvent::Enable(sz)) => self.early_data.enable(sz),
            Event::EarlyData(EarlyDataEvent::Finished) => self.early_data.finished(),
            Event::EarlyData(EarlyDataEvent::Start) => self.early_data.start(),
            Event::EarlyData(EarlyDataEvent::Rejected) => self.early_data.rejected(),
            _ => unreachable!(),
        }
    }
}
