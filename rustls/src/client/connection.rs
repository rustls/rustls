use alloc::vec::Vec;
use core::ops::Deref;
use core::{fmt, mem};
use std::io;

use pki_types::{FipsStatus, ServerName};

use super::config::ClientConfig;
use super::hs::ClientHelloInput;
use crate::client::EchStatus;
use crate::common_state::{CommonState, ConnectionOutputs, EarlyDataEvent, Event, Protocol, Side};
use crate::conn::private::SideOutput;
use crate::conn::{
    Buffers, Connection, ConnectionCore, IoState, KeyingMaterialExporter, PlaintextSink, Reader,
    SideCommonOutput, Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::OutboundPlain;
use crate::enums::ApplicationProtocol;
use crate::error::Error;
use crate::log::trace;
use crate::msgs::{ClientExtensionsInput, Delocator, TlsInputBuffer};
use crate::quic::QuicOutput;
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;

/// This represents a single TLS client connection.
pub struct ClientConnection {
    core: ConnectionCore<ClientSide>,
    fips: FipsStatus,
    buffers: Buffers,
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
        if self.core.side.early_data.is_enabled() {
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
        self.core.side.early_data.is_accepted()
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        self.core.side.ech_status
    }

    fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
        self.core
            .side
            .early_data
            .check_write(data.len())
            .map(|sz| {
                self.core
                    .common
                    .send
                    .send_early_plaintext(&data[..sz])
            })
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.core
            .common
            .recv
            .tls13_tickets_received
    }

    fn current_io_state(&self) -> IoState {
        let common_state = &self.core.common;
        IoState {
            tls_bytes_to_write: common_state.send.sendable_tls.len(),
            plaintext_bytes_to_read: self.buffers.received_plaintext.len(),
            peer_has_closed: common_state
                .recv
                .has_received_close_notify,
        }
    }
}

impl Connection for ClientConnection {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> Result<usize, io::Error> {
        if self
            .buffers
            .received_plaintext
            .is_full()
        {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if self
            .core
            .common
            .recv
            .has_received_close_notify
        {
            return Ok(0);
        }

        let res = self.buffers.deframer_buffer.read(rd);
        if let Ok(0) = res {
            self.buffers.has_seen_eof = true;
        }
        res
    }

    fn write_tls(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.core
            .common
            .send
            .sendable_tls
            .write_to(wr)
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
                .core
                .common
                .recv
                .has_received_close_notify
            && (self
                .core
                .common
                .send
                .may_send_application_data
                || self
                    .core
                    .common
                    .send
                    .sendable_tls
                    .is_empty())
    }

    fn wants_write(&self) -> bool {
        !self
            .core
            .common
            .send
            .sendable_tls
            .is_empty()
    }

    fn reader(&mut self) -> Reader<'_> {
        let has_received_close_notify = self
            .core
            .common
            .recv
            .has_received_close_notify;
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
            let Some(payload) = self
                .core
                .process_new_packets(&mut self.buffers.deframer_buffer, None)?
            else {
                break;
            };

            let payload =
                payload.reborrow(&Delocator::new(self.buffers.deframer_buffer.slice_mut()));
            self.buffers
                .received_plaintext
                .append(payload.into_vec());
            self.buffers.deframer_buffer.discard(
                self.core
                    .common
                    .recv
                    .deframer
                    .take_discard(),
            );
        }

        // Release unsent buffered plaintext.
        if self
            .core
            .common
            .send
            .may_send_application_data
            && !self
                .buffers
                .sendable_plaintext
                .is_empty()
        {
            self.core
                .common
                .send
                .send_buffered_plaintext(&mut self.buffers.sendable_plaintext);
        }

        Ok(self.current_io_state())
    }

    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        self.core.exporter()
    }

    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        self.core.dangerous_extract_secrets()
    }

    fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.buffers
            .sendable_plaintext
            .set_limit(limit);
        self.core
            .common
            .send
            .sendable_tls
            .set_limit(limit);
    }

    fn set_plaintext_buffer_limit(&mut self, limit: Option<usize>) {
        self.buffers
            .received_plaintext
            .set_limit(limit);
    }

    fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core
            .common
            .send
            .refresh_traffic_keys()
    }

    fn send_close_notify(&mut self) {
        self.core
            .common
            .send
            .send_close_notify()
    }

    fn is_handshaking(&self) -> bool {
        !(self
            .core
            .common
            .send
            .may_send_application_data
            && self
                .core
                .common
                .recv
                .may_receive_application_data)
    }

    fn fips(&self) -> FipsStatus {
        self.fips
    }
}

impl PlaintextSink for ClientConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self
            .core
            .common
            .send
            .buffer_plaintext(buf.into(), &mut self.buffers.sendable_plaintext);
        self.core
            .common
            .send
            .maybe_refresh_traffic_keys();
        Ok(len)
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
        let len = self
            .core
            .common
            .send
            .buffer_plaintext(payload, &mut self.buffers.sendable_plaintext);
        self.core
            .common
            .send
            .maybe_refresh_traffic_keys();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.core.common.outputs
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
        let fips = config.fips();
        Ok(ClientConnection {
            core: ConnectionCore::for_client(
                config,
                name,
                ClientExtensionsInput::from_alpn(alpn_protocols),
                None,
                Protocol::Tcp,
            )?,
            buffers: Buffers::new(),
            fips,
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

impl ConnectionCore<ClientSide> {
    pub(crate) fn for_client(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        extra_exts: ClientExtensionsInput,
        quic: Option<&mut dyn QuicOutput>,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client);
        common_state
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        let mut data = ClientConnectionData::new();

        let mut output = SideCommonOutput {
            side: &mut data,
            quic,
            common: &mut common_state,
        };

        let input = ClientHelloInput::new(name, &extra_exts, protocol, &mut output, config)?;
        let state = input.start_handshake(extra_exts, &mut output)?;

        Ok(Self::new(state, data, common_state))
    }

    pub(crate) fn is_early_data_accepted(&self) -> bool {
        self.side.early_data.is_accepted()
    }
}

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

pub(crate) struct ClientConnectionData {
    early_data: EarlyData,
    ech_status: EchStatus,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            early_data: EarlyData::new(),
            ech_status: EchStatus::default(),
        }
    }
}

/// State associated with a client connection.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct ClientSide;

impl crate::conn::SideData for ClientSide {}

impl crate::conn::private::Side for ClientSide {
    type Data = ClientConnectionData;
    type State = super::hs::ClientState;
}

impl SideOutput for ClientConnectionData {
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
