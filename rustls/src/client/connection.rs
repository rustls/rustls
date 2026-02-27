use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};
use std::io;

use pki_types::{FipsStatus, ServerName};

use super::ClientState;
use super::config::ClientConfig;
use super::hs::ClientHelloInput;
use crate::client::{EchStatus, SendEarlyData};
use crate::common_state::{
    CommonState, ConnectionOutputs, EarlyDataEvent, Event, Output, Protocol, Side,
};
use crate::conn::{
    Connection, ConnectionBuffers, ConnectionCore, IoState, KeyingMaterialExporter, PlaintextSink,
    Reader, SideCommonOutput, Writer,
};
#[cfg(doc)]
use crate::crypto;
use crate::crypto::cipher::OutboundPlain;
use crate::enums::ApplicationProtocol;
use crate::error::{ApiMisuse, Error};
use crate::log::trace;
use crate::msgs::ClientExtensionsInput;
use crate::state::ReceiveTrafficState;
use crate::suites::ExtractedSecrets;
use crate::sync::Arc;

/// This represents a single TLS client connection.
pub struct ClientConnection {
    state: Result<ClientState, Error>,
    buffers: ConnectionBuffers,
    fips: FipsStatus,
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
        match &mut self.state {
            Ok(ClientState::AwaitServerFlight(st)) => match st.try_send_early_data() {
                Some(send) => Some(WriteEarlyData::new(send, &mut self.buffers)),
                None => None,
            },
            _ => None,
        }
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        match &self.state {
            Ok(ClientState::Traffic(traffic)) => traffic.is_early_data_accepted(),
            _ => false,
        }
    }

    /// Return the connection's Encrypted Client Hello (ECH) status.
    pub fn ech_status(&self) -> EchStatus {
        self.state
            .as_ref()
            .map(|s| s.ech_status())
            .unwrap_or(EchStatus::Rejected)
    }

    /// Returns the number of TLS1.3 tickets that have been received.
    pub fn tls13_tickets_received(&self) -> u32 {
        match &self.state {
            Ok(ClientState::Traffic(ct)) => ct
                .receive
                .as_ref()
                .map(|r| r.tls13_tickets_received())
                .unwrap_or_default(),
            _ => 0,
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
            Ok(ClientState::Traffic(traffic)) => traffic.receive.is_none(),
            _ => false,
        }
    }

    fn write_or_buffer_appdata(&mut self, data: OutboundPlain<'_>) -> io::Result<usize> {
        Ok(match &mut self.state {
            Ok(ClientState::Traffic(ct)) => {
                let Some(s) = &mut ct.send else {
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

                if let Ok(chunks) = s.write(data.split_at(len).0) {
                    for c in chunks {
                        self.buffers.sendable_tls.append(c);
                    }
                }
                while let Some(chunk) = s.take_data() {
                    self.buffers.sendable_tls.append(chunk);
                }
                len
            }
            _ => self
                .buffers
                .sendable_plaintext
                .append_limited_copy(data),
        })
    }

    /// Act on a potential state transition from a handshake-related state to `new`.
    fn post_handshake_state(&mut self, mut new: ClientState) -> ClientState {
        if let ClientState::Traffic(traffic) = &mut new {
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

impl Connection for ClientConnection {
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
                ClientState::SendClientFlight(mut scf) => {
                    while let Some(chunk) = scf.take_data() {
                        self.buffers.sendable_tls.append(chunk);
                    }
                    self.state = Ok(self.post_handshake_state(scf.into_next()));
                }
                ClientState::AwaitServerFlight(asf) => {
                    if self.buffers.deframer_buffer.is_empty() {
                        self.state = Ok(ClientState::AwaitServerFlight(asf));
                        break;
                    }
                    match asf.input_data(&mut self.buffers.deframer_buffer) {
                        Ok(state) => {
                            self.state = Ok(self.post_handshake_state(state));
                            if matches!(self.state, Ok(ClientState::AwaitServerFlight(_))) {
                                break;
                            }
                        }
                        Err(mut err) => {
                            while let Some(chunk) = err.take_tls_data() {
                                self.buffers.sendable_tls.append(chunk);
                            }

                            self.state = Err(err.error.clone());
                            return Err(err.error);
                        }
                    };
                }
                ClientState::Traffic(mut traffic) => {
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

                    self.state = Ok(ClientState::Traffic(traffic));
                    break;
                }
            }
        }

        Ok(self.current_io_state())
    }

    fn exporter(&mut self) -> Result<KeyingMaterialExporter, Error> {
        match &mut self.state {
            Ok(ClientState::Traffic(traffic)) => traffic.outputs.take_exporter(),
            _ => Err(Error::HandshakeNotComplete),
        }
    }

    fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        match self.state {
            Ok(ClientState::Traffic(traffic)) => Ok(traffic
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
            Ok(ClientState::Traffic(ct)) => match &mut ct.send {
                Some(s) => s.refresh_traffic_keys(),
                None => Err(ApiMisuse::SendSideAlreadyClosed.into()),
            },
            _ => Err(Error::HandshakeNotComplete),
        }
    }

    fn send_close_notify(&mut self) {
        let Ok(ClientState::Traffic(traffic)) = &mut self.state else {
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
        !matches!(self.state, Ok(ClientState::Traffic(_)))
    }

    fn fips(&self) -> FipsStatus {
        self.fips
    }
}

impl PlaintextSink for ClientConnection {
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

impl From<ClientState> for ClientConnection {
    fn from(state: ClientState) -> Self {
        // pump clienthello into outgoing buffers
        let ClientState::SendClientFlight(mut send) = state else {
            unreachable!();
        };

        let mut buffers = ConnectionBuffers::new();
        while let Some(chunk) = send.take_data() {
            buffers.sendable_tls.append(chunk);
        }
        let state = Ok(send.into_next());

        Self {
            state,
            buffers,
            fips: FipsStatus::Unvalidated,
        }
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        self.state.as_ref().unwrap().deref()
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state.as_mut().unwrap().deref_mut()
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

        let fips = config.fips();
        let mut inner = ClientConnection::from(ClientState::new(config, name, alpn_protocols)?);
        inner.fips = fips;
        Ok(inner)
    }
}

/// Allows writing of early data in resumed TLS 1.3 connections.
///
/// "Early data" is also known as "0-RTT data".
///
/// This type implements [`io::Write`].
pub struct WriteEarlyData<'a> {
    send: SendEarlyData<'a>,
    buffers: &'a mut ConnectionBuffers,
}

impl<'a> WriteEarlyData<'a> {
    fn new(send: SendEarlyData<'a>, buffers: &'a mut ConnectionBuffers) -> Self {
        WriteEarlyData { send, buffers }
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.send.bytes_left()
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
        self.send.early_exporter()
    }
}

impl io::Write for WriteEarlyData<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some((used, chunks)) = self.send.write_into_vecs(buf) else {
            return Ok(0);
        };
        for c in chunks {
            self.buffers.sendable_tls.append(c);
        }
        Ok(used)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/*
impl EarlyData {
    pub(crate) fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        self.check_write_opt(sz)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
    }

    pub(crate) fn bytes_left(&self) -> usize {
        self.left
    }
}*/

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
        let mut data = ClientConnectionData::new();

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

    pub(super) fn is_accepted(&self) -> bool {
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

    pub(super) fn check_write(&mut self, sz: usize) -> io::Result<usize> {
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

    pub(super) fn bytes_left(&self) -> usize {
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

#[derive(Debug)]
pub(crate) struct ClientConnectionData {
    pub(super) early_data: EarlyData,
    ech_status: EchStatus,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            early_data: EarlyData::new(),
            ech_status: EchStatus::default(),
        }
    }

    pub(crate) fn early_data_is_enabled(&self) -> bool {
        self.early_data.is_enabled()
    }

    pub(crate) fn ech_status(&self) -> EchStatus {
        self.ech_status
    }
}

impl Output for ClientConnectionData {
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

/// State associated with a client connection.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct ClientSide;

impl crate::conn::SideData for ClientSide {}

impl crate::conn::private::SideData for ClientSide {
    type Data = ClientConnectionData;
    type StateMachine = super::hs::StateMachine;
}
