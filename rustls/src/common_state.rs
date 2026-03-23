use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, DerefMut, Range};

use pki_types::DnsName;

use crate::client::EchStatus;
use crate::conn::{Exporter, ReceivePath, SendOutput, SendPath};
use crate::crypto::Identity;
use crate::crypto::cipher::Payload;
use crate::crypto::kx::SupportedKxGroup;
use crate::enums::{ApplicationProtocol, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::hash_hs::HandshakeHash;
use crate::msgs::{
    AlertLevel, Codec, Delocator, HandshakeMessagePayload, Locator, Message, MessagePayload,
};
use crate::quic::{self, QuicOutput};
use crate::suites::SupportedCipherSuite;

/// Connection state common to both client and server connections.
pub struct CommonState {
    pub(crate) outputs: ConnectionOutputs,
    pub(crate) send: SendPath,
    pub(crate) recv: ReceivePath,
}

impl CommonState {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            outputs: ConnectionOutputs::default(),
            send: SendPath::default(),
            recv: ReceivePath::new(side),
        }
    }

    /// Returns true if the caller should call [`Connection::write_tls`] as soon as possible.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn wants_write(&self) -> bool {
        !self.send.sendable_tls.is_empty()
    }

    /// Queues a `close_notify` warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn send_close_notify(&mut self) {
        self.send.send_close_notify()
    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    ///
    /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
    pub fn is_handshaking(&self) -> bool {
        !(self.send.may_send_application_data && self.recv.may_receive_application_data)
    }
}

impl Deref for CommonState {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.outputs
    }
}

impl DerefMut for CommonState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.outputs
    }
}

impl fmt::Debug for CommonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonState")
            .finish_non_exhaustive()
    }
}

/// Facts about the connection learned through the handshake.
#[derive(Default)]
pub struct ConnectionOutputs {
    negotiated_version: Option<ProtocolVersion>,
    handshake_kind: Option<HandshakeKind>,
    suite: Option<SupportedCipherSuite>,
    negotiated_kx_group: Option<&'static dyn SupportedKxGroup>,
    alpn_protocol: Option<ApplicationProtocol<'static>>,
    peer_identity: Option<Identity<'static>>,
    pub(crate) exporter: Option<Box<dyn Exporter>>,
    pub(crate) early_exporter: Option<Box<dyn Exporter>>,
}

impl ConnectionOutputs {
    /// Retrieves the certificate chain or the raw public key used by the peer to authenticate.
    ///
    /// This is made available for both full and resumed handshakes.
    ///
    /// For clients, this is the identity of the server. For servers, this is the identity of the
    /// client, if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    pub fn peer_identity(&self) -> Option<&Identity<'static>> {
        self.peer_identity.as_ref()
    }

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of `None` after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    pub fn alpn_protocol(&self) -> Option<&ApplicationProtocol<'static>> {
        self.alpn_protocol.as_ref()
    }

    /// Retrieves the cipher suite agreed with the peer.
    ///
    /// This returns None until the cipher suite is agreed.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// Retrieves the key exchange group agreed with the peer.
    ///
    /// This function may return `None` depending on the state of the connection,
    /// the type of handshake, and the protocol version.
    ///
    /// If [`CommonState::is_handshaking()`] is true this function will return `None`.
    /// Similarly, if the [`ConnectionOutputs::handshake_kind()`] is [`HandshakeKind::Resumed`]
    /// and the [`ConnectionOutputs::protocol_version()`] is TLS 1.2, then no key exchange will have
    /// occurred and this function will return `None`.
    pub fn negotiated_key_exchange_group(&self) -> Option<&'static dyn SupportedKxGroup> {
        self.negotiated_kx_group
    }

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns `None` until the version is agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    /// Which kind of handshake was performed.
    ///
    /// This tells you whether the handshake was a resumption or not.
    ///
    /// This will return `None` before it is known which sort of
    /// handshake occurred.
    pub fn handshake_kind(&self) -> Option<HandshakeKind> {
        self.handshake_kind
    }

    pub(super) fn into_kernel_parts(self) -> Option<(ProtocolVersion, SupportedCipherSuite)> {
        let Self {
            negotiated_version,
            suite,
            ..
        } = self;

        match (negotiated_version, suite) {
            (Some(version), Some(suite)) => Some((version, suite)),
            _ => None,
        }
    }
}

impl ConnectionOutput for ConnectionOutputs {
    fn handle(&mut self, ev: OutputEvent<'_>) {
        match ev {
            OutputEvent::ApplicationProtocol(protocol) => {
                self.alpn_protocol = Some(ApplicationProtocol::from(protocol.as_ref()).to_owned())
            }
            OutputEvent::CipherSuite(suite) => self.suite = Some(suite),
            OutputEvent::EarlyExporter(exporter) => self.early_exporter = Some(exporter),
            OutputEvent::Exporter(exporter) => self.exporter = Some(exporter),
            OutputEvent::HandshakeKind(hk) => {
                assert!(self.handshake_kind.is_none());
                self.handshake_kind = Some(hk);
            }
            OutputEvent::KeyExchangeGroup(kxg) => {
                assert!(self.negotiated_kx_group.is_none());
                self.negotiated_kx_group = Some(kxg);
            }
            OutputEvent::PeerIdentity(identity) => self.peer_identity = Some(identity),
            OutputEvent::ProtocolVersion(ver) => {
                self.negotiated_version = Some(ver);
            }
        }
    }
}

/// Send an alert via `output` if `error` specifies one.
pub(crate) fn maybe_send_fatal_alert(send: &mut dyn SendOutput, error: &Error) {
    let Ok(alert) = AlertDescription::try_from(error) else {
        return;
    };
    send.send_alert(AlertLevel::Fatal, alert);
}

/// Describes which sort of handshake happened.
#[derive(Debug, PartialEq, Clone, Copy)]
#[non_exhaustive]
pub enum HandshakeKind {
    /// A full handshake.
    ///
    /// This is the typical TLS connection initiation process when resumption is
    /// not yet unavailable, and the initial `ClientHello` was accepted by the server.
    Full,

    /// A full TLS1.3 handshake, with an extra round-trip for a `HelloRetryRequest`.
    ///
    /// The server can respond with a `HelloRetryRequest` if the initial `ClientHello`
    /// is unacceptable for several reasons, the most likely being if no supported key
    /// shares were offered by the client.
    FullWithHelloRetryRequest,

    /// A resumed handshake.
    ///
    /// Resumed handshakes involve fewer round trips and less cryptography than
    /// full ones, but can only happen when the peers have previously done a full
    /// handshake together, and then remember data about it.
    Resumed,

    /// A resumed handshake, with an extra round-trip for a `HelloRetryRequest`.
    ///
    /// The server can respond with a `HelloRetryRequest` if the initial `ClientHello`
    /// is unacceptable for several reasons, but this does not prevent the client
    /// from resuming.
    ResumedWithHelloRetryRequest,
}

/// The route for handshake state machine to surface determinations about the connection.
pub(crate) trait Output<'m> {
    fn emit(&mut self, ev: Event<'_>);

    fn output(&mut self, ev: OutputEvent<'_>);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool);

    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        None
    }

    fn received_plaintext(&mut self, _payload: Payload<'m>) {}

    fn start_traffic(&mut self);

    fn receive(&mut self) -> &mut ReceivePath;

    fn send(&mut self) -> &mut dyn SendOutput;
}

pub(crate) trait ConnectionOutput {
    fn handle(&mut self, ev: OutputEvent<'_>);
}

/// The set of events output by the low-level handshake state machine.
pub(crate) enum Event<'a> {
    EarlyApplicationData(Payload<'a>),
    EarlyData(EarlyDataEvent),
    EchStatus(EchStatus),
    ReceivedServerName(Option<DnsName<'static>>),
    ResumptionData(Vec<u8>),
    ServerEchAccepted(Option<crate::server::ech::EchFrontendInfo>),
}

pub(crate) enum OutputEvent<'a> {
    ApplicationProtocol(ApplicationProtocol<'a>),
    CipherSuite(SupportedCipherSuite),
    EarlyExporter(Box<dyn Exporter>),
    Exporter(Box<dyn Exporter>),
    HandshakeKind(HandshakeKind),
    KeyExchangeGroup(&'static dyn SupportedKxGroup),
    PeerIdentity(Identity<'static>),
    ProtocolVersion(ProtocolVersion),
}

pub(crate) enum EarlyDataEvent {
    /// server: we accepted an early_data offer
    Accepted,
    /// client: declares the maximum amount of early data that can be sent
    Enable(usize),
    /// client: early data can now be sent using the record layer as normal
    Start,
    /// client: early data phase has closed after sending EndOfEarlyData
    Finished,
    /// client: the server rejected our request for early data
    Rejected,
}

/// Lifetime-erased equivalent to [`Payload`]
///
/// Stores an index into [`Payload`] buffer enabling in-place decryption
/// without holding a lifetime to the receive buffer.
pub(crate) enum UnborrowedPayload {
    Unborrowed(Range<usize>),
    Owned(Vec<u8>),
}

impl UnborrowedPayload {
    /// Convert [`Payload`] into [`UnborrowedPayload`] which stores a range
    /// into the [`Payload`] slice without borrowing such that it can be later
    /// reborrowed.
    ///
    /// # Panics
    ///
    /// Passed [`Locator`] must have been created from the same slice which
    /// contains the payload.
    pub(crate) fn unborrow(locator: &Locator, payload: Payload<'_>) -> Self {
        match payload {
            Payload::Borrowed(payload) => Self::Unborrowed(locator.locate(payload)),
            Payload::Owned(payload) => Self::Owned(payload),
        }
    }

    /// Convert [`UnborrowedPayload`] back into [`Payload`]
    ///
    /// # Panics
    ///
    /// Passed [`Delocator`] must have been created from the same slice that
    /// [`UnborrowedPayload`] was originally unborrowed from.
    pub(crate) fn reborrow<'b>(self, delocator: &Delocator<'b>) -> Payload<'b> {
        match self {
            Self::Unborrowed(range) => Payload::Borrowed(delocator.slice_from_range(&range)),
            Self::Owned(payload) => Payload::Owned(payload),
        }
    }
}

/// Side of the connection.
#[expect(clippy::exhaustive_enums)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Side {
    /// A client initiates the connection.
    Client,
    /// A server waits for a client to connect.
    Server,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Protocol {
    /// TCP-TLS, standardized in RFC5246 and RFC8446
    Tcp,
    /// QUIC, standardized in RFC9001
    Quic(quic::Version),
}

impl Protocol {
    pub(crate) fn is_quic(&self) -> bool {
        matches!(self, Self::Quic(_))
    }
}

pub(crate) struct HandshakeFlight<'a, const TLS13: bool> {
    pub(crate) transcript: &'a mut HandshakeHash,
    body: Vec<u8>,
}

impl<'a, const TLS13: bool> HandshakeFlight<'a, TLS13> {
    pub(crate) fn new(transcript: &'a mut HandshakeHash) -> Self {
        Self {
            transcript,
            body: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, hs: HandshakeMessagePayload<'_>) {
        let start_len = self.body.len();
        hs.encode(&mut self.body);
        self.transcript
            .add(&self.body[start_len..]);
    }

    pub(crate) fn finish(self, output: &mut dyn Output<'_>) {
        let m = Message {
            version: match TLS13 {
                true => ProtocolVersion::TLSv1_3,
                false => ProtocolVersion::TLSv1_2,
            },
            payload: MessagePayload::HandshakeFlight(Payload::new(self.body)),
        };

        output.send_msg(m, TLS13);
    }
}

pub(crate) type HandshakeFlightTls12<'a> = HandshakeFlight<'a, false>;
pub(crate) type HandshakeFlightTls13<'a> = HandshakeFlight<'a, true>;
