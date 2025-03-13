use core::marker::PhantomData;

use alloc::boxed::Box;

use crate::client::ClientConnectionData;
use crate::common_state::Protocol;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{CertificateChain, NewSessionTicketPayloadTls13};
use crate::quic::Quic;
use crate::server::ServerConnectionData;
use crate::{CommonState, ConnectionTrafficSecrets, Error, ProtocolVersion, SupportedCipherSuite};

/// An external client connection.
///
/// The only difference for external client vs server connections is that client
/// connections have support for recording new session tickets.
pub type ExternalClientConnection = ExternalConnection<ClientConnectionData>;

/// An external server connection.
///
/// The only difference for external client vs server connections is that client
/// connections have support for recording new session tickets.
pub type ExternalServerConnection = ExternalConnection<ServerConnectionData>;

/// An external connection.
///
/// See the [`crate::external`] module docs for more details.
pub struct ExternalConnection<Data> {
    state: Box<dyn ExternalState>,

    peer_certificates: Option<CertificateChain<'static>>,
    quic: Quic,

    negotiated_version: ProtocolVersion,
    protocol: Protocol,
    suite: SupportedCipherSuite,

    _data: PhantomData<Data>,
}

impl<Data> ExternalConnection<Data> {
    pub(crate) fn new(state: Box<dyn ExternalState>, common: CommonState) -> Result<Self, Error> {
        Ok(Self {
            state,

            peer_certificates: common.peer_certificates,
            quic: common.quic,
            negotiated_version: common
                .negotiated_version
                .ok_or(Error::HandshakeNotComplete)?,
            protocol: common.protocol,
            suite: common
                .suite
                .ok_or(Error::HandshakeNotComplete)?,

            _data: PhantomData,
        })
    }

    /// Retrieves the ciphersuite agreed with the peer.
    pub fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        self.suite
    }

    /// Retrieves the protocol version agreed with the peer.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.negotiated_version
    }

    /// Update the traffic secret used for encrypting messages sent to the peer.
    ///
    /// Returns the new traffic secret and initial sequence number to use.
    ///
    /// In order to use the new secret you should send a TLS 1.3 key update to
    /// the peer and then use the new traffic secrets to encrypt any future
    /// messages.
    ///
    /// Note that it is only possible to update the traffic secrets on a TLS 1.3
    /// connection. Attempting to do so on a non-TLS 1.3 connection will result
    /// in an error.
    pub fn update_tx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), Error> {
        // The sequence number always starts at 0 after a key update.
        self.state
            .update_secrets(Direction::Transmit)
            .map(|secret| (0, secret))
    }

    /// Update the traffic secret used for decrypting messages received from the
    /// peer.
    ///
    /// Returns the new traffic secret and initial sequence number to use.
    ///
    /// You should call this method once you receive a TLS 1.3 key update message
    /// from the peer.
    ///
    /// Note that it is only possible to update the traffic secrets on a TLS 1.3
    /// connection. Attempting to do so on a non-TLS 1.3 connection will result
    /// in an error.
    pub fn update_rx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), Error> {
        // The sequence number always starts at 0 after a key update.
        self.state
            .update_secrets(Direction::Receive)
            .map(|secret| (0, secret))
    }
}

impl ExternalConnection<ClientConnectionData> {
    /// Handle a `new_session_ticket` message from the peer.
    ///
    /// This will register the session ticket within with rustls so that it can
    /// be used to establish future TLS connections.
    ///
    /// # Getting the right payload
    ///
    /// This method expects to be passed the inner payload of the handshake
    /// message. This means that you will need to parse the header of the
    /// handshake message in order to determine the correct payload to pass in.
    /// The message format is described in [RFC 8446 section 4][0]. `payload`
    /// should not include the `msg_type` or `length` fields.
    ///
    /// Code to parse out the payload should look something like this
    /// ```no_run
    /// use rustls::{ContentType, HandshakeType};
    /// use rustls::external::ExternalClientConnection;
    ///
    /// # fn doctest(conn: &mut ExternalClientConnection, typ: ContentType, message: &[u8]) -> Result<(), rustls::Error> {
    /// let conn: &mut ExternalClientConnection = // ...
    /// #   conn;
    /// let typ: ContentType = // ...
    /// #   typ;
    /// let mut message: &[u8] = // ...
    /// #   message;
    ///
    /// // Processing for other messages not included in this example
    /// assert_eq!(typ, ContentType::Handshake);
    ///
    /// // There may be multiple handshake payloads within a single handshake message.
    /// while !message.is_empty() {
    ///     let (typ, len, rest) = match message {
    ///         &[typ, a, b, c, ref rest @ ..] => (
    ///             HandshakeType::from(typ),
    ///             u32::from_be_bytes([0, a, b, c]) as usize,
    ///             rest
    ///         ),
    ///         _ => panic!("error handling not included in this example")
    ///     };
    ///
    ///     // Processing for other messages not included in this example.
    ///     assert_eq!(typ, HandshakeType::NewSessionTicket);
    ///     assert!(rest.len() >= len, "invalid handshake message");
    ///
    ///     let (payload, rest) = rest.split_at(len);
    ///     message = rest;
    ///
    ///     conn.handle_new_session_ticket(payload)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// This method will return an error if:
    /// - This connection is not a TLS 1.3 connection (in TLS 1.2 session tickets
    ///   are sent as part of the handshake).
    /// - This connection is a server connection.
    /// - The provided payload is not a valid `new_session_ticket` payload or has
    ///   extra unparsed trailing data.
    /// - An error occurs while the connection updates the session ticket store.
    ///
    /// [0]: https://datatracker.ietf.org/doc/html/rfc8446#section-4
    pub fn handle_new_session_ticket(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.protocol_version() != ProtocolVersion::TLSv1_3 {
            return Err(Error::General(
                "TLS 1.2 session tickets may not be sent once the handshake has completed".into(),
            ));
        }

        let mut reader = Reader::init(payload);
        let nst = NewSessionTicketPayloadTls13::read(&mut reader)?;
        reader.expect_empty("NewSessionTicket")?;

        let mut cx = ExternalContext {
            peer_certificates: self.peer_certificates.as_ref(),
            protocol: self.protocol,
            quic: &self.quic,
        };
        self.state
            .handle_new_session_ticket(&mut cx, &nst)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Direction {
    Transmit,
    Receive,
}

pub(crate) trait ExternalState: Send + Sync {
    /// Update the traffic secret for the specified direction on the connection.
    fn update_secrets(&mut self, dir: Direction) -> Result<ConnectionTrafficSecrets, Error>;

    fn handle_new_session_ticket(
        &mut self,
        cx: &mut ExternalContext<'_>,
        message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error>;
}

pub(crate) struct ExternalContext<'a> {
    pub(crate) peer_certificates: Option<&'a CertificateChain<'static>>,
    pub(crate) protocol: Protocol,
    pub(crate) quic: &'a Quic,
}

impl ExternalContext<'_> {
    pub(crate) fn is_quic(&self) -> bool {
        self.protocol == Protocol::Quic
    }
}
