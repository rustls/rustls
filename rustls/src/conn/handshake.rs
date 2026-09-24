//! Transport-generic handshake machinery.
//!
//! [`Accepted`] and [`VerifyPeerIdentity`] are public and generic over [`Transport`].
//!
//! The remaining public handshake types (`rustls::{NeedsInput, ClientHandshake,
//! ServerHandshake}` and their `rustls::quic` counterparts) are thin shims over the types
//! in this module.  The shims own the public signatures and documentation; the shared
//! underlying logic lives here, parameterised by [`Transport`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::{fmt, mem};

use super::{
    ConnectionCommon, NeedsInput, SideCommonOutput, SideData, StateMachine, VerifySidePeerIdentity,
};
use crate::client::{ClientSide, ClientState};
use crate::common_state::{Protocol, maybe_send_fatal_alert};
use crate::crypto::VerifiedIdentity;
use crate::crypto::cipher::Payload;
use crate::error::Error;
use crate::msgs::{ServerExtensionsInput, TransportParameters};
use crate::quic::{self, Quic, QuicEvent, QuicOutput};
use crate::server::{
    ChooseConfig, ClientHello, ServerConfig, ServerHandshake, ServerSide, ServerState,
};
use crate::sync::Arc;
use crate::tracing::trace;

/// The states a server handshake can be in, for any transport.
pub(crate) enum ServerNext<T: Transport> {
    NeedsInput(ConnectionCommon<ServerSide, T>),
    ChooseConfig(Accepted<T>),
    VerifyClientIdentity(VerifyPeerIdentity<ServerSide, T>),
    Complete(ConnectionCommon<ServerSide, T>),
}

impl<T: Transport> TryFrom<ConnectionCommon<ServerSide, T>> for ServerNext<T> {
    type Error = Error;

    fn try_from(mut conn: ConnectionCommon<ServerSide, T>) -> Result<Self, Error> {
        const MISUSED: Error = Error::Unreachable("forgot to restore state");

        Ok(match mem::replace(&mut conn.state, Err(MISUSED))? {
            ServerState::ChooseConfig(choose_config) => Self::ChooseConfig(Accepted {
                conn,
                choose_config,
            }),

            ServerState::VerifyClientIdentity(verify_identity) => {
                Self::VerifyClientIdentity(VerifyPeerIdentity {
                    conn,
                    verify_identity,
                })
            }

            state if state.is_traffic() => {
                conn.state = Ok(state);
                Self::Complete(conn)
            }

            state => {
                conn.state = Ok(state);
                Self::NeedsInput(conn)
            }
        })
    }
}

/// The states a client handshake can be in, for any transport.
pub(crate) enum ClientNext<T: Transport> {
    NeedsInput(ConnectionCommon<ClientSide, T>),
    VerifyServerIdentity(VerifyPeerIdentity<ClientSide, T>),
    Complete(ConnectionCommon<ClientSide, T>),
}

impl<T: Transport> TryFrom<ConnectionCommon<ClientSide, T>> for ClientNext<T> {
    type Error = Error;

    fn try_from(mut conn: ConnectionCommon<ClientSide, T>) -> Result<Self, Error> {
        const MISUSED: Error = Error::Unreachable("forgot to restore state");

        Ok(match mem::replace(&mut conn.state, Err(MISUSED))? {
            ClientState::VerifyServerIdentity(verify_identity) => {
                Self::VerifyServerIdentity(VerifyPeerIdentity {
                    conn,
                    verify_identity,
                })
            }

            state if state.is_traffic() => {
                conn.state = Ok(state);
                Self::Complete(conn)
            }

            state => {
                conn.state = Ok(state);
                Self::NeedsInput(conn)
            }
        })
    }
}

/// Represents that a `ClientHello` message has been received.
///
/// The handshake can be progressed by choosing a [`ServerConfig`] based on
/// [`Self::client_hello()`] and providing it to [`Self::choose_config()`].
pub struct Accepted<T: Transport> {
    // invariant: `core.inner.state` is `Err(_)` and requires restoring
    conn: ConnectionCommon<ServerSide, T>,
    choose_config: Box<ChooseConfig>,
}

impl<T: Transport> Accepted<T> {
    /// Get the [`ClientHello`] for this connection.
    pub fn client_hello(&self) -> ClientHello<'_> {
        let ch = self.choose_config.client_hello();
        trace!("Accepted::client_hello(): {ch:#?}");
        ch
    }

    fn partial_choose_config(
        self,
        config: Arc<ServerConfig>,
        exts: ServerExtensionsInput,
        tls: &mut Vec<u8>,
    ) -> Result<ConnectionCommon<ServerSide, T>, Error> {
        let Self {
            mut conn,
            choose_config,
        } = self;

        let result = conn.accepted(choose_config, exts, config, tls);

        let send_path = &mut conn.common.send;

        if let Err(err) = &result {
            maybe_send_fatal_alert(send_path, err, tls)?;
        }

        result?;
        Ok(conn)
    }
}

impl Accepted<Tcp> {
    /// Choose a [`ServerConfig`] to progress the handshake.
    ///
    /// Output to send to the peer is appended to `tls`.  Typically, this is the `ServerHello`,
    /// but it may also be an `Alert` if an error is returned.
    ///
    /// Returns an error if configuration-dependent validation of the received `ClientHello` message fails.
    pub fn choose_config(
        self,
        config: Arc<ServerConfig>,
        tls: &mut Vec<u8>,
    ) -> Result<ServerHandshake, Error> {
        let core = self.partial_choose_config(config, ServerExtensionsInput::default(), tls)?;
        Ok(ServerHandshake::NeedsInput(NeedsInput(core)))
    }
}

impl Accepted<Quic> {
    /// Choose a [`ServerConfig`] to progress the handshake.
    ///
    /// Resolves an [`Accepted`], providing the [`ServerConfig`] that should be used for
    /// the session, and the TLS-encoded QUIC transport parameters to send.
    ///
    /// Returns an error if configuration-dependent validation of the received
    /// `ClientHello` message fails.
    ///
    /// Events are appended to `output`.
    pub fn choose_config(
        self,
        config: Arc<ServerConfig>,
        params: Vec<u8>,
        output: &mut Vec<QuicEvent>,
    ) -> Result<quic::ServerHandshake, Error> {
        quic::check_server_config(&config)?;

        let exts = ServerExtensionsInput {
            transport_parameters: Some(match self.conn.transport.version {
                quic::Version::V1 | quic::Version::V2 => {
                    TransportParameters::Quic(Payload::new(params))
                }
            }),
        };

        let mut tls = Vec::new();
        let core = self.partial_choose_config(config, exts, &mut tls)?;

        // In QUIC mode, handshake output is emitted via `QuicEvent`s, not `tls`.
        debug_assert!(tls.is_empty());
        quic::ServerHandshake::from_core(core, output)
    }
}

impl<T: Transport> fmt::Debug for Accepted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .finish_non_exhaustive()
    }
}

/// The peer's presented identity must be verified.
///
/// The caller has three choices:
///
/// - Call [`Self::with_config()`].  This calls the configured verifier trait
///   ([`ClientVerifier::verify_identity()`][] or [`ServerVerifier::verify_identity()`][])
///   synchronously.
///
/// - Call [`Self::presented_identity()`] to obtain the peer's presented identity,
///   verify that outside the library (perhaps asynchronously), and then continue the handshake with
///   [`Self::continue_with()`].
///
///   If the verification fails, the error can be passed into [`Self::continue_with()`] to follow
///   a uniform error handling path.
///
/// - Abandon the handshake by discarding this object.
///
/// The returned object is a further handshake state for this side.  Commonly this will
/// contain a [`ServerHandshake::NeedsInput`][], [`ClientHandshake::NeedsInput`][] or [`quic::ServerHandshake::NeedsInput`][]
/// which will accept and process further data.
///
/// [`ClientVerifier::verify_identity()`]: crate::verify::ClientVerifier::verify_identity
/// [`ServerVerifier::verify_identity()`]: crate::verify::ServerVerifier::verify_identity
/// [`ServerHandshake::NeedsInput`]: crate::server::ServerHandshake::NeedsInput
/// [`ClientHandshake::NeedsInput`]: crate::client::ClientHandshake::NeedsInput
/// [`quic::ServerHandshake::NeedsInput`]: crate::quic::ServerHandshake::NeedsInput
pub struct VerifyPeerIdentity<Side: SideData, T: Transport> {
    // invariant: `core.inner.state` is `Err(_)` and requires restoring
    conn: ConnectionCommon<Side, T>,
    verify_identity: Box<dyn VerifySidePeerIdentity<Side>>,
}

impl<Side: SideData, T: Transport> VerifyPeerIdentity<Side, T> {
    /// Inspect the identity that the peer has provided.
    pub fn presented_identity(&self) -> Result<Side::PeerIdentity<'_>, Error> {
        self.verify_identity
            .presented_identity()
    }
}

impl<Side: SideData> VerifyPeerIdentity<Side, Tcp> {
    /// Progress the handshake by calling the pre-configured certificate verification trait.
    pub fn with_config(self, tls: &mut Vec<u8>) -> Result<Side::Handshake, Error> {
        let result = self
            .verify_identity
            .verify_with_config();
        self.continue_with(result, tls)
    }

    /// Progress the handshake by incorporating the result of an external verification.
    ///
    /// Further data to send to the peer may be appended to `tls`.
    ///
    /// If `verification_result` is an error, this error is returned and the handshake terminates.
    /// An alert may be appended to `tls` for sending to the peer.
    pub fn continue_with(
        self,
        verification_result: Result<VerifiedIdentity<'static>, Error>,
        tls: &mut Vec<u8>,
    ) -> Result<Side::Handshake, Error> {
        let core = self.partial_continue_with(verification_result, tls)?;
        Side::tcp_handshake_from_core(core)
    }
}

impl<Side: SideData> VerifyPeerIdentity<Side, Quic> {
    /// Progress the handshake by calling the pre-configured certificate verification trait.
    pub fn with_config(self, output: &mut Vec<QuicEvent>) -> Result<Side::QuicHandshake, Error> {
        let result = self
            .verify_identity
            .verify_with_config();
        self.continue_with(result, output)
    }

    /// Progress the handshake by incorporating the result of an external verification.
    ///
    /// If `verification_result` is an error, this error is returned and the handshake terminates.
    ///
    /// Events are appended to `output`.
    pub fn continue_with(
        self,
        verification_result: Result<VerifiedIdentity<'static>, Error>,
        output: &mut Vec<QuicEvent>,
    ) -> Result<Side::QuicHandshake, Error> {
        let core = self.partial_continue_with(verification_result, &mut Vec::new())?;
        Side::quic_handshake_from_core(core, output)
    }
}

impl<Side: SideData, T: Transport> VerifyPeerIdentity<Side, T> {
    fn partial_continue_with(
        self,
        verification_result: Result<VerifiedIdentity<'static>, Error>,
        tls: &mut Vec<u8>,
    ) -> Result<ConnectionCommon<Side, T>, Error> {
        let Self {
            mut conn,
            verify_identity,
        } = self;

        let result = verification_result.and_then(|verified| {
            verify_identity.continue_with(
                verified,
                &mut SideCommonOutput {
                    side: &mut conn.side,
                    quic: T::quic(&mut conn.transport),
                    common: &mut conn.common,
                    tls,
                },
            )
        });

        if let Err(err) = &result {
            maybe_send_fatal_alert(&mut conn.common.send, err, tls)?;
        }

        conn.state = result;
        Ok(conn)
    }
}

impl<Side: SideData, T: Transport> fmt::Debug for VerifyPeerIdentity<Side, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyPeerIdentity")
            .finish_non_exhaustive()
    }
}

/// The aspects of a handshake that depend on the underlying transport.
#[expect(private_bounds)]
pub trait Transport: Sized + sealed::Transport {}

pub(crate) mod sealed {
    use super::QuicOutput;
    use crate::Protocol;

    pub(crate) trait Transport {
        fn protocol(&self) -> Protocol;

        /// The sink for QUIC-specific events.
        fn quic(&mut self) -> Option<&mut dyn QuicOutput>;
    }
}

/// TLS over TCP.
#[expect(clippy::exhaustive_structs)]
pub struct Tcp;

impl Transport for Tcp {}

impl sealed::Transport for Tcp {
    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }

    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        None
    }
}
