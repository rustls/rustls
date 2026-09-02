//! Transport-generic handshake machinery.
//!
//! [`Accepted`] is public and generic over [`Transport`].
//!
//! The remaining public handshake types (`rustls::{NeedsInput, VerifyPeerIdentity,
//! ClientHandshake, ServerHandshake}` and their `rustls::quic` counterparts) are thin shims
//! over the types in this module.  The shims own the public signatures and documentation; the
//! shared underlying logic lives here, parameterised by [`Transport`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::{ConnectionCommon, MessageIter, MessageIterMode, NeedsInput, SideData};
use crate::TlsInputBuffer;
use crate::common_state::maybe_send_fatal_alert;
use crate::crypto::cipher::Payload;
use crate::error::Error;
use crate::msgs::{ServerExtensionsInput, TransportParameters};
use crate::quic::{self, Quic, QuicCommon, QuicEvent, QuicOutput};
use crate::server::{ChooseConfig, ClientHello, ServerConfig, ServerHandshake, ServerSide};
use crate::sync::Arc;
use crate::tracing::trace;

pub(crate) struct Core<Side: SideData, T: Transport> {
    pub(crate) inner: ConnectionCommon<Side>,
    pub(crate) transport: T,
}

impl<Side: SideData, T: Transport> Core<Side, T> {
    pub(crate) fn new(inner: ConnectionCommon<Side>, transport: T) -> Self {
        Self { inner, transport }
    }

    pub(crate) fn process(
        self,
        input: &mut dyn TlsInputBuffer,
        tls: &mut Vec<u8>,
    ) -> Result<Self, Error> {
        let Self {
            mut inner,
            mut transport,
        } = self;

        let mut iter = MessageIter::new(
            input,
            tls,
            transport.quic(),
            &mut inner,
            MessageIterMode::Handshake,
        );
        let result = loop {
            match iter.next(false) {
                Some(Ok(_)) => {}
                Some(Err(e)) => break Err(e),
                None => break Ok(()),
            };
        };

        input.discard(
            inner
                .common
                .recv
                .deframer
                .take_discard(),
        );

        result?;
        Ok(Self { inner, transport })
    }
}

/// Represents that a `ClientHello` message has been received.
///
/// The handshake can be progressed by choosing a [`ServerConfig`] based on
/// [`Self::client_hello()`] and providing it to [`Self::choose_config()`].
pub struct Accepted<T: Transport> {
    // invariant: `core.inner.state` is `Err(_)` and requires restoring
    core: Core<ServerSide, T>,
    choose_config: Box<ChooseConfig>,
}

impl<T: Transport> Accepted<T> {
    pub(crate) fn new(core: Core<ServerSide, T>, choose_config: Box<ChooseConfig>) -> Self {
        Self {
            core,
            choose_config,
        }
    }

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
    ) -> Result<Core<ServerSide, T>, Error> {
        let Self {
            core: Core {
                mut inner,
                mut transport,
            },
            choose_config,
        } = self;

        let result = inner.accepted(choose_config, exts, T::quic(&mut transport), config, tls);

        let send_path = &mut inner.common.send;

        if let Err(err) = &result {
            maybe_send_fatal_alert(send_path, err, tls);
        }

        result?;
        Ok(Core { inner, transport })
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
        Ok(ServerHandshake::NeedsInput(NeedsInput::new(core.inner)))
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
            transport_parameters: Some(match self.core.transport.version {
                quic::Version::V1 | quic::Version::V2 => {
                    TransportParameters::Quic(Payload::new(params))
                }
            }),
        };

        let mut tls = Vec::new();
        let Core {
            inner,
            mut transport,
        } = self.partial_choose_config(config, exts, &mut tls)?;

        // In QUIC mode, handshake output is emitted via `QuicEvent`s, not `tls`.
        debug_assert!(tls.is_empty());
        output.extend(transport.events());
        quic::ServerHandshake::try_from(QuicCommon::new(inner, transport))
    }
}

impl<T: Transport> fmt::Debug for Accepted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .finish_non_exhaustive()
    }
}

/// The aspects of a handshake that depend on the underlying transport.
#[expect(private_bounds)]
pub trait Transport: Sized + sealed::Transport {}

pub(crate) mod sealed {
    pub(crate) trait Transport {
        /// The sink for QUIC-specific events.
        fn quic(&mut self) -> Option<&mut dyn super::QuicOutput>;
    }
}

/// TLS over TCP.
#[expect(clippy::exhaustive_structs)]
pub struct Tcp;

impl Transport for Tcp {}

impl sealed::Transport for Tcp {
    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        None
    }
}
