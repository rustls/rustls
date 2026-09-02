//! Transport-generic handshake machinery.
//!
//! The public handshake types (`rustls::{NeedsInput, VerifyPeerIdentity, Accepted,
//! ClientHandshake, ServerHandshake}` and their `rustls::quic` counterparts) are thin
//! shims over the types in this module.
//!
//! The shims own the public signatures and documentation; the shared underlying logic lives
//! here, parameterised by [`Transport`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{
    ConnectionCommon, MessageIter, MessageIterMode, ReceivePath, SideCommonOutput, SideData,
    VerifyPeerIdentityInternal,
};
use crate::TlsInputBuffer;
use crate::common_state::{Output, maybe_send_fatal_alert};
use crate::crypto::VerifiedIdentity;
use crate::error::Error;
use crate::msgs::ServerExtensionsInput;
use crate::quic::QuicOutput;
use crate::server::{ChooseConfig, ClientHello, ServerConfig, ServerSide};
use crate::sync::Arc;

pub(crate) struct NeedsInputCore<Side: SideData, T: Transport>(pub(crate) Core<Side, T>);

impl<Side: SideData, T: Transport> NeedsInputCore<Side, T> {
    pub(crate) fn new(core: Core<Side, T>) -> Self {
        Self(core)
    }

    pub(crate) fn process(
        self,
        input: &mut dyn TlsInputBuffer,
        tls: &mut Vec<u8>,
    ) -> Result<Core<Side, T>, Error> {
        let Core {
            mut inner,
            mut transport,
        } = self.0;

        let result = {
            let mut iter = MessageIter::new(
                input,
                tls,
                T::quic(&mut transport),
                &mut inner,
                MessageIterMode::Handshake,
            );

            loop {
                match iter.next() {
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(e),
                    None => break Ok(()),
                }
            }
        };

        input.discard(
            inner
                .common
                .recv
                .deframer
                .take_discard(),
        );

        result?;
        Ok(Core { inner, transport })
    }

    pub(crate) fn receive(&mut self) -> &mut ReceivePath {
        &mut self.0.inner.common.recv
    }
}

pub(crate) struct AcceptedCore<T: Transport> {
    pub(crate) core: Core<ServerSide, T>,
    choose_config: Box<ChooseConfig>,
}

impl<T: Transport> AcceptedCore<T> {
    pub(crate) fn new(core: Core<ServerSide, T>, choose_config: Box<ChooseConfig>) -> Self {
        Self {
            core,
            choose_config,
        }
    }

    pub(crate) fn client_hello(&self) -> ClientHello<'_> {
        self.choose_config.client_hello()
    }

    pub(crate) fn choose_config(
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

        let result = {
            let result = inner.accepted(choose_config, exts, T::quic(&mut transport), config, tls);

            if let Err(err) = &result {
                maybe_send_fatal_alert(&mut inner.common.send, err, tls);
            }

            result
        };

        result?;
        Ok(Core { inner, transport })
    }
}

pub(crate) struct VerifyCore<Side: SideData, T: Transport> {
    core: Core<Side, T>,
    verify_identity: Box<dyn VerifyPeerIdentityInternal<Side>>,
}

impl<Side: SideData, T: Transport> VerifyCore<Side, T> {
    pub(crate) fn new(
        core: Core<Side, T>,
        verify_identity: Box<dyn VerifyPeerIdentityInternal<Side>>,
    ) -> Self {
        Self {
            core,
            verify_identity,
        }
    }

    pub(crate) fn with_config(self, tls: &mut Vec<u8>) -> Result<Core<Side, T>, Error> {
        let Self {
            core,
            verify_identity,
        } = self;

        Self::advance(core, tls, |output| verify_identity.with_config(output))
    }

    pub(crate) fn continue_with(
        self,
        verification_result: Result<VerifiedIdentity<'static>, Error>,
        tls: &mut Vec<u8>,
    ) -> Result<Core<Side, T>, Error> {
        let Self {
            core,
            verify_identity,
        } = self;

        Self::advance(core, tls, |output| {
            verification_result.and_then(|verified| verify_identity.continue_with(verified, output))
        })
    }

    pub(crate) fn presented_identity(&self) -> Result<Side::PeerIdentity<'_>, Error> {
        self.verify_identity
            .presented_identity()
    }

    fn advance(
        core: Core<Side, T>,
        tls: &mut Vec<u8>,
        advance: impl FnOnce(&mut dyn Output<'_>) -> Result<Side::State, Error>,
    ) -> Result<Core<Side, T>, Error> {
        let Core {
            mut inner,
            mut transport,
        } = core;

        {
            let result = advance(&mut SideCommonOutput {
                side: &mut inner.side,
                quic: T::quic(&mut transport),
                common: &mut inner.common,
                tls,
            });

            if let Err(err) = &result {
                maybe_send_fatal_alert(&mut inner.common.send, err, tls);
            }

            inner.state = result;
        }

        Ok(Core { inner, transport })
    }
}

pub(crate) struct Core<Side: SideData, T: Transport> {
    pub(crate) inner: ConnectionCommon<Side>,
    pub(crate) transport: T::State,
}

impl<Side: SideData, T: Transport> Core<Side, T> {
    pub(crate) fn new(inner: ConnectionCommon<Side>, transport: T::State) -> Self {
        Self { inner, transport }
    }
}

/// The aspects of a handshake that depend on the underlying transport.
pub(crate) trait Transport: Sized {
    /// Transport state that persists across handshake steps.
    type State;

    /// The sink for handshake messages and key changes, if this transport has one.
    ///
    /// `None` means the handshake is encoded as TLS records into the caller's buffer.
    fn quic(state: &mut Self::State) -> Option<&mut dyn QuicOutput>;
}

pub(crate) struct Tcp;

impl Transport for Tcp {
    type State = ();

    fn quic(_state: &mut Self::State) -> Option<&mut dyn QuicOutput> {
        None
    }
}
