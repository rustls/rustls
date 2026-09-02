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

use super::{ConnectionCommon, MessageIter, MessageIterMode, SideData};
use crate::TlsInputBuffer;
use crate::common_state::maybe_send_fatal_alert;
use crate::error::Error;
use crate::msgs::ServerExtensionsInput;
use crate::quic::QuicOutput;
use crate::server::{ChooseConfig, ClientHello, ServerConfig, ServerSide};
use crate::sync::Arc;

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
            match iter.next() {
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

pub(crate) struct AcceptedCore<T: Transport> {
    // invariant: `core.inner.state` is `Err(_)` and requires restoring
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

        let result = inner.accepted(choose_config, exts, T::quic(&mut transport), config, tls);

        let send_path = &mut inner.common.send;

        if let Err(err) = &result {
            maybe_send_fatal_alert(send_path, err, tls);
        }

        result?;
        Ok(Core { inner, transport })
    }
}

/// The aspects of a handshake that depend on the underlying transport.
pub(crate) trait Transport: Sized {
    /// The sink for handshake messages and key changes, if this transport has one.
    ///
    /// `None` means the handshake is encoded as TLS records into the caller's buffer.
    fn quic(&mut self) -> Option<&mut dyn QuicOutput>;
}

pub(crate) struct Tcp;

impl Transport for Tcp {
    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        None
    }
}
