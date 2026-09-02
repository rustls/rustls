//! Transport-generic handshake machinery.
//!
//! The public handshake types (`rustls::{NeedsInput, VerifyPeerIdentity, Accepted,
//! ClientHandshake, ServerHandshake}` and their `rustls::quic` counterparts) are thin
//! shims over the types in this module.
//!
//! The shims own the public signatures and documentation; the shared underlying logic lives
//! here, parameterised by [`Transport`].

use alloc::vec::Vec;

use super::{ConnectionCommon, MessageIter, MessageIterMode, ReceivePath, SideData};
use crate::TlsInputBuffer;
use crate::error::Error;
use crate::quic::QuicOutput;

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
