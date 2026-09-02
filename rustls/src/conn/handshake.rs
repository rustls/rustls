//! Transport-generic handshake machinery.
//!
//! The public handshake types (`rustls::{NeedsInput, VerifyPeerIdentity, Accepted,
//! ClientHandshake, ServerHandshake}` and their `rustls::quic` counterparts) are thin
//! shims over the types in this module.
//!
//! The shims own the public signatures and documentation; the shared underlying logic lives
//! here, parameterised by [`Transport`].

use alloc::vec::Vec;

use super::{ConnectionCommon, MessageIter, MessageIterMode, SideData};
use crate::TlsInputBuffer;
use crate::error::Error;
use crate::quic::QuicOutput;

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

/// The aspects of a handshake that depend on the underlying transport.
pub(crate) trait Transport: Sized {
    /// The sink for QUIC-specific events.
    fn quic(&mut self) -> Option<&mut dyn QuicOutput>;
}

pub(crate) struct Tcp;

impl Transport for Tcp {
    fn quic(&mut self) -> Option<&mut dyn QuicOutput> {
        None
    }
}
