//! Tracks unacked inbound DTLS 1.3 messages.

use alloc::vec::Vec;
use core::mem;

use std::collections::HashMap;
use std::collections::HashSet;

use crate::common_state::Side;
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::msgs::HandshakeSequenceNumber;
use crate::{AckRecordSequenceNumber, Epoch, FullRecordSequenceNumber};

/// Records received from the peer that are pending an ACK.
pub(crate) struct UnackedRecords {
    /// Which side of the connection we are.
    side: Side,
    /// Unacked record numbers from the flight currently being received.
    ///
    /// Records could come from multiple epochs, and the ACK that eventually is transmitted could be
    /// in yet another epoch!
    unacked: HashMap<HandshakeSequenceNumber, HashSet<AckRecordSequenceNumber>>,
    /// Handshake sequence numbers of the flight currently being received.
    // TODO(DTLS): flights are never very big, so this could probably be a smallish array to avoid
    // allocating.
    current_handshake_flight: Vec<HandshakeSequenceNumber>,
}

impl UnackedRecords {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            side,
            unacked: HashMap::new(),
            current_handshake_flight: Vec::new(),
        }
    }

    /// Note the reception of a record and one or more handshake fragments in it.
    ///
    /// Only records containing handshake message fragments should be observed. Others are not ACKed
    /// so we don't want to grow the unacked record list unnecessarily.
    pub(crate) fn observe_record_seq(
        &mut self,
        epoch: Epoch,
        record_seq: FullRecordSequenceNumber,
        handshake_seqs: Vec<HandshakeSequenceNumber>,
    ) {
        for handshake_seq in handshake_seqs {
            self.unacked
                .entry(handshake_seq)
                .or_insert(HashSet::new())
                .insert(AckRecordSequenceNumber {
                    epoch,
                    seq: record_seq,
                });
        }
    }

    /// Note the successful processing of a handshake message.
    pub(crate) fn observe_handshake_seq(
        &mut self,
        version: ProtocolVersion,
        accepted_message: Option<(HandshakeSequenceNumber, HandshakeType)>,
    ) -> Option<Vec<AckRecordSequenceNumber>> {
        // Acks are DTLS 1.3 only.
        if version != ProtocolVersion::DTLSv1_3 {
            return None;
        }

        // Only handshake messages are ACKed.
        let Some((seq, typ)) = accepted_message else {
            return None;
        };

        // Empty the unacked list when a new flight is received:
        //
        // "ACKs only cover the current outstanding flight ... In particular, receiving a message
        // from a handshake flight implicitly acknowledges all messages from the previous
        // flight(s)."
        if typ.first_in_flight(self.side) {
            self.current_handshake_flight = Vec::new();
        }

        self.current_handshake_flight.push(seq);

        // For now we only send ACKs in teh conditions that are MUSTs per the specification. Namely:
        if !matches!(
            (self.side, typ),
            // - Server receives "the client's final flight of the main handshake", which ends with
            //   Finished
            (Side::Server, HandshakeType::Finished)
            // - Either side receives a KeyUpdate
            | (_, HandshakeType::KeyUpdate)
        ) {
            return None;
        }

        // We are going to ack the flight we have been receiving, consisting of handshake seqs in
        // self.current_handshake_flight. Look up the record numbers containing fragments thereof so
        // we can construct the ACK.
        let mut to_ack = HashSet::new();
        for handshake_seq in mem::take(&mut self.current_handshake_flight) {
            if let Some(value) = self.unacked.remove(&handshake_seq) {
                to_ack.extend(value);
            }
        }

        let mut to_ack: Vec<_> = to_ack.into_iter().collect();
        to_ack.sort();
        Some(to_ack)
    }
}
