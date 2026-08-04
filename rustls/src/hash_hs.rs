use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;

use crate::crypto::{HashAlgorithm, hash};
use crate::enums::ProtocolVersion;
use crate::msgs::{
    Codec, HandshakeAlignedProof, HandshakeMessagePayload, HandshakeSequenceNumber, Message,
    MessagePayload,
};

/// Early stage buffering of handshake payloads.
///
/// Before we know the hash algorithm to use to verify the handshake or the negotiated protocol
/// version, we just buffer the messages.
///
/// During the handshake, we may restart the transcript due to a HelloRetryRequest, reverting
/// from the `HandshakeHash` to a `HandshakeHashBuffer` again.
#[derive(Clone)]
pub(crate) struct HandshakeHashBuffer {
    buffer: Vec<(Vec<u8>, HandshakeSequenceNumber)>,
    client_auth_enabled: bool,
}

impl HandshakeHashBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            client_auth_enabled: false,
        }
    }

    /// We might be doing client auth, so need to keep a full
    /// log of the handshake.
    pub(crate) fn set_client_auth_enabled(&mut self) {
        self.client_auth_enabled = true;
    }

    /// Hash/buffer a handshake message.
    pub(crate) fn add_message(&mut self, m: &Message<'_>) {
        match &m.payload {
            MessagePayload::Handshake { encoded, seq, .. } => self.add(encoded.bytes(), *seq),
            MessagePayload::HandshakeFlight(_) => panic!("should never add flight to HHB"),
            _ => {}
        }
    }

    /// Hash or buffer a byte slice.
    pub(crate) fn add(&mut self, bytes: &[u8], seq: HandshakeSequenceNumber) {
        self.buffer.push((bytes.to_vec(), seq));
    }

    /// Get the hash value if we were to hash `extra` too.
    pub(crate) fn hash_given(
        &self,
        provider: &'static dyn hash::Hash,
        version: ProtocolVersion,
        extra: &[u8],
    ) -> hash::Output {
        self.clone()
            .start_hash(provider, version)
            .hash_given(extra)
    }

    /// We now know what hash function the verify_data will use.
    pub(crate) fn start_hash(
        self,
        provider: &'static dyn hash::Hash,
        version: ProtocolVersion,
    ) -> HandshakeHash {
        let mut hh = HandshakeHash {
            provider,
            ctx: provider.start(),
            client_auth: match self.client_auth_enabled {
                true => Some(Vec::new()),
                false => None,
            },
            version,
        };

        for (buffer, seq) in &self.buffer {
            hh.add(buffer, *seq);
        }

        hh
    }
}

/// This deals with keeping a running hash of the handshake
/// payloads.  This is computed by buffering initially.  Once
/// we know what hash function we need to use we switch to
/// incremental hashing.
///
/// For client auth, we also need to buffer all the messages.
/// This is disabled in cases where client auth is not possible.
pub(crate) struct HandshakeHash {
    provider: &'static dyn hash::Hash,
    ctx: Box<dyn hash::Context>,

    /// buffer for client-auth.
    client_auth: Option<Vec<u8>>,

    version: ProtocolVersion,
}

impl HandshakeHash {
    /// We decided not to do client auth after all, so discard
    /// the transcript.
    pub(crate) fn abandon_client_auth(&mut self) {
        self.client_auth = None;
    }

    /// Hash a handshake message.
    pub(crate) fn add_message(&mut self, m: &Message<'_>) {
        for (message, seq) in match &m.payload {
            MessagePayload::Handshake { encoded, seq, .. } => {
                Box::new(core::iter::once((encoded.bytes(), *seq)))
                    as Box<dyn Iterator<Item = (&[u8], HandshakeSequenceNumber)>>
            }
            MessagePayload::HandshakeFlight(messages) => Box::new(
                messages
                    .iter()
                    .map(|(_, seq, bytes)| (bytes.as_slice(), *seq)),
            )
                as Box<dyn Iterator<Item = (&[u8], HandshakeSequenceNumber)>>,
            // Not a handshake message, do nothing
            _ => return,
        } {
            self.add(message, seq);
        }
    }

    /// Hash a byte slice, interpreted as an encoded handshake message.
    pub(crate) fn add(&mut self, bytes: &[u8], seq: HandshakeSequenceNumber) {
        if self.version == ProtocolVersion::DTLSv1_2 {
            // The DTLS 1.2 handshake transcript differs from other protocol versions:
            //
            // > Hash calculations include entire handshake messages, including DTLS-specific
            // > fields: message_seq, fragment_offset, and fragment_length. However, in order to
            // > remove sensitivity to handshake message fragmentation, the Finished MAC MUST be
            // > computed as if each handshake message had been sent as a single fragment.
            //
            // <https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.6>
            //
            // We synthesize handshake fragment fields representing the reassembled message and
            // insert them in the transcript where they'd go in a DTLS 1.2 handshake message.
            //
            // <https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2>
            //
            // Hash msg_type and length...
            self.add_raw(&bytes[..1 + 3]);
            // ...message_seq...
            self.add_raw(seq.to_wire_bytes().as_slice());
            // ...fragment_offset (U24(0), because we reassembled into a single fragment)...
            self.add_raw(&[0, 0, 0]);
            // ...fragment_length (equal to length, read from handshake header)...
            self.add_raw(&bytes[1..4]);
            // ...and the rest of the message, the encoded handshake.
            self.add_raw(&bytes[4..]);
        } else {
            // For other protocol versions, we hash the handshake payload without additional
            // ceremony.
            self.add_raw(bytes);
        }
    }
    /// Hash or buffer a byte slice.
    fn add_raw(&mut self, buf: &[u8]) -> &mut Self {
        self.ctx.update(buf);

        if let Some(curr_buffer) = &mut self.client_auth {
            curr_buffer.extend_from_slice(buf);
        }

        self
    }

    /// Get the hash value if we were to hash `extra` too.
    pub(crate) fn hash_given(&self, extra: &[u8]) -> hash::Output {
        let mut ctx = self.ctx.fork();
        ctx.update(extra);
        ctx.finish()
    }

    pub(crate) fn into_hrr_buffer(self, _proof: &HandshakeAlignedProof) -> HandshakeHashBuffer {
        let old_hash = self.ctx.finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());

        HandshakeHashBuffer {
            buffer: Vec::from([(old_handshake_hash_msg.get_encoding(), 0.into())]),
            client_auth_enabled: self.client_auth.is_some(),
        }
    }

    /// Take the current hash value, and encapsulate it in a
    /// 'handshake_hash' handshake message.  Start this hash
    /// again, with that message at the front.
    pub(crate) fn rollup_for_hrr(&mut self) {
        let ctx = &mut self.ctx;

        let old_ctx = mem::replace(ctx, self.provider.start());
        let old_hash = old_ctx.finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());

        self.add_raw(&old_handshake_hash_msg.get_encoding());
    }

    /// Get the current hash value.
    pub(crate) fn current_hash(&self) -> hash::Output {
        self.ctx.fork_finish()
    }

    /// Takes this object's buffer containing all handshake messages
    /// so far.  This method only works once; it resets the buffer
    /// to empty.
    pub(crate) fn take_handshake_buf(&mut self) -> Option<Vec<u8>> {
        self.client_auth.take()
    }

    /// The hashing algorithm
    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        self.provider.algorithm()
    }

    /// The protocol version in use.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.version
    }
}

impl Clone for HandshakeHash {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            ctx: self.ctx.fork(),
            client_auth: self.client_auth.clone(),
            version: self.version,
        }
    }
}

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod tests {
    use super::*;
    use crate::crypto::test_provider::SHA256;

    #[test]
    fn hashes_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(b"hello", 0.into());
        assert_eq!(hhb.buffer.len(), 1);
        assert_eq!(hhb.buffer[0].0.len(), 5);
        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert!(hh.client_auth.is_none());
        hh.add_raw(b"world");
        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }

    #[test]
    fn buffers_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello", 0.into());
        assert_eq!(hhb.buffer.len(), 1);
        assert_eq!(hhb.buffer[0].0.len(), 5);

        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );

        hh.add_raw(b"world");
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(10)
        );

        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
        let buf = hh.take_handshake_buf();
        assert_eq!(Some(b"helloworld".to_vec()), buf);
    }

    #[test]
    fn abandon() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello", 0.into());
        assert_eq!(hhb.buffer.len(), 1);
        assert_eq!(hhb.buffer[0].0.len(), 5);

        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );

        hh.abandon_client_auth();
        assert_eq!(hh.client_auth, None);
        hh.add_raw(b"world");
        assert_eq!(hh.client_auth, None);

        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }

    #[test]
    fn clones_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello", 0.into());
        assert_eq!(hhb.buffer.len(), 1);
        assert_eq!(hhb.buffer[0].0.len(), 5);

        // Cloning the HHB should result in the same buffer and client auth state.
        let mut hhb_prime = hhb.clone();
        assert_eq!(hhb_prime.buffer, hhb.buffer);
        assert!(hhb_prime.client_auth_enabled);

        // Updating the HHB clone shouldn't affect the original.
        hhb_prime.add(b"world", 0.into());
        assert_eq!(hhb_prime.buffer.len(), 2);
        assert_eq!(hhb_prime.buffer[1].0.len(), 5);
        assert_ne!(hhb.buffer, hhb_prime.buffer);

        let hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        let hh_hash = hh.current_hash();
        let hh_hash = hh_hash.as_ref();

        // Cloning the HH should result in the same current hash.
        let mut hh_prime = hh.clone();
        let hh_prime_hash = hh_prime.current_hash();
        let hh_prime_hash = hh_prime_hash.as_ref();
        assert_eq!(hh_hash, hh_prime_hash);

        // Updating the HH clone shouldn't affect the original.
        hh_prime.add_raw(b"goodbye");
        assert_eq!(hh.current_hash().as_ref(), hh_hash);
        assert_ne!(hh_prime.current_hash().as_ref(), hh_hash);
    }

    #[test]
    fn dtls_versions() {
        let first_message = [1, 0, 0, 10, 1, 1, 1, 1, 1, 1];
        let second_message = [2, 0, 0, 20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];

        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(&first_message, 4.into());

        let mut hh_tls_12 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_2);
        let mut hh_tls_13 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_3);
        let mut hh_dtls_12 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::DTLSv1_2);
        let mut hh_dtls_13 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::DTLSv1_3);

        for hh in [
            &mut hh_tls_12,
            &mut hh_tls_13,
            &mut hh_dtls_12,
            &mut hh_dtls_13,
        ] {
            hh.add(&second_message, 5.into());
        }

        // Transcript hashes for TLS 1.2, TLS 1.3, DTLS 1.3 should all be the same
        assert_eq!(
            hh_tls_12.current_hash().as_ref(),
            hh_tls_13.current_hash().as_ref()
        );
        assert_eq!(
            hh_tls_12.current_hash().as_ref(),
            hh_dtls_13.current_hash().as_ref()
        );
        // Transcript hash for DTLS 1.2 should differ because it includes handshake fragment fields
        assert_ne!(
            hh_tls_12.current_hash().as_ref(),
            hh_dtls_12.current_hash().as_ref()
        );

        // Hashing as DTLS 1.2 should be equivalent to hashing bytes [0..4] + handshake fragment
        // fields + [4..] as any other version
        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(&first_message[..4], 0.into());
        // fragment fields: seq (2) + fragment offset (3) + len (3)
        hhb.add(&[0, 4, 0, 0, 0, 0, 0, 10], 0.into());
        hhb.add(&first_message[4..], 0.into());
        let mut hh = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_2);
        hh.add(&second_message[..4], 0.into());
        // fragment fields: seq (2) + fragment offset (3) + len (3)
        hh.add(&[0, 5, 0, 0, 0, 0, 0, 20], 0.into());
        hh.add(&second_message[4..], 0.into());
        assert_eq!(
            hh_dtls_12.current_hash().as_ref(),
            hh.current_hash().as_ref()
        );
    }
}
