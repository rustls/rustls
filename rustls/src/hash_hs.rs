use crate::crypto::hash;
use crate::msgs::codec::Codec;
use crate::msgs::enums::HashAlgorithm;
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{Message, MessagePayload};

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;

/// Early stage buffering of handshake payloads.
///
/// Before we know the hash algorithm to use to verify the handshake, we just buffer the messages.
/// During the handshake, we may restart the transcript due to a HelloRetryRequest, reverting
/// from the `HandshakeHash` to a `HandshakeHashBuffer` again.
pub(crate) struct HandshakeHashBuffer {
    buffer: Vec<u8>,
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
    pub(crate) fn add_message(&mut self, m: &Message) {
        if let MessagePayload::Handshake { encoded, .. } = &m.payload {
            self.buffer
                .extend_from_slice(&encoded.0);
        }
    }

    /// Hash or buffer a byte slice.
    #[cfg(all(test, any(feature = "ring", feature = "aws_lc_rs")))]
    fn update_raw(&mut self, buf: &[u8]) {
        self.buffer.extend_from_slice(buf);
    }

    /// Get the hash value if we were to hash `extra` too.
    pub(crate) fn get_hash_given(
        &self,
        provider: &'static dyn hash::Hash,
        extra: &[u8],
    ) -> hash::Output {
        let mut ctx = provider.start();
        ctx.update(&self.buffer);
        ctx.update(extra);
        ctx.finish()
    }

    /// We now know what hash function the verify_data will use.
    pub(crate) fn start_hash(self, provider: &'static dyn hash::Hash) -> HandshakeHash {
        let mut ctx = provider.start();
        ctx.update(&self.buffer);
        HandshakeHash {
            provider,
            ctx,
            client_auth: match self.client_auth_enabled {
                true => Some(self.buffer),
                false => None,
            },
        }
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
}

impl HandshakeHash {
    /// We decided not to do client auth after all, so discard
    /// the transcript.
    pub(crate) fn abandon_client_auth(&mut self) {
        self.client_auth = None;
    }

    /// Hash/buffer a handshake message.
    pub(crate) fn add_message(&mut self, m: &Message) -> &mut Self {
        if let MessagePayload::Handshake { encoded, .. } = &m.payload {
            self.update_raw(&encoded.0);
        }
        self
    }

    /// Hash or buffer a byte slice.
    fn update_raw(&mut self, buf: &[u8]) -> &mut Self {
        self.ctx.update(buf);

        if let Some(buffer) = &mut self.client_auth {
            buffer.extend_from_slice(buf);
        }

        self
    }

    /// Get the hash value if we were to hash `extra` too,
    /// using hash function `hash`.
    pub(crate) fn get_hash_given(&self, extra: &[u8]) -> hash::Output {
        let mut ctx = self.ctx.fork();
        ctx.update(extra);
        ctx.finish()
    }

    pub(crate) fn into_hrr_buffer(self) -> HandshakeHashBuffer {
        let old_hash = self.ctx.finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());

        HandshakeHashBuffer {
            client_auth_enabled: self.client_auth.is_some(),
            buffer: old_handshake_hash_msg.get_encoding(),
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

        self.update_raw(&old_handshake_hash_msg.get_encoding());
    }

    /// Get the current hash value.
    pub(crate) fn get_current_hash(&self) -> hash::Output {
        self.ctx.fork_finish()
    }

    /// Takes this object's buffer containing all handshake messages
    /// so far.  This method only works once; it resets the buffer
    /// to empty.
    #[cfg(feature = "tls12")]
    pub(crate) fn take_handshake_buf(&mut self) -> Option<Vec<u8>> {
        self.client_auth.take()
    }

    /// The hashing algorithm
    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        self.provider.algorithm()
    }
}

#[cfg(all(test, any(feature = "ring", feature = "aws_lc_rs")))]
mod tests {
    use super::HandshakeHashBuffer;
    use crate::test_provider::hash::SHA256;

    #[test]
    fn hashes_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.update_raw(b"hello");
        assert_eq!(hhb.buffer.len(), 5);
        let mut hh = hhb.start_hash(&SHA256);
        assert!(hh.client_auth.is_none());
        hh.update_raw(b"world");
        let h = hh.get_current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn buffers_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.update_raw(b"hello");
        assert_eq!(hhb.buffer.len(), 5);
        let mut hh = hhb.start_hash(&SHA256);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );
        hh.update_raw(b"world");
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(10)
        );
        let h = hh.get_current_hash();
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
        hhb.update_raw(b"hello");
        assert_eq!(hhb.buffer.len(), 5);
        let mut hh = hhb.start_hash(&SHA256);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );
        hh.abandon_client_auth();
        assert_eq!(hh.client_auth, None);
        hh.update_raw(b"world");
        assert_eq!(hh.client_auth, None);
        let h = hh.get_current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }
}
