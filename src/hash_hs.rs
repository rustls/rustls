extern crate ring;
use self::ring::digest;

use std::mem;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};

/// This deals with keeping a running hash of the handshake
/// payloads.  This is computed incrementally, because we
/// know the hash function to use very early on.
///
/// For client auth, we also need to buffer all the messages.
/// This is compiled out to reduce memory usage.
pub struct HandshakeHash {
  ctx: digest::Context,
  buffer: Vec<u8>
}

impl HandshakeHash {
  /* TODO: compile out buffer */
  pub fn new(alg: &'static digest::Algorithm) -> HandshakeHash {
    HandshakeHash { ctx: digest::Context::new(alg), buffer: Vec::new() }
  }

  pub fn update(&mut self, m: &Message) -> &mut HandshakeHash {
    match m.payload {
      MessagePayload::Handshake(ref hs) => {
        let mut buf = Vec::new();
        hs.encode(&mut buf);
        self.update_raw(&buf);
      },
      _ => unreachable!()
    };
    self
  }

  pub fn update_raw(&mut self, buf: &[u8]) -> &mut Self {
    self.ctx.update(buf);
    self.buffer.extend_from_slice(buf);

    self
  }

  pub fn get_current_hash(&self) -> Vec<u8> {
    let h = self.ctx.clone().finish();
    let mut ret = Vec::new();
    ret.extend_from_slice(h.as_ref());
    ret
  }

  /// Takes this object's buffer containing all handshake messages
  /// so far.  This method only works once; it resets the buffer
  /// to empty.
  pub fn take_handshake_buf(&mut self) -> Vec<u8> {
    mem::replace(&mut self.buffer, Vec::new())
  }
}
