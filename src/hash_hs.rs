extern crate ring;
use self::ring::digest;

use std::mem;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};

/// This deals with keeping a running hash of the handshake
/// payloads.  This is computed by buffering initially.  Once
/// we know what hash function we need to use we switch to
/// incremental hashing.
///
/// For client auth, we also need to buffer all the messages.
/// This is disable in cases where client auth is not possible.
pub struct HandshakeHash {
  /// None before we know what hash function we're using
  ctx: Option<digest::Context>,

  /// true if we need to keep all messages
  client_auth_enabled: bool,

  /// buffer for pre-hashing stage and client-auth.
  buffer: Vec<u8>
}

impl HandshakeHash {
  pub fn new() -> HandshakeHash {
    HandshakeHash {
      ctx: None,
      client_auth_enabled: false,
      buffer: Vec::new()
    }
  }

  /// We might be doing client auth, so need to keep a full
  /// log of the handshake.
  pub fn set_client_auth_enabled(&mut self) {
    assert!(self.ctx.is_none()); // or we might have already discarded messages
    self.client_auth_enabled = true;
  }

  /// We now know what hash function the verify_data will use.
  pub fn start_hash(&mut self, alg: &'static digest::Algorithm) {
    assert!(self.ctx.is_none());

    let mut ctx = digest::Context::new(alg);
    ctx.update(&self.buffer);
    self.ctx = Some(ctx);

    /* Discard buffer if we don't need it now. */
    if !self.client_auth_enabled {
      self.buffer.drain(..);
    }
  }

  /// Hash/buffer a handshake message.
  pub fn add_message(&mut self, m: &Message) -> &mut HandshakeHash {
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

  /// Hash or buffer a byte slice.
  fn update_raw(&mut self, buf: &[u8]) -> &mut Self {
    if self.ctx.is_some() {
      self.ctx.as_mut().unwrap().update(buf);
    }

    if self.ctx.is_none() || self.client_auth_enabled {
      self.buffer.extend_from_slice(buf);
    }

    self
  }

  /// Get the current hash value.
  pub fn get_current_hash(&self) -> Vec<u8> {
    let h = self.ctx.as_ref().unwrap().clone().finish();
    let mut ret = Vec::new();
    ret.extend_from_slice(h.as_ref());
    ret
  }

  /// Takes this object's buffer containing all handshake messages
  /// so far.  This method only works once; it resets the buffer
  /// to empty.
  pub fn take_handshake_buf(&mut self) -> Vec<u8> {
    assert!(self.client_auth_enabled);
    mem::replace(&mut self.buffer, Vec::new())
  }
}
