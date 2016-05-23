extern crate ring;
use self::ring::digest;

use msgs::message::{Message, MessagePayload};

pub struct HandshakeHash {
  ctx: digest::Context
}

impl HandshakeHash {
  pub fn new(alg: &'static digest::Algorithm) -> HandshakeHash {
    HandshakeHash { ctx: digest::Context::new(alg) }
  }

  pub fn update(&mut self, m: &Message) -> &mut HandshakeHash {
    match m.payload {
      MessagePayload::Handshake(_) => {
        let mut buf = Vec::new();
        m.payload.encode(&mut buf);
        self.update_raw(&buf);
      },
      _ => unreachable!()
    };
    self
  }

  pub fn update_raw(&mut self, buf: &[u8]) -> &mut HandshakeHash {
    self.ctx.update(buf);
    self
  }

  pub fn get_current_hash(&self) -> Vec<u8> {
    let h = self.ctx.clone().finish();
    let mut ret = Vec::new();
    ret.extend_from_slice(h.as_ref());
    ret.truncate(12);
    ret
  }
}
