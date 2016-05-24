extern crate ring;
use prf;
use std::io::Write;

pub struct SessionSecrets {
  pub client_random: [u8; 32],
  pub server_random: [u8; 32],
  master_secret: [u8; 48]
}

impl SessionSecrets {
  pub fn for_server() -> SessionSecrets {
    SessionSecrets {
      client_random: [0u8; 32],
      server_random: [0u8; 32],
      master_secret: [0u8; 48]
    }
  }

  pub fn for_client() -> SessionSecrets {
    SessionSecrets::for_server()
  }

  fn join_randoms(&self) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms.as_mut().write(&self.client_random);
    randoms[32..].as_mut().write(&self.server_random);
    randoms
  }

  pub fn init(&mut self,
              hashalg: &'static ring::digest::Algorithm,
              pms: &[u8]) {
    let randoms = self.join_randoms();
    prf::prf(&mut self.master_secret,
             hashalg,
             pms,
             b"master secret",
             &randoms);
  }

  pub fn make_key_block(&self, hashalg: &'static ring::digest::Algorithm, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(len, 0u8);

    let randoms = self.join_randoms();
    prf::prf(&mut out,
             hashalg,
             &self.master_secret,
             b"key expansion",
             &randoms);

    out
  }
}
