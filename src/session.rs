pub struct SessionSecrets {
  peer_is_server: bool,
  master_secret: [u8; 48],
  client_random: [u8; 32],
  server_random: [u8; 32]
}

impl SessionSecrets {
  pub fn for_server() -> SessionSecrets {
    SessionSecrets {
      peer_is_server: false,
      master_secret: [0u8; 48],
      client_random: [0u8; 32],
      server_random: [0u8; 32]
    }
  }

  pub fn for_client() -> SessionSecrets {
    let mut sec = SessionSecrets::for_server();
    sec.peer_is_server = true;
    sec
  }
}
