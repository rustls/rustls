use msgs::handshake::SessionID;
use msgs::enums::CipherSuite;
use msgs::codec::{Reader, Codec};
use msgs::base::PayloadU8;

/* These are the keys and values we store in session storage. */
#[derive(Debug)]
pub struct ClientSessionKey {
  dns_name: PayloadU8
}

impl Codec for ClientSessionKey {
  fn encode(&self, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(b"session");
    self.dns_name.encode(bytes);
  }

  /* Don't need to read these. */
  fn read(_r: &mut Reader) -> Option<ClientSessionKey> {
    None
  }
}

impl ClientSessionKey {
  pub fn for_dns_name(dns_name: &str) -> ClientSessionKey {
    ClientSessionKey {
      dns_name: PayloadU8::new(dns_name.as_bytes().to_vec())
    }
  }

  pub fn get_encoding(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    buf
  }
}

#[derive(Debug)]
pub struct ClientSessionValue {
  pub cipher_suite: CipherSuite,
  pub session_id: SessionID,
  pub master_secret: PayloadU8
}

impl Codec for ClientSessionValue {
  fn encode(&self, bytes: &mut Vec<u8>) {
    self.cipher_suite.encode(bytes);
    self.session_id.encode(bytes);
    self.master_secret.encode(bytes);
  }

  fn read(r: &mut Reader) -> Option<ClientSessionValue> {
    let cs = try_ret!(CipherSuite::read(r));
    let sid = try_ret!(SessionID::read(r));
    let ms = try_ret!(PayloadU8::read(r));

    Some(ClientSessionValue {
      cipher_suite: cs,
      session_id: sid,
      master_secret: ms
    })
  }
}

impl ClientSessionValue {
  pub fn new(cs: &CipherSuite, sessid: &SessionID, ms: Vec<u8>) -> ClientSessionValue {
    ClientSessionValue {
      cipher_suite: *cs,
      session_id: sessid.clone(),
      master_secret: PayloadU8::new(ms)
    }
  }

  pub fn read_bytes(bytes: &[u8]) -> Option<ClientSessionValue> {
    let mut rd = Reader::init(bytes);
    ClientSessionValue::read(&mut rd)
  }

  pub fn get_encoding(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    buf
  }
}
