use msgs::enums::CipherSuite;
use session::SessionSecrets;
use session::MessageCipher;
use suites::{SupportedCipherSuite, DEFAULT_CIPHERSUITES};
use msgs::handshake::{CertificatePayload, ClientExtension, DigitallySignedStruct};
use msgs::deframer::MessageDeframer;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::message::Message;
use msgs::base::Payload;
use client_hs;
use hash_hs;
use verify;
use handshake::HandshakeError;
use rand;

use std::sync::Arc;
use std::io;
use std::collections::VecDeque;
use std::mem;

pub struct ClientConfig {
  /* List of ciphersuites, in preference order. */
  pub ciphersuites: Vec<&'static SupportedCipherSuite>,

  /* Collection of root certificates. */
  pub root_store: verify::RootCertStore
}

impl ClientConfig {
  pub fn default() -> ClientConfig {
    ClientConfig {
      ciphersuites: DEFAULT_CIPHERSUITES.to_vec(),
      root_store: verify::RootCertStore::empty()
    }
  }
}

pub struct ClientHandshakeData {
  pub client_hello: Vec<u8>,
  pub server_cert_chain: CertificatePayload,
  pub ciphersuite: Option<&'static SupportedCipherSuite>,
  pub dns_name: String,
  pub server_kx_params: Vec<u8>,
  pub server_kx_sig: Option<DigitallySignedStruct>,
  pub handshake_hash: Option<hash_hs::HandshakeHash>,
  pub secrets: SessionSecrets
}

impl ClientHandshakeData {
  fn new(host_name: &str) -> ClientHandshakeData {
    ClientHandshakeData {
      client_hello: Vec::new(),
      server_cert_chain: Vec::new(),
      ciphersuite: None,
      dns_name: host_name.to_string(),
      server_kx_params: Vec::new(),
      server_kx_sig: None,
      handshake_hash: None,
      secrets: SessionSecrets::for_client()
    }
  }

  pub fn generate_client_random(&mut self) {
    rand::fill_random(&mut self.secrets.client_random);
  }

  pub fn hash_message(&mut self, m: &Message) {
    self.handshake_hash.as_mut().unwrap().update(m);
  }

  pub fn get_verify_hash(&self) -> Vec<u8> {
    self.handshake_hash.as_ref().unwrap().get_current_hash()
  }
}

#[derive(PartialEq)]
pub enum ConnState {
  ExpectServerHello,
  ExpectCertificate,
  ExpectServerKX,
  ExpectServerHelloDone,
  ExpectCCS,
  ExpectFinished,
  Traffic
}

impl ConnState {
  fn is_encrypted(&self) -> bool {
    match *self {
      ConnState::ExpectFinished
        | ConnState::Traffic => true,
      _ => false
    }
  }
}

pub struct ClientSession {
  pub config: Arc<ClientConfig>,
  pub handshake_data: ClientHandshakeData,
  pub secrets_current: SessionSecrets,
  message_cipher: Box<MessageCipher>,
  write_seq: u64,
  read_seq: u64,
  pub message_deframer: MessageDeframer,
  pub message_fragmenter: MessageFragmenter,
  pub sendable_plaintext: Vec<u8>,
  pub received_plaintext: Vec<u8>,
  pub tls_queue: VecDeque<Message>,
  pub state: ConnState
}

impl ClientSession {
  pub fn new(client_config: &Arc<ClientConfig>,
             hostname: &str) -> ClientSession {
    let mut cs = ClientSession {
      config: client_config.clone(),
      handshake_data: ClientHandshakeData::new(hostname),
      secrets_current: SessionSecrets::for_client(),
      message_cipher: MessageCipher::invalid(),
      write_seq: 0,
      read_seq: 0,
      message_deframer: MessageDeframer::new(),
      message_fragmenter: MessageFragmenter::new(MAX_FRAGMENT_LEN),
      sendable_plaintext: Vec::new(),
      received_plaintext: Vec::new(),
      tls_queue: VecDeque::new(),
      state: ConnState::ExpectServerHello
    };

    client_hs::emit_client_hello(&mut cs);
    cs
  }

  pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
    let mut ret = Vec::new();

    for cs in self.config.ciphersuites.iter() {
      ret.push(cs.suite.clone());
    }

    /* We don't do renegotation at all, in fact. */
    ret.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    ret
  }

  pub fn start_encryption(&mut self) {
    let scs = self.handshake_data.ciphersuite.as_ref().unwrap();
    self.message_cipher = MessageCipher::new(scs, &self.secrets_current);
  }

  pub fn encrypt_outgoing(&mut self, plain: &Message) -> Message {
    let seq = self.write_seq;
    self.write_seq += 1;
    assert!(self.write_seq != 0);
    self.message_cipher.encrypt(plain, seq).unwrap()
  }

  pub fn decrypt_incoming(&mut self, plain: &Message) -> Option<Message> {
    let seq = self.read_seq;
    self.read_seq += 1;
    assert!(self.read_seq != 0);
    self.message_cipher.decrypt(plain, seq).ok()
  }

  pub fn find_cipher_suite(&self, suite: &CipherSuite) -> Option<&'static SupportedCipherSuite> {
    let got = suite.clone();
    for ref scs in &self.config.ciphersuites {
      if scs.suite == got {
        return Some(scs);
      }
    }

    None
  }

  pub fn add_extensions(&self, _exts: &mut Vec<ClientExtension>) {
  }

  pub fn wants_read(&self) -> bool {
    true
  }

  pub fn wants_write(&self) -> bool {
    !self.tls_queue.is_empty()
  }

  pub fn process_msg(&mut self, msg: &mut Message) -> Result<(), HandshakeError> {
    if !self.state.is_encrypted() {
      msg.decode_payload();
    }

    let handler = self.get_handler();
    let expects = (handler.expect)();
    try!(expects.check_message(msg));
    let new_state = try!((handler.handle)(self, msg));
    self.state = new_state;

    /* Once we're connected, start flushing sendable_plaintext. */
    if self.state == ConnState::Traffic {
      self.flush_plaintext();
    }

    Ok(())
  }

  fn get_handler(&self) -> &'static client_hs::Handler {
    match self.state {
      ConnState::ExpectServerHello => &client_hs::EXPECT_SERVER_HELLO,
      ConnState::ExpectCertificate => &client_hs::EXPECT_CERTIFICATE,
      ConnState::ExpectServerKX => &client_hs::EXPECT_SERVER_KX,
      ConnState::ExpectServerHelloDone => &client_hs::EXPECT_SERVER_HELLO_DONE,
      ConnState::ExpectCCS => &client_hs::EXPECT_CCS,
      ConnState::ExpectFinished => &client_hs::EXPECT_FINISHED,
      ConnState::Traffic => &client_hs::TRAFFIC
    }
  }

  pub fn process_new_packets(&mut self) -> Result<(), HandshakeError> {
    loop {
      match self.message_deframer.frames.pop_front() {
        Some(mut msg) => try!(self.process_msg(&mut msg)),
        None => break
      }
    }

    Ok(())
  }

  pub fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    self.message_deframer.read(rd)
  }

  pub fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<()> {
    let msg_maybe = self.tls_queue.pop_front();
    if msg_maybe.is_none() {
      return Ok(());
    }

    let mut data = Vec::new();
    let msg = msg_maybe.unwrap();
    println!("writing {:?}", msg);
    msg.encode(&mut data);

    println!("write {:?}", data);

    wr.write_all(&data)
  }

  pub fn send_plain(&mut self, data: &[u8]) {
    use msgs::enums::{ContentType, ProtocolVersion};
    use msgs::message::MessagePayload;

    if self.state != ConnState::Traffic {
      /* If we haven't completed handshaking, buffer
       * plaintext to send once we do. */
      self.sendable_plaintext.extend_from_slice(data);
      return;
    }

    assert!(self.state.is_encrypted());

    /* Make one giant message, then have the fragmenter chop
     * it into bits.  Then encrypt and queue those bits. */
    let m = Message {
      typ: ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(data.to_vec())
    };

    let mut plain_messages = VecDeque::new();
    self.message_fragmenter.fragment(&m, &mut plain_messages);

    for m in plain_messages {
      let em = self.encrypt_outgoing(&m);
      self.tls_queue.push_back(em);
    }
  }

  pub fn flush_plaintext(&mut self) {
    if self.state != ConnState::Traffic {
      return;
    }

    let buf = mem::replace(&mut self.sendable_plaintext, Vec::new());
    self.send_plain(&buf);
  }

  pub fn take_received_plaintext(&mut self, bytes: Payload) {
    self.received_plaintext.extend_from_slice(&bytes.body);
  }
}

impl io::Read for ClientSession {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let len = try!(self.received_plaintext.as_slice().read(buf));
    self.received_plaintext.drain(0..len);
    Ok(len)
  }
}

impl io::Write for ClientSession {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self.send_plain(buf);
    Ok(buf.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    self.flush_plaintext();
    Ok(())
  }
}
