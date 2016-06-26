use session::{SessionSecrets, MessageCipher};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES, KeyExchange};
use msgs::enums::{ContentType, AlertDescription, AlertLevel};
use msgs::handshake::{SessionID, CertificatePayload, ASN1Cert};
use msgs::handshake::{ServerNameRequest, SupportedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, ECPointFormatList};
use msgs::deframer::MessageDeframer;
use msgs::hsjoiner::HandshakeJoiner;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::message::{Message, MessagePayload};
use msgs::base::Payload;
use hash_hs;
use server_hs;
use error::TLSError;
use rand;
use sign;

use std::sync::Arc;
use std::io;
use std::collections::VecDeque;

pub trait StoresSessions {
  /* Generate a session ID. */
  fn generate(&self) -> SessionID;

  /* Store session secrets. */
  fn store(&self, id: &SessionID, sec: &SessionSecrets) -> bool;

  /* Find a session with the given id. */
  fn find(&self, id: &SessionID) -> Option<SessionSecrets>;

  /* Erase a session with the given id. */
  fn erase(&self, id: &SessionID) -> bool;
}

pub trait ResolvesCert {
  /// Choose a certificate chain and matching key given any SNI,
  /// sigalgs, EC curves and EC point format extensions
  /// from the client.
  ///
  /// The certificate chain is returned as a `CertificatePayload`,
  /// the key is inside a `Signer`.
  fn resolve(&self,
             server_name: Option<&ServerNameRequest>,
             sigalgs: &SupportedSignatureAlgorithms,
             ec_curves: &EllipticCurveList,
             ec_pointfmts: &ECPointFormatList) -> Result<(CertificatePayload, Arc<Box<sign::Signer>>), ()>;
}

pub struct ServerConfig {
  /* List of ciphersuites, in preference order. */
  pub ciphersuites: Vec<&'static SupportedCipherSuite>,

  /* Ignore the client's ciphersuite order. Instead,
   * choose the top ciphersuite in the server list
   * which is supported by the client. */
  pub ignore_client_order: bool,

  /* How to store client sessions. */
  pub session_storage: Box<StoresSessions>,

  /* How to choose a server cert and key. */
  pub cert_resolver: Box<ResolvesCert>
}

struct NoSessionStorage {}

impl StoresSessions for NoSessionStorage {
  fn generate(&self) -> SessionID { SessionID { bytes: Vec::new() } }
  fn store(&self, _id: &SessionID, _sec: &SessionSecrets) -> bool { false }
  fn find(&self, _id: &SessionID) -> Option<SessionSecrets> { None }
  fn erase(&self, _id: &SessionID) -> bool { false }
}

/* Something which never resolves a certificate. */
struct FailResolveChain {}

impl ResolvesCert for FailResolveChain {
  fn resolve(&self,
             _server_name: Option<&ServerNameRequest>,
             _sigalgs: &SupportedSignatureAlgorithms,
             _ec_curves: &EllipticCurveList,
             _ec_pointfmts: &ECPointFormatList) -> Result<(CertificatePayload, Arc<Box<sign::Signer>>), ()> {
    Err(())
  }
}

/* Something which always resolves to the same cert chain. */
struct AlwaysResolvesChain {
  chain: CertificatePayload,
  key: Arc<Box<sign::Signer>>
}

impl AlwaysResolvesChain {
  fn new_rsa(chain: Vec<Vec<u8>>, priv_key: &[u8]) -> AlwaysResolvesChain {
    let key = sign::RSASigner::new(priv_key).unwrap();
    let mut payload = Vec::new();
    for cert in chain {
      payload.push(ASN1Cert { body: cert.into_boxed_slice() });
    }
    AlwaysResolvesChain { chain: payload, key: Arc::new(Box::new(key)) }
  }
}

impl ResolvesCert for AlwaysResolvesChain {
  fn resolve(&self,
             _server_name: Option<&ServerNameRequest>,
             _sigalgs: &SupportedSignatureAlgorithms,
             _ec_curves: &EllipticCurveList,
             _ec_pointfmts: &ECPointFormatList) -> Result<(CertificatePayload, Arc<Box<sign::Signer>>), ()> {
    Ok((self.chain.clone(), self.key.clone()))
  }
}

impl ServerConfig {
  pub fn default() -> ServerConfig {
    ServerConfig {
      ciphersuites: ALL_CIPHERSUITES.to_vec(),
      ignore_client_order: false,
      session_storage: Box::new(NoSessionStorage {}),
      cert_resolver: Box::new(FailResolveChain {})
    }
  }

  /// Sets a single certificate chain and matching private key.  This
  /// certificate and key is used for all subsequent connections,
  /// irrespective of things like SNI hostname.
  pub fn set_single_cert(&mut self, cert_chain: Vec<Vec<u8>>, key_der: Vec<u8>) {
    self.cert_resolver = Box::new(AlwaysResolvesChain::new_rsa(cert_chain, &key_der));
  }
}

pub struct ServerHandshakeData {
  pub server_cert_chain: Option<CertificatePayload>,
  pub ciphersuite: Option<&'static SupportedCipherSuite>,
  pub secrets: SessionSecrets,
  pub handshake_hash: Option<hash_hs::HandshakeHash>,
  pub kx_data: Option<KeyExchange>
}

impl ServerHandshakeData {
  fn new() -> ServerHandshakeData {
    ServerHandshakeData {
      server_cert_chain: None,
      ciphersuite: None,
      secrets: SessionSecrets::for_server(),
      handshake_hash: None,
      kx_data: None
    }
  }

  pub fn generate_server_random(&mut self) {
    rand::fill_random(&mut self.secrets.server_random);
  }

  pub fn start_handshake_hash(&mut self) {
    let hash = self.ciphersuite.as_ref().unwrap().get_hash();
    self.handshake_hash = Some(hash_hs::HandshakeHash::new(hash));
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
  ExpectClientHello,
  ExpectClientKX,
  ExpectCCS,
  ExpectFinished,
  Traffic
}

impl ConnState {
  fn is_encrypted(&self) -> bool {
    match *self {
      ConnState::ExpectFinished |
        ConnState::Traffic => true,
      _ => false
    }
  }
}

pub struct ServerSession {
  pub config: Arc<ServerConfig>,
  pub handshake_data: ServerHandshakeData,
  pub secrets_current: SessionSecrets,
  message_cipher: Box<MessageCipher>,
  write_seq: u64,
  read_seq: u64,
  peer_eof: bool,
  pub message_deframer: MessageDeframer,
  pub handshake_joiner: HandshakeJoiner,
  pub message_fragmenter: MessageFragmenter,
  tls_queue: VecDeque<Message>,
  pub state: ConnState,
}

impl ServerSession {
  pub fn new(server_config: &Arc<ServerConfig>) -> ServerSession {
    ServerSession {
      config: server_config.clone(),
      handshake_data: ServerHandshakeData::new(),
      secrets_current: SessionSecrets::for_server(),
      message_cipher: MessageCipher::invalid(),
      write_seq: 0,
      read_seq: 0,
      peer_eof: false,
      message_deframer: MessageDeframer::new(),
      handshake_joiner: HandshakeJoiner::new(),
      message_fragmenter: MessageFragmenter::new(MAX_FRAGMENT_LEN),
      tls_queue: VecDeque::new(),
      state: ConnState::ExpectClientHello
    }
  }

  pub fn wants_read(&self) -> bool {
    true
  }

  pub fn wants_write(&self) -> bool {
    !self.tls_queue.is_empty()
  }

  pub fn process_alert(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    if let MessagePayload::Alert(ref alert) = msg.payload {
      /* If we get a CloseNotify, make a note to declare EOF to our
       * caller. */
      if alert.description == AlertDescription::CloseNotify {
        self.peer_eof = true;
        return Ok(())
      }

      /* Warnings are nonfatal. */
      if alert.level == AlertLevel::Warning {
        warn!("TLS alert warning received: {:#?}", msg);
        return Ok(())
      }

      error!("TLS alert received: {:#?}", msg);
      return Err(TLSError::AlertReceived(alert.description.clone()));
    } else {
      unreachable!();
    }
  }

  pub fn process_msg(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    /* Decrypt if demanded by current state. */
    if self.state.is_encrypted() {
      println!("decrypt incoming {:?}", msg);
      let dm = try!(self.decrypt_incoming(msg)
                    .ok_or(TLSError::DecryptError));
      *msg = dm;
    }

    /* For handshake messages, we need to join them before parsing
     * and processing. */
    if self.handshake_joiner.want_message(msg) {
      self.handshake_joiner.take_message(msg);
      return self.process_new_handshake_messages();
    }

    /* Now we can fully parse the message payload. */
    msg.decode_payload();

    if msg.is_content_type(ContentType::Alert) {
      return self.process_alert(msg);
    }

    return self.process_main_protocol(msg);
  }

  fn process_new_handshake_messages(&mut self) -> Result<(), TLSError> {
    loop {
      match self.handshake_joiner.frames.pop_front() {
        Some(mut msg) => try!(self.process_main_protocol(&mut msg)),
        None => break
      }
    }

    Ok(())
  }

  pub fn process_main_protocol(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    let handler = self.get_handler();
    try!(handler.expect.check_message(msg));
    let new_state = try!((handler.handle)(self, msg));
    self.state = new_state;

    if self.state == ConnState::Traffic {
      self.flush_plaintext();
    }

    Ok(())
  }

  fn get_handler(&self) -> &'static server_hs::Handler {
    match self.state {
      ConnState::ExpectClientHello => &server_hs::EXPECT_CLIENT_HELLO,
      ConnState::ExpectClientKX => &server_hs::EXPECT_CLIENT_KX,
      ConnState::ExpectCCS => &server_hs::EXPECT_CCS,
      ConnState::ExpectFinished => &server_hs::EXPECT_FINISHED,
      ConnState::Traffic => &server_hs::TRAFFIC
    }
  }

  pub fn process_new_packets(&mut self) -> Result<(), TLSError> {
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

  pub fn start_encryption(&mut self) {
    let scs = self.handshake_data.ciphersuite.as_ref().unwrap();
    self.message_cipher = MessageCipher::new(scs, &self.secrets_current);
  }

  /// Send a raw TLS message, fragmenting it if needed.
  pub fn send_msg(&mut self, m: &Message, must_encrypt: bool) {
    if !must_encrypt {
      self.message_fragmenter.fragment(m, &mut self.tls_queue);
    } else {
      self.send_msg_encrypt(m);
    }
  }

  /// Fragment `m`, encrypt the fragments, and then queue
  /// the encrypted fragments for sending.
  pub fn send_msg_encrypt(&mut self, m: &Message) {
    let mut plain_messages = VecDeque::new();
    self.message_fragmenter.fragment(m, &mut plain_messages);

    for m in plain_messages {
      let em = self.encrypt_outgoing(&m);
      self.tls_queue.push_back(em);
    }
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

  pub fn flush_plaintext(&mut self) {
  }

  pub fn take_received_plaintext(&mut self, bytes: Payload) {
    println!("plaintext {:?}", bytes);
  }
}

