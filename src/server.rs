use session::SessionSecrets;
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES};
use msgs::handshake::{SessionID, CertificatePayload, ASN1Cert};
use msgs::handshake::{ServerNameRequest, SupportedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, ECPointFormatList};
use msgs::deframer::MessageDeframer;
use msgs::message::Message;
use server_hs;
use error::TLSError;
use rand;

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
  /* Choose a certificate chain given any SNI,
   * sigalgs, EC curves and EC point format extensions
   * from the client. */
  fn resolve(&self,
             server_name: Option<&ServerNameRequest>,
             sigalgs: &SupportedSignatureAlgorithms,
             ec_curves: &EllipticCurveList,
             ec_pointfmts: &ECPointFormatList) -> Result<CertificatePayload, ()>;
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

  /* How to choose a server cert. */
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
             _ec_pointfmts: &ECPointFormatList) -> Result<CertificatePayload, ()> {
    Err(())
  }
}

/* Something which always resolves to the same cert chain. */
struct AlwaysResolvesChain {
  chain: CertificatePayload
}

impl AlwaysResolvesChain {
  fn chain(chain: Vec<Vec<u8>>) -> AlwaysResolvesChain {
    let mut payload = Vec::new();
    for cert in chain {
      payload.push(ASN1Cert { body: cert.into_boxed_slice() });
    }
    AlwaysResolvesChain { chain: payload }
  }
}

impl ResolvesCert for AlwaysResolvesChain {
  fn resolve(&self,
             _server_name: Option<&ServerNameRequest>,
             _sigalgs: &SupportedSignatureAlgorithms,
             _ec_curves: &EllipticCurveList,
             _ec_pointfmts: &ECPointFormatList) -> Result<CertificatePayload, ()> {
    Ok(self.chain.clone())
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

  pub fn set_cert_chain(&mut self, cert_chain: Vec<Vec<u8>>) {
    self.cert_resolver = Box::new(AlwaysResolvesChain::chain(cert_chain));
  }
}

pub struct ServerHandshakeData {
  pub server_cert_chain: Option<CertificatePayload>,
  pub ciphersuite: Option<&'static SupportedCipherSuite>,
  pub secrets: SessionSecrets
}

impl ServerHandshakeData {
  fn new() -> ServerHandshakeData {
    ServerHandshakeData {
      server_cert_chain: None,
      ciphersuite: None,
      secrets: SessionSecrets::for_server()
    }
  }

  pub fn generate_server_random(&mut self) {
    rand::fill_random(&mut self.secrets.server_random);
  }
}

pub enum ConnState {
  ExpectClientHello,
  ExpectClientKX,
  ExpectCCS,
  ExpectFinish,
  Traffic
}

pub struct ServerSession {
  pub config: Arc<ServerConfig>,
  pub handshake_data: ServerHandshakeData,
  pub secrets_current: SessionSecrets,
  pub message_deframer: MessageDeframer,
  pub tls_queue: VecDeque<Message>,
  pub state: ConnState
}

impl ServerSession {
  pub fn new(server_config: &Arc<ServerConfig>) -> ServerSession {
    ServerSession {
      config: server_config.clone(),
      handshake_data: ServerHandshakeData::new(),
      secrets_current: SessionSecrets::for_server(),
      message_deframer: MessageDeframer::new(),
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

  pub fn process_msg(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    msg.decode_payload();

    let handler = self.get_handler();
    let expects = (handler.expect)();
    try!(expects.check_message(msg));
    let new_state = try!((handler.handle)(self, msg));
    self.state = new_state;

    Ok(())
  }

  fn get_handler(&self) -> &'static server_hs::Handler {
    match self.state {
      ConnState::ExpectClientHello => &server_hs::EXPECT_CLIENT_HELLO,
      ConnState::ExpectClientKX => &server_hs::EXPECT_CLIENT_KX,
      _ => &server_hs::INVALID_STATE
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
}
