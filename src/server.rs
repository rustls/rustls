use session::{Session, SessionSecrets, SessionCommon};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES, KeyExchange};
use msgs::enums::ContentType;
use msgs::enums::AlertDescription;
use msgs::handshake::{SessionID, CertificatePayload, ASN1Cert};
use msgs::handshake::{ServerNameRequest, SupportedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, ECPointFormatList};
use msgs::message::Message;
use hash_hs;
use server_hs;
use error::TLSError;
use rand;
use sign;

use std::sync::Arc;
use std::io;

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

/// Common configuration for a set of server sessions.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
pub struct ServerConfig {
  /// List of ciphersuites, in preference order.
  pub ciphersuites: Vec<&'static SupportedCipherSuite>,

  /// Ignore the client's ciphersuite order. Instead,
  /// choose the top ciphersuite in the server list
  /// which is supported by the client.
  pub ignore_client_order: bool,

  /// How to store client sessions.
  pub session_storage: Box<StoresSessions>,

  /// How to choose a server cert and key.
  pub cert_resolver: Box<ResolvesCert>,

  /// Protocol names we support, most preferred first.
  /// If empty we don't do ALPN at all.
  pub alpn_protocols: Vec<String>
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
    let key = sign::RSASigner::new(priv_key)
      .expect("Invalid RSA private key");
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
  /// Make a `ServerConfig` with a default set of ciphersuites,
  /// no keys/certificates, no ALPN protocols, and no
  /// session persistence.
  pub fn new() -> ServerConfig {
    ServerConfig {
      ciphersuites: ALL_CIPHERSUITES.to_vec(),
      ignore_client_order: false,
      session_storage: Box::new(NoSessionStorage {}),
      alpn_protocols: Vec::new(),
      cert_resolver: Box::new(FailResolveChain {})
    }
  }

  /// Sets a single certificate chain and matching private key.  This
  /// certificate and key is used for all subsequent connections,
  /// irrespective of things like SNI hostname.
  ///
  /// `cert_chain` is a vector of DER-encoded certificates.
  /// `key_der` is a DER-encoded RSA private key.
  pub fn set_single_cert(&mut self, cert_chain: Vec<Vec<u8>>, key_der: Vec<u8>) {
    self.cert_resolver = Box::new(AlwaysResolvesChain::new_rsa(cert_chain, &key_der));
  }

  /// Set the ALPN protocol list to the given protocol names.
  /// Overwrites any existing configured protocols.
  ///
  /// The first element in the `protocols` list is the most
  /// preferred, the last is the least preferred.
  pub fn set_protocols(&mut self, protocols: &[String]) {
    self.alpn_protocols.clear();
    self.alpn_protocols.extend_from_slice(protocols);
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
      ConnState::ExpectFinished
        | ConnState::Traffic => true,
      _ => false
    }
  }
}

pub struct ServerSessionImpl {
  pub config: Arc<ServerConfig>,
  pub handshake_data: ServerHandshakeData,
  pub secrets_current: SessionSecrets,
  pub common: SessionCommon,
  pub alpn_protocol: Option<String>,
  pub state: ConnState,
}

impl ServerSessionImpl {
  pub fn new(server_config: &Arc<ServerConfig>) -> ServerSessionImpl {
    ServerSessionImpl {
      config: server_config.clone(),
      handshake_data: ServerHandshakeData::new(),
      secrets_current: SessionSecrets::for_server(),
      common: SessionCommon::new(None),
      alpn_protocol: None,
      state: ConnState::ExpectClientHello
    }
  }

  pub fn wants_read(&self) -> bool {
    true
  }

  pub fn wants_write(&self) -> bool {
    !self.common.tls_queue.is_empty()
  }

  pub fn process_msg(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    /* Decrypt if demanded by current state. */
    if self.common.peer_encrypting {
      let dm = try!(self.common.decrypt_incoming(msg)
                    .ok_or(TLSError::DecryptError));
      *msg = dm;
    }

    /* For handshake messages, we need to join them before parsing
     * and processing. */
    if self.common.handshake_joiner.want_message(msg) {
      try!(
        self.common.handshake_joiner.take_message(msg)
        .ok_or_else(|| TLSError::CorruptMessage)
      );
      return self.process_new_handshake_messages();
    }

    /* Now we can fully parse the message payload. */
    msg.decode_payload();

    if msg.is_content_type(ContentType::Alert) {
      return self.common.process_alert(msg);
    }

    return self.process_main_protocol(msg);
  }

  fn process_new_handshake_messages(&mut self) -> Result<(), TLSError> {
    loop {
      match self.common.handshake_joiner.frames.pop_front() {
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

    if self.state.is_encrypted() && !self.common.peer_encrypting {
      self.common.peer_now_encrypting();
    }

    if self.state == ConnState::Traffic && !self.common.traffic {
      self.common.start_traffic();
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
      match self.common.message_deframer.frames.pop_front() {
        Some(mut msg) => try!(self.process_msg(&mut msg)),
        None => break
      }
    }

    Ok(())
  }

  pub fn start_encryption(&mut self) {
    let scs = self.handshake_data.ciphersuite.as_ref().unwrap();
    self.common.start_encryption(scs, &self.secrets_current);
  }

  pub fn send_close_notify(&mut self) {
    self.common.send_warning_alert(AlertDescription::CloseNotify)
  }
}

/// This represents a single TLS server session.
///
/// Send TLS-protected data to the peer using the io::Write trait implementation.
/// Read data from the peer using the io::Read trait implementation.
pub struct ServerSession {
  /* We use the pimpl idiom to hide unimportant details. */
  imp: ServerSessionImpl
}

impl ServerSession {
  /// Make a new ServerSession.  `config` controls how
  /// we behave in the TLS protocol.
  pub fn new(config: &Arc<ServerConfig>) -> ServerSession {
    ServerSession { imp: ServerSessionImpl::new(config) }
  }
}

impl Session for ServerSession {
  /// Read TLS content from `rd`.  This method does internal
  /// buffering, so `rd` can supply TLS messages in arbitrary-
  /// sized chunks (like a socket or pipe might).
  ///
  /// You should call `process_new_packets` each time a call to
  /// this function succeeds.
  ///
  /// The returned error only relates to IO on `rd`.  TLS-level
  /// errors are emitted from `process_new_packets`.
  fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    self.imp.common.read_tls(rd)
  }

  /// Writes TLS messages to `wr`.
  fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<()> {
    self.imp.common.write_tls(wr)
  }

  /// Processes any new packets read by a previous call to `read_tls`.
  /// Errors from this function relate to TLS protocol errors, and
  /// are generally fatal to the session.
  ///
  /// Success from this function can mean new plaintext is available:
  /// obtain it using `read`.
  fn process_new_packets(&mut self) -> Result<(), TLSError> {
    self.imp.process_new_packets()
  }

  /// Returns true if the caller should call `read_tls` as soon
  /// as possible.
  fn wants_read(&self) -> bool {
    self.imp.wants_read()
  }

  /// Returns true if the caller should call `write_tls` as soon
  /// as possible.
  fn wants_write(&self) -> bool {
    self.imp.wants_write()
  }

  /// Queues a close_notify fatal alert to be sent in the next
  /// `write_tls` call.  This informs the peer that the
  /// connection is being closed.
  ///
  /// Returns false if an alert cannot be sent thanks to the
  /// current state of the connection (ie, they cannot be sent
  /// during handshake).
  fn send_close_notify(&mut self) {
    self.imp.send_close_notify()
  }
}

impl io::Read for ServerSession {
  /// Obtain plaintext data received from the peer over
  /// this TLS connection.
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    self.imp.common.read(buf)
  }
}

impl io::Write for ServerSession {
  /// Send the plaintext `buf` to the peer, encrypting
  /// and authenticating it.  Once this function succeeds
  /// you should call `write_tls` which will output
  ///
  /// This function buffers plaintext sent before the
  /// TLS handshake completes, and sends it as soon
  /// as it can.  This buffer is of *unlimited size* so
  /// writing much data before it can be sent will
  /// cause excess memory usage.
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self.imp.common.send_plain(buf);
    Ok(buf.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    self.imp.common.flush_plaintext();
    Ok(())
  }
}
