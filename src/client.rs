use msgs::enums::CipherSuite;
use session::{SessionSecrets, SessionCommon};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES};
use msgs::handshake::{CertificatePayload, DigitallySignedStruct, SessionID};
use msgs::enums::ContentType;
use msgs::message::Message;
use msgs::persist;
use client_hs;
use hash_hs;
use verify;
use error::TLSError;
use rand;

use std::sync::Arc;
use std::io;
use std::cell;

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
pub trait StoresClientSessions {
  /// Stores a new `value` for `key`.  Returns `true`
  /// if the value was stored.
  fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> bool;

  /// Returns the latest value for `key`.  Returns `None`
  /// if there's no such value.
  fn get(&mut self, key: &Vec<u8>) -> Option<Vec<u8>>;
}

struct NoSessionStorage {}

impl StoresClientSessions for NoSessionStorage {
  fn put(&mut self, _key: Vec<u8>, _value: Vec<u8>) -> bool {
    false
  }

  fn get(&mut self, _key: &Vec<u8>) -> Option<Vec<u8>> {
    None
  }
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
pub struct ClientConfig {
  /// List of ciphersuites, in preference order.
  pub ciphersuites: Vec<&'static SupportedCipherSuite>,

  /// Collection of root certificates.
  pub root_store: verify::RootCertStore,

  /// Which ALPN protocols we include in our client hello.
  /// If empty, no ALPN extension is sent.
  pub alpn_protocols: Vec<String>,

  /// How we store session data or tickets.
  pub session_persistence: cell::RefCell<Box<StoresClientSessions>>,

  /// Our MTU.  If None, we don't limit TLS message sizes.
  pub mtu: Option<usize>
}

impl ClientConfig {
  /// Make a `ClientConfig` with a default set of ciphersuites,
  /// no root certificates, no ALPN protocols, and no
  /// session persistence.
  pub fn default() -> ClientConfig {
    ClientConfig {
      ciphersuites: ALL_CIPHERSUITES.to_vec(),
      root_store: verify::RootCertStore::empty(),
      alpn_protocols: Vec::new(),
      session_persistence: cell::RefCell::new(Box::new(NoSessionStorage {})),
      mtu: None
    }
  }

  /// Set the ALPN protocol list to the given protocol names.
  /// Overwrites any existing configured protocols.
  /// The first element in the `protocols` list is the most
  /// preferred, the last is the least preferred.
  pub fn set_protocols(&mut self, protocols: &[String]) {
    self.alpn_protocols.clear();
    self.alpn_protocols.extend_from_slice(protocols);
  }

  /// Sets persistence layer to `persist`.
  pub fn set_persistence(&mut self, persist: Box<StoresClientSessions>) {
    self.session_persistence = cell::RefCell::new(persist);
  }

  /// Sets MTU to `mtu`.  If None, the default is used.
  /// If Some(x) then x must be greater than 5 bytes.
  pub fn set_mtu(&mut self, mtu: &Option<usize>) {
    self.mtu = mtu.clone();
  }
}

pub struct ClientHandshakeData {
  pub client_hello: Vec<u8>,
  pub server_cert_chain: CertificatePayload,
  pub ciphersuite: Option<&'static SupportedCipherSuite>,
  pub dns_name: String,
  pub session_id: SessionID,
  pub server_kx_params: Vec<u8>,
  pub server_kx_sig: Option<DigitallySignedStruct>,
  pub handshake_hash: Option<hash_hs::HandshakeHash>,
  pub resuming_session: Option<persist::ClientSessionValue>,
  pub secrets: SessionSecrets
}

impl ClientHandshakeData {
  fn new(host_name: &str) -> ClientHandshakeData {
    ClientHandshakeData {
      client_hello: Vec::new(),
      server_cert_chain: Vec::new(),
      ciphersuite: None,
      dns_name: host_name.to_string(),
      session_id: SessionID::empty(),
      server_kx_params: Vec::new(),
      server_kx_sig: None,
      handshake_hash: None,
      resuming_session: None,
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
  ExpectCCSResume,
  ExpectFinishedResume,
  Traffic
}

impl ConnState {
  fn is_encrypted(&self) -> bool {
    match *self {
      ConnState::ExpectFinished
        | ConnState::ExpectFinishedResume
        | ConnState::Traffic => true,
      _ => false
    }
  }
}

pub struct ClientSessionImpl {
  pub config: Arc<ClientConfig>,
  pub handshake_data: ClientHandshakeData,
  pub secrets_current: SessionSecrets,
  pub alpn_protocol: Option<String>,
  pub common: SessionCommon,
  pub state: ConnState
}

impl ClientSessionImpl {
  pub fn new(config: &Arc<ClientConfig>,
             hostname: &str) -> ClientSessionImpl {
    let mut cs = ClientSessionImpl {
      config: config.clone(),
      handshake_data: ClientHandshakeData::new(hostname),
      secrets_current: SessionSecrets::for_client(),
      alpn_protocol: None,
      common: SessionCommon::new(config.mtu),
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
    self.common.start_encryption(scs, &self.secrets_current);
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
      self.common.handshake_joiner.take_message(msg);
      return self.process_new_handshake_messages();
    }

    /* Now we can fully parse the message payload. */
    msg.decode_payload();

    /* For alerts, we have separate logic. */
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

  /// Process `msg`.  First, we get the current `Handler`.  Then we ask what
  /// that Handler expects.  Finally, we ask the handler to handle the message.
  fn process_main_protocol(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    let handler = self.get_handler();
    try!(handler.expect.check_message(msg));
    let new_state = try!((handler.handle)(self, msg));
    self.state = new_state;

    /* Start decrypting incoming messages at the right time. */
    if self.state.is_encrypted() && !self.common.peer_encrypting {
      self.common.peer_now_encrypting();
    }

    /* Once we're connected, start flushing sendable_plaintext. */
    if self.state == ConnState::Traffic && !self.common.traffic {
      self.common.start_traffic();
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
      ConnState::ExpectCCSResume => &client_hs::EXPECT_CCS_RESUME,
      ConnState::ExpectFinishedResume => &client_hs::EXPECT_FINISHED_RESUME,
      ConnState::Traffic => &client_hs::TRAFFIC
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
}

/// This represents a single TLS client session.
pub struct ClientSession {
  /* We use the pimpl idiom to hide unimportant details. */
  imp: ClientSessionImpl
}

impl ClientSession {
  /// Make a new ClientSession.  `config` controls how
  /// we behave in the TLS protocol, `hostname` is the
  /// hostname of who we want to talk to.
  pub fn new(config: &Arc<ClientConfig>,
             hostname: &str) -> ClientSession {
    ClientSession { imp: ClientSessionImpl::new(config, hostname) }
  }

  /// Read TLS content from `rd`.  This method does internal
  /// buffering, so `rd` can supply TLS messages in arbitrary-
  /// sized chunks (like a socket or pipe might).
  ///
  /// You should call `process_new_packets` each time a call to
  /// this function succeeds.
  ///
  /// The returned error only relates to IO on `rd`.  TLS-level
  /// errors are emitted from `process_new_packets`.
  pub fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    self.imp.common.read_tls(rd)
  }

  /// Writes TLS messages to `wr`.
  pub fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<()> {
    self.imp.common.write_tls(wr)
  }

  /// Processes any new packets read by a previous call to `read_tls`.
  /// Errors from this function relate to TLS protocol errors, and
  /// are generally fatal to the session.
  ///
  /// Success from this function can mean new plaintext is available:
  /// obtain it using `read`.
  pub fn process_new_packets(&mut self) -> Result<(), TLSError> {
    self.imp.process_new_packets()
  }

  /// Returns true if the caller should call `read_tls` as soon
  /// as possible.
  pub fn wants_read(&self) -> bool {
    self.imp.wants_read()
  }

  /// Returns true if the caller should call `write_tls` as soon
  /// as possible.
  pub fn wants_write(&self) -> bool {
    self.imp.wants_write()
  }
}

impl io::Read for ClientSession {
  /// Obtain plaintext data received from the peer over
  /// this TLS connection.
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    self.imp.common.read(buf)
  }
}

impl io::Write for ClientSession {
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
