use msgs::enums::CipherSuite;
use msgs::enums::AlertDescription;
use session::{Session, SessionSecrets, SessionCommon};
use suites::{SupportedCipherSuite, ALL_CIPHERSUITES};
use msgs::handshake::{CertificatePayload, DigitallySignedStruct, SessionID};
use msgs::handshake::{DistinguishedNames, SupportedSignatureAlgorithms, ASN1Cert};
use msgs::handshake::SignatureAndHashAlgorithm;
use msgs::enums::ContentType;
use msgs::message::Message;
use msgs::persist;
use client_hs;
use hash_hs;
use verify;
use sign;
use error::TLSError;
use rand;

use std::sync::{Arc, Mutex};
use std::io;

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

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert {
  /// With the server-supplied acceptable issuers in `acceptable_issuers`,
  /// the server's supported signature algorithms in `sigalgs`,
  /// return a certificate chain and signing key to authenticate.
  ///
  /// Return None to continue the handshake without any client
  /// authentication.  The server may reject the handshake later
  /// if it requires authentication.
  fn resolve(&self,
             acceptable_issuers: &DistinguishedNames,
             sigalgs: &SupportedSignatureAlgorithms)
    -> Option<(CertificatePayload, Arc<Box<sign::Signer>>)>;
}

struct FailResolveClientCert {}

impl ResolvesClientCert for FailResolveClientCert {
  fn resolve(&self,
             _acceptable_issuers: &DistinguishedNames,
             _sigalgs: &SupportedSignatureAlgorithms)
    -> Option<(CertificatePayload, Arc<Box<sign::Signer>>)>
  {
    None
  }
}

struct AlwaysResolvesClientCert {
  chain: CertificatePayload,
  key: Arc<Box<sign::Signer>>
}

impl AlwaysResolvesClientCert {
  fn new_rsa(chain: Vec<Vec<u8>>, priv_key: &[u8]) -> AlwaysResolvesClientCert {
    let key = sign::RSASigner::new(priv_key)
      .expect("Invalid RSA private key");
    let mut payload = Vec::new();
    for cert in chain {
      payload.push(ASN1Cert { body: cert.into_boxed_slice() });
    }

    AlwaysResolvesClientCert { chain: payload, key: Arc::new(Box::new(key)) }
  }
}

impl ResolvesClientCert for AlwaysResolvesClientCert {
  fn resolve(&self,
             _acceptable_issuers: &DistinguishedNames,
             _sigalgs: &SupportedSignatureAlgorithms)
    -> Option<(CertificatePayload, Arc<Box<sign::Signer>>)>
  {
    Some((self.chain.clone(), self.key.clone()))
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
  pub session_persistence: Mutex<Box<StoresClientSessions + Send + Sync>>,

  /// Our MTU.  If None, we don't limit TLS message sizes.
  pub mtu: Option<usize>,

  /// How to decide what client auth certificate/keys to use.
  pub client_auth_cert_resolver: Box<ResolvesClientCert>
}

impl ClientConfig {
  /// Make a `ClientConfig` with a default set of ciphersuites,
  /// no root certificates, no ALPN protocols, no
  /// session persistence, and no client auth.
  pub fn new() -> ClientConfig {
    ClientConfig {
      ciphersuites: ALL_CIPHERSUITES.to_vec(),
      root_store: verify::RootCertStore::empty(),
      alpn_protocols: Vec::new(),
      session_persistence: Mutex::new(Box::new(NoSessionStorage {})),
      mtu: None,
      client_auth_cert_resolver: Box::new(FailResolveClientCert {})
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
  pub fn set_persistence(&mut self, persist: Box<StoresClientSessions + Send + Sync>) {
    self.session_persistence = Mutex::new(persist);
  }

  /// Sets MTU to `mtu`.  If None, the default is used.
  /// If Some(x) then x must be greater than 5 bytes.
  pub fn set_mtu(&mut self, mtu: &Option<usize>) {
    /* Internally our MTU relates to fragment size, and does
     * not include the TLS header overhead.
     *
     * Externally the MTU is the whole packet size.  The difference
     * is PACKET_OVERHEAD. */
    if let Some(x) = *mtu {
      use msgs::fragmenter;
      assert!(x > fragmenter::PACKET_OVERHEAD);
      self.mtu = Some(x - fragmenter::PACKET_OVERHEAD);
    } else {
      self.mtu = None;
    }
  }

  /// Sets a single client authentication certificate and private key.
  /// This is blindly used for all servers that ask for client auth.
  ///
  /// `cert_chain` is a vector of DER-encoded certificates,
  /// `key_der` is a DER-encoded RSA private key.
  pub fn set_single_client_cert(&mut self, cert_chain: Vec<Vec<u8>>,
                                key_der: Vec<u8>) {
    self.client_auth_cert_resolver = Box::new(
      AlwaysResolvesClientCert::new_rsa(cert_chain, &key_der)
    );
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
  pub secrets: SessionSecrets,
  pub doing_client_auth: bool,
  pub client_auth_sigalg: Option<SignatureAndHashAlgorithm>,
  pub client_auth_cert: Option<CertificatePayload>,
  pub client_auth_key: Option<Arc<Box<sign::Signer>>>
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
      secrets: SessionSecrets::for_client(),
      doing_client_auth: false,
      client_auth_sigalg: None,
      client_auth_cert: None,
      client_auth_key: None
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
  ExpectServerHelloDoneOrCertRequest,
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
    // We want to read more data all the time, except when we
    // have unprocessed plaintext.  This provides back-pressure
    // to the TCP buffers.
    //
    // This also covers the handshake case, because we don't have
    // readable plaintext before handshake has completed.
    !self.common.has_readable_plaintext()
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
      ConnState::ExpectServerHelloDoneOrCertRequest => &client_hs::EXPECT_DONE_OR_CERTREQ,
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

  pub fn send_close_notify(&mut self) {
    self.common.send_warning_alert(AlertDescription::CloseNotify)
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
}

impl Session for ClientSession {
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
  fn send_close_notify(&mut self) {
    self.imp.send_close_notify()
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
