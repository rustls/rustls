use msgs::enums::CipherSuite;
use msgs::enums::{AlertDescription, HandshakeType, ExtensionType};
use session::{Session, SessionSecrets, SessionRandoms, SessionCommon};
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

use std::collections;
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

/// An implementor of StoresClientSessions which does nothing.
struct NoSessionStorage {}

impl StoresClientSessions for NoSessionStorage {
  fn put(&mut self, _key: Vec<u8>, _value: Vec<u8>) -> bool {
    false
  }

  fn get(&mut self, _key: &Vec<u8>) -> Option<Vec<u8>> {
    None
  }
}

/// An implementor of StoresClientSessions that stores everything
/// in memory.  It enforces a limit on the number of sessions
/// to bound memory usage.
pub struct ClientSessionMemoryCache {
  cache: collections::HashMap<Vec<u8>, Vec<u8>>,
  max_entries: usize
}

impl ClientSessionMemoryCache {
  pub fn new(size: usize) -> Box<ClientSessionMemoryCache> {
    assert!(size > 0);
    Box::new(ClientSessionMemoryCache {
      cache: collections::HashMap::new(),
      max_entries: size
    })
  }

  fn limit_size(&mut self) {
    while self.cache.len() > self.max_entries {
      let k = self.cache.keys().next().unwrap().clone();
      self.cache.remove(&k);
    }
  }
}

impl StoresClientSessions for ClientSessionMemoryCache {
  fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> bool {
    self.cache.insert(key, value);
    self.limit_size();
    true
  }

  fn get(&mut self, key: &Vec<u8>) -> Option<Vec<u8>> {
    self.cache.get(key).map(|x| x.clone())
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

  /// Return true if any certificates at all are available.
  fn has_certs(&self) -> bool;
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

  fn has_certs(&self) -> bool { false }
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
      payload.push(ASN1Cert::new(cert));
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

  fn has_certs(&self) -> bool { true }
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
  pub client_auth_cert_resolver: Box<ResolvesClientCert>,

  /// Whether to support RFC5077 tickets.  You must provide a working
  /// `session_persistence` member for this to have any meaningful
  /// effect.
  ///
  /// The default is true.
  pub enable_tickets: bool
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
      client_auth_cert_resolver: Box::new(FailResolveClientCert {}),
      enable_tickets: true
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
  pub server_cert_chain: CertificatePayload,
  pub ciphersuite: Option<&'static SupportedCipherSuite>,
  pub dns_name: String,
  pub session_id: SessionID,
  pub sent_extensions: Vec<ExtensionType>,
  pub server_kx_params: Vec<u8>,
  pub server_kx_sig: Option<DigitallySignedStruct>,
  pub transcript: hash_hs::HandshakeHash,
  pub resuming_session: Option<persist::ClientSessionValue>,
  pub randoms: SessionRandoms,
  pub must_issue_new_ticket: bool,
  pub new_ticket: Vec<u8>,
  pub new_ticket_lifetime: u32,
  pub doing_client_auth: bool,
  pub client_auth_sigalg: Option<SignatureAndHashAlgorithm>,
  pub client_auth_cert: Option<CertificatePayload>,
  pub client_auth_key: Option<Arc<Box<sign::Signer>>>
}

impl ClientHandshakeData {
  fn new(host_name: &str) -> ClientHandshakeData {
    ClientHandshakeData {
      server_cert_chain: Vec::new(),
      ciphersuite: None,
      dns_name: host_name.to_string(),
      session_id: SessionID::empty(),
      sent_extensions: Vec::new(),
      server_kx_params: Vec::new(),
      server_kx_sig: None,
      transcript: hash_hs::HandshakeHash::new(),
      resuming_session: None,
      randoms: SessionRandoms::for_client(),
      must_issue_new_ticket: false,
      new_ticket: Vec::new(),
      new_ticket_lifetime: 0,
      doing_client_auth: false,
      client_auth_sigalg: None,
      client_auth_cert: None,
      client_auth_key: None
    }
  }
}

#[derive(PartialEq)]
pub enum ConnState {
  ExpectServerHello,
  ExpectCertificate,
  ExpectServerKX,
  ExpectServerHelloDoneOrCertRequest,
  ExpectServerHelloDone,
  ExpectNewTicket,
  ExpectCCS,
  ExpectFinished,
  ExpectNewTicketResume,
  ExpectCCSResume,
  ExpectFinishedResume,
  Traffic
}

pub struct ClientSessionImpl {
  pub config: Arc<ClientConfig>,
  pub handshake_data: ClientHandshakeData,
  pub secrets: Option<SessionSecrets>,
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
      secrets: None,
      alpn_protocol: None,
      common: SessionCommon::new(config.mtu),
      state: ConnState::ExpectServerHello
    };

    if cs.config.client_auth_cert_resolver.has_certs() {
      cs.handshake_data.transcript.set_client_auth_enabled();
    }

    client_hs::emit_client_hello(&mut cs);
    cs
  }

  pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
    let mut ret = Vec::new();

    for cs in self.config.ciphersuites.iter() {
      ret.push(cs.suite);
    }

    /* We don't do renegotation at all, in fact. */
    ret.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    ret
  }

  pub fn start_encryption(&mut self) {
    let scs = self.handshake_data.ciphersuite.as_ref().unwrap();
    self.common.start_encryption(scs, self.secrets.as_ref().unwrap());
  }

  pub fn find_cipher_suite(&self, suite: &CipherSuite) -> Option<&'static SupportedCipherSuite> {
    for ref scs in &self.config.ciphersuites {
      if &scs.suite == suite {
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
    !self.common.sendable_tls.is_empty()
  }

  pub fn is_handshaking(&self) -> bool {
    self.state != ConnState::Traffic
  }

  pub fn process_msg(&mut self, mut msg: Message) -> Result<(), TLSError> {
    /* Decrypt if demanded by current state. */
    if self.common.peer_encrypting {
      let dm = try!(self.common.decrypt_incoming(msg));
      msg = dm;
    }

    /* For handshake messages, we need to join them before parsing
     * and processing. */
    if self.common.handshake_joiner.want_message(&msg) {
      try!(
        self.common.handshake_joiner.take_message(msg)
        .ok_or_else(|| TLSError::CorruptMessagePayload(ContentType::Handshake))
      );
      return self.process_new_handshake_messages();
    }

    /* Now we can fully parse the message payload. */
    if !msg.decode_payload() {
      return Err(TLSError::CorruptMessagePayload(msg.typ));
    }

    /* For alerts, we have separate logic. */
    if msg.is_content_type(ContentType::Alert) {
      return self.common.process_alert(msg);
    }

    return self.process_main_protocol(msg);
  }

  fn process_new_handshake_messages(&mut self) -> Result<(), TLSError> {
    while let Some(msg) = self.common.handshake_joiner.frames.pop_front() {
      try!(self.process_main_protocol(msg));
    }

    Ok(())
  }

  fn queue_unexpected_alert(&mut self) {
    self.common.send_fatal_alert(AlertDescription::UnexpectedMessage);
  }

  fn is_hello_req(&self, msg: &Message) -> bool {
    msg.is_handshake_type(HandshakeType::HelloRequest)
  }

  /// Detect and drop/reject HelloRequests.  This is needed irrespective
  /// of the current protocol state, which should illustrate how badly
  /// TLS renegotiation is designed.
  fn process_hello_req(&mut self) {
    /* If we're post handshake, send a refusal alert.
     * Otherwise, drop it silently. */
    if self.state == ConnState::Traffic {
      self.common.send_warning_alert(AlertDescription::NoRenegotiation);
    }
  }

  /// Process `msg`.  First, we get the current `Handler`.  Then we ask what
  /// that Handler expects.  Finally, we ask the handler to handle the message.
  fn process_main_protocol(&mut self, msg: Message) -> Result<(), TLSError> {
    if self.is_hello_req(&msg) {
      self.process_hello_req();
      return Ok(());
    }

    let handler = self.get_handler();
    try!(handler.expect.check_message(&msg)
         .map_err(|err| { self.queue_unexpected_alert(); err }));
    let new_state = try!((handler.handle)(self, msg));
    self.state = new_state;

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
      ConnState::ExpectNewTicket => &client_hs::EXPECT_NEW_TICKET,
      ConnState::ExpectCCS => &client_hs::EXPECT_CCS,
      ConnState::ExpectFinished => &client_hs::EXPECT_FINISHED,
      ConnState::ExpectNewTicketResume => &client_hs::EXPECT_NEW_TICKET_RESUME,
      ConnState::ExpectCCSResume => &client_hs::EXPECT_CCS_RESUME,
      ConnState::ExpectFinishedResume => &client_hs::EXPECT_FINISHED_RESUME,
      ConnState::Traffic => &client_hs::TRAFFIC
    }
  }

  pub fn process_new_packets(&mut self) -> Result<(), TLSError> {
    if self.common.message_deframer.desynced {
      return Err(TLSError::CorruptMessage);
    }

    while let Some(msg) = self.common.message_deframer.frames.pop_front() {
      try!(self.process_msg(msg));
    }

    Ok(())
  }

  pub fn send_close_notify(&mut self) {
    self.common.send_warning_alert(AlertDescription::CloseNotify)
  }

  pub fn get_peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
    if self.handshake_data.server_cert_chain.is_empty() {
      return None;
    }

    let mut r = Vec::new();
    for cert in &self.handshake_data.server_cert_chain {
      r.push(cert.0.clone());
    }

    Some(r)
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
  fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    self.imp.common.read_tls(rd)
  }

  /// Writes TLS messages to `wr`.
  fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<usize> {
    self.imp.common.write_tls(wr)
  }

  fn process_new_packets(&mut self) -> Result<(), TLSError> {
    self.imp.process_new_packets()
  }

  fn wants_read(&self) -> bool {
    self.imp.wants_read()
  }

  fn wants_write(&self) -> bool {
    self.imp.wants_write()
  }

  fn is_handshaking(&self) -> bool {
    self.imp.is_handshaking()
  }

  fn send_close_notify(&mut self) {
    self.imp.send_close_notify()
  }

  fn get_peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
    self.imp.get_peer_certificates()
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
    self.imp.common.send_plain(buf.to_vec());
    Ok(buf.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    self.imp.common.flush_plaintext();
    Ok(())
  }
}
