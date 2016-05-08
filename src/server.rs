use msgs::enums::CipherSuite;
use session::SessionSecrets;
use suites::{SupportedCipherSuite, default_ciphersuites};
use msgs::handshake::{SessionID, CertificatePayload};
use msgs::handshake::{ServerNameRequest, SupportedSignatureAlgorithms};
use msgs::handshake::{EllipticCurveList, ECPointFormatList};

use std::sync::Arc;
use std::fmt::Debug;

pub trait StoresSessions {
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
  fn store(&self, id: &SessionID, sec: &SessionSecrets) -> bool { false }
  fn find(&self, id: &SessionID) -> Option<SessionSecrets> { None }
  fn erase(&self, id: &SessionID) -> bool { false }
}

struct FailResolveChain {}

impl ResolvesCert for FailResolveChain {
  fn resolve(&self,
             server_name: Option<&ServerNameRequest>,
             sigalgs: &SupportedSignatureAlgorithms,
             ec_curves: &EllipticCurveList,
             ec_pointfmts: &ECPointFormatList) -> Result<CertificatePayload, ()> {
    Err(())
  }
}

impl ServerConfig {
  pub fn default() -> ServerConfig {
    ServerConfig {
      ciphersuites: default_ciphersuites.to_vec(),
      ignore_client_order: false,
      session_storage: Box::new(NoSessionStorage {}),
      cert_resolver: Box::new(FailResolveChain {})
    }
  }
}

pub struct ServerSession {
  pub config: Arc<ServerConfig>,
  pub secrets_handshake: SessionSecrets,
  pub secrets_current: SessionSecrets,
}

impl ServerSession {
  pub fn new() -> ServerSession {
    ServerSession {
      config: Arc::new(ServerConfig::default()),
      secrets_handshake: SessionSecrets::for_server(),
      secrets_current: SessionSecrets::for_server()
    }
  }
}
