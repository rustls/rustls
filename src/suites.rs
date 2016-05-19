use msgs::enums::{CipherSuite, HashAlgorithm};
use msgs::handshake::KeyExchangeAlgorithm;
use msgs::handshake::CertificatePayload;

extern crate ring;

#[derive(Debug)]
pub enum BulkAlgorithm {
  AES_128_GCM,
  AES_256_GCM
}

/* This contains the data we need to keep for a connection
 * for a particular kind of KX. */
pub enum KeyExchangeData {
  ECDHE(ring::agreement::EphemeralKeyPair),
  Invalid
}

#[derive(Debug)]
pub struct SupportedCipherSuite {
  pub suite: CipherSuite,
  pub kx: KeyExchangeAlgorithm,
  pub bulk: BulkAlgorithm,
  pub hash: HashAlgorithm
}

impl PartialEq for SupportedCipherSuite {
  fn eq(&self, other: &SupportedCipherSuite) -> bool {
    self.suite == other.suite
  }
}

impl SupportedCipherSuite {
  pub fn init_kx(&self) -> KeyExchangeData {
    KeyExchangeData::Invalid
  }
}

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE_RSA,
  bulk: BulkAlgorithm::AES_128_GCM,
  hash: HashAlgorithm::SHA256
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  kx: KeyExchangeAlgorithm::ECDHE_RSA,
  bulk: BulkAlgorithm::AES_256_GCM,
  hash: HashAlgorithm::SHA384
};

pub static DEFAULT_CIPHERSUITES: [&'static SupportedCipherSuite; 2] = [
  &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
];

/* These both O(N^2)! */
pub fn choose_ciphersuite_preferring_client(
    client_suites: &Vec<CipherSuite>,
    server_suites: &Vec<&'static SupportedCipherSuite>) -> Option<&'static SupportedCipherSuite> {
  for client_suite in client_suites {
    if let Some(selected) = server_suites.iter().find(|x| *client_suite == x.suite) {
      return Some(*selected);
    }
  }

  None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &Vec<CipherSuite>,
    server_suites: &Vec<&'static SupportedCipherSuite>) -> Option<&'static SupportedCipherSuite> {
  if let Some(selected) = server_suites.iter().find(|x| client_suites.contains(&x.suite)) {
    return Some(*selected);
  }

  None
}

pub fn reduce_given_cert(all: &Vec<&'static SupportedCipherSuite>, certs: &CertificatePayload)
  -> Vec<&'static SupportedCipherSuite> {
  /* NYI */
  all.clone()
}

#[cfg(test)]
mod test {
  use msgs::enums::CipherSuite;

  #[test]
  fn test_client_pref() {
    let client = vec![
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ];
    let server = vec![
      &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    let chosen = super::choose_ciphersuite_preferring_client(&client, &server);
    assert!(chosen.is_some());
    assert_eq!(chosen.unwrap(), &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  }

  #[test]
  fn test_server_pref() {
    let client = vec![
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ];
    let server = vec![
      &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    let chosen = super::choose_ciphersuite_preferring_server(&client, &server);
    assert!(chosen.is_some());
    assert_eq!(chosen.unwrap(), &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
  }
}
