use msgs::enums::{CipherSuite};

#[derive(Debug)]
pub struct SupportedCipherSuite {
  suite: CipherSuite,
}

impl PartialEq for SupportedCipherSuite {
  fn eq(&self, other: &SupportedCipherSuite) -> bool {
    self.suite == other.suite
  }
}

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
};

pub static default_ciphersuites: [&'static SupportedCipherSuite; 2] = [
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
