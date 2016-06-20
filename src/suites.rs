use msgs::enums::{CipherSuite, HashAlgorithm, NamedCurve};
use msgs::handshake::KeyExchangeAlgorithm;
use msgs::handshake::CertificatePayload;
use msgs::handshake::ServerECDHParams;
use msgs::base::{Payload, PayloadU8};
use msgs::codec::{Reader, Codec};

extern crate ring;
extern crate untrusted;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum BulkAlgorithm {
  AES_128_GCM,
  AES_256_GCM
}

/* The result of a key exchange.  This has our public key,
 * and the agreed premaster secret. */
pub struct KeyExchangeResult {
  pub pubkey: Vec<u8>,
  pub premaster_secret: Vec<u8>
}

impl KeyExchangeResult {
  pub fn ecdhe(kx_params: &Vec<u8>) -> Option<KeyExchangeResult> {
    let mut rd = Reader::init(&kx_params);
    let ecdh_params = ServerECDHParams::read(&mut rd).unwrap();

    let alg = match ecdh_params.curve_params.named_curve {
      NamedCurve::X25519 => &ring::agreement::X25519,
      NamedCurve::secp256r1 => &ring::agreement::ECDH_P256,
      NamedCurve::secp384r1 => &ring::agreement::ECDH_P384,
      _ => unreachable!()
    };

    let rng = ring::rand::SystemRandom::new();
    let ours = ring::agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();

    /* Encode our public key. */
    let mut pubkey = Vec::new();
    pubkey.resize(ours.public_key_len(), 0u8);
    ours.compute_public_key(pubkey.as_mut_slice()).unwrap();

    /* Do the key agreement. */
    let secret = ring::agreement::agree_ephemeral(
      ours,
      alg,
      untrusted::Input::new(&ecdh_params.public.body).unwrap(),
      (),
      |v| { let mut r = Vec::new(); r.extend_from_slice(v); Ok(r) }
    );

    if secret.is_err() {
      return None;
    }

    Some(KeyExchangeResult { pubkey: pubkey, premaster_secret: secret.unwrap() })
  }

  pub fn encode_public(&self) -> Payload {
    /* This is a bodgey way of making an ECPoint. */
    let ecpoint = PayloadU8 { body: self.pubkey.clone().into_boxed_slice() };
    let mut body = Vec::new();
    ecpoint.encode(&mut body);
    Payload { body: body.into_boxed_slice() }
  }
}

/// A cipher suite supported by rustls.
#[derive(Debug)]
pub struct SupportedCipherSuite {
  /// The TLS enumeration naming this cipher suite.
  pub suite: CipherSuite,
  pub kx: KeyExchangeAlgorithm,
  pub bulk: BulkAlgorithm,
  pub hash: HashAlgorithm,
  pub mac_key_len: usize,
  pub enc_key_len: usize,
  pub fixed_iv_len: usize
}

impl PartialEq for SupportedCipherSuite {
  fn eq(&self, other: &SupportedCipherSuite) -> bool {
    self.suite == other.suite
  }
}

impl SupportedCipherSuite {
  pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
    match &self.hash {
      &HashAlgorithm::SHA1 => &ring::digest::SHA1,
      &HashAlgorithm::SHA256 => &ring::digest::SHA256,
      &HashAlgorithm::SHA384 => &ring::digest::SHA384,
      &HashAlgorithm::SHA512 => &ring::digest::SHA512,
      _ => unreachable!()
    }
  }

  pub fn do_client_kx(&self, kx_params: &Vec<u8>) -> Option<KeyExchangeResult> {
    match &self.kx {
      &KeyExchangeAlgorithm::ECDHE_ECDSA |
        &KeyExchangeAlgorithm::ECDHE_RSA => KeyExchangeResult::ecdhe(kx_params),
      _ => unreachable!()
    }
  }

  pub fn get_aead_alg(&self) -> &'static ring::aead::Algorithm {
    match &self.bulk {
      &BulkAlgorithm::AES_128_GCM => &ring::aead::AES_128_GCM,
      &BulkAlgorithm::AES_256_GCM => &ring::aead::AES_256_GCM
    }
  }

  pub fn key_block_len(&self) -> usize {
    (self.mac_key_len + self.enc_key_len + self.fixed_iv_len) * 2
  }
}

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE_RSA,
  bulk: BulkAlgorithm::AES_128_GCM,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 16,
  fixed_iv_len: 4
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  kx: KeyExchangeAlgorithm::ECDHE_RSA,
  bulk: BulkAlgorithm::AES_256_GCM,
  hash: HashAlgorithm::SHA384,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 4
};

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE_ECDSA,
  bulk: BulkAlgorithm::AES_128_GCM,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 16,
  fixed_iv_len: 4
};

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  kx: KeyExchangeAlgorithm::ECDHE_ECDSA,
  bulk: BulkAlgorithm::AES_256_GCM,
  hash: HashAlgorithm::SHA384,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 4
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: [&'static SupportedCipherSuite; 4] = [
  &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
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

pub fn reduce_given_cert(all: &Vec<&'static SupportedCipherSuite>, _certs: &CertificatePayload)
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
