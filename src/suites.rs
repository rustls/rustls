use msgs::enums::{CipherSuite, HashAlgorithm, SignatureAlgorithm, NamedCurve};
use msgs::handshake::{SignatureAndHashAlgorithm, KeyExchangeAlgorithm};
use msgs::handshake::SupportedSignatureAlgorithms;
use msgs::handshake::{ClientECDHParams, ServerECDHParams};
use msgs::codec::{Reader, Codec};
use util;

extern crate ring;
extern crate untrusted;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
  AES_128_GCM,
  AES_256_GCM,
  CHACHA20_POLY1305
}

/// The result of a key exchange.  This has our public key,
/// and the agreed premaster secret.
pub struct KeyExchangeResult {
  pub pubkey: Vec<u8>,
  pub premaster_secret: Vec<u8>
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub struct KeyExchange {
  alg: &'static ring::agreement::Algorithm,
  privkey: ring::agreement::EphemeralPrivateKey,
  pub pubkey: Vec<u8>
}

impl KeyExchange {
  pub fn named_curve_to_ecdh_alg(named_curve: &NamedCurve) -> &'static ring::agreement::Algorithm {
    match named_curve {
      &NamedCurve::X25519 => &ring::agreement::X25519,
      &NamedCurve::secp256r1 => &ring::agreement::ECDH_P256,
      &NamedCurve::secp384r1 => &ring::agreement::ECDH_P384,
      _ => unreachable!()
    }
  }

  pub fn client_ecdhe(kx_params: &Vec<u8>) -> Option<KeyExchangeResult> {
    let mut rd = Reader::init(&kx_params);
    let ecdh_params = ServerECDHParams::read(&mut rd).unwrap();

    KeyExchange::start_ecdhe(&ecdh_params.curve_params.named_curve)
      .complete(&ecdh_params.public.body)
  }

  pub fn start_ecdhe(named_curve: &NamedCurve) -> KeyExchange {
    let alg = KeyExchange::named_curve_to_ecdh_alg(named_curve);
    let rng = ring::rand::SystemRandom::new();
    let ours = ring::agreement::EphemeralPrivateKey::generate(alg, &rng)
      .unwrap();

    let mut pubkey = Vec::new();
    pubkey.resize(ours.public_key_len(), 0u8);
    ours.compute_public_key(pubkey.as_mut_slice()).unwrap();

    KeyExchange { alg: alg, privkey: ours, pubkey: pubkey }
  }

  pub fn server_complete(self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = ClientECDHParams::read(&mut rd).unwrap();

    self.complete(&ecdh_params.public.body)
  }

  fn complete(self, peer: &[u8]) -> Option<KeyExchangeResult> {
    let secret = ring::agreement::agree_ephemeral(
      self.privkey,
      self.alg,
      untrusted::Input::from(peer),
      (),
      |v| { let mut r = Vec::new(); r.extend_from_slice(v); Ok(r) }
    );

    if secret.is_err() {
      return None;
    }

    Some(KeyExchangeResult { pubkey: self.pubkey, premaster_secret: secret.unwrap() })
  }
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the ALL_CIPHERSUITES array.
#[derive(Debug)]
pub struct SupportedCipherSuite {
  /// The TLS enumeration naming this cipher suite.
  pub suite: CipherSuite,
  pub kx: KeyExchangeAlgorithm,
  pub bulk: BulkAlgorithm,
  pub hash: HashAlgorithm,
  pub sign: SignatureAlgorithm,
  pub mac_key_len: usize,
  pub enc_key_len: usize,
  pub fixed_iv_len: usize,

  /// This is a non-standard extension which extends the
  /// key block to provide an initial explicit nonce offset,
  /// in a deterministic and safe way.  GCM needs this,
  /// chacha20poly1305 works this way by design.
  pub explicit_nonce_len: usize
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

  /// We have parameters and a verified public key in `kx_params`.
  /// Generate an ephemeral key, generate the shared secret, and
  /// return it and the public half in a `KeyExchangeResult`.
  pub fn do_client_kx(&self, kx_params: &Vec<u8>) -> Option<KeyExchangeResult> {
    match &self.kx {
      &KeyExchangeAlgorithm::ECDHE => KeyExchange::client_ecdhe(kx_params),
      _ => unreachable!()
    }
  }

  pub fn start_server_kx(&self, named_curve: &NamedCurve) -> KeyExchange {
    match &self.kx {
      &KeyExchangeAlgorithm::ECDHE => KeyExchange::start_ecdhe(named_curve),
      _ => unreachable!()
    }
  }

  /// Resolve a single supported `SignatureAndHashAlgorithm` from the
  /// offered `SupportedSignatureAlgorithms`.  If we return None,
  /// the handshake terminates.
  pub fn resolve_sig_alg(&self, sigalgs: &SupportedSignatureAlgorithms) -> Option<SignatureAndHashAlgorithm> {
    let our_preference = vec![
      // Prefer the designated hash algorithm of this suite, for
      // security level consistency.
      SignatureAndHashAlgorithm { hash: self.hash.clone(), sign: self.sign.clone() },

      // Then prefer the right sign algorithm, with the best hashes
      // first.
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA512, sign: self.sign.clone() },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA384, sign: self.sign.clone() },
      SignatureAndHashAlgorithm { hash: HashAlgorithm::SHA256, sign: self.sign.clone() }
    ];

    util::first_in_both(our_preference.as_slice(),
                        sigalgs.as_slice())
  }

  pub fn get_aead_alg(&self) -> &'static ring::aead::Algorithm {
    match &self.bulk {
      &BulkAlgorithm::AES_128_GCM => &ring::aead::AES_128_GCM,
      &BulkAlgorithm::AES_256_GCM => &ring::aead::AES_256_GCM,
      &BulkAlgorithm::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305
    }
  }

  pub fn key_block_len(&self) -> usize {
    (self.mac_key_len + self.enc_key_len + self.fixed_iv_len) * 2 + self.explicit_nonce_len
  }
}

pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::ECDSA,
  bulk: BulkAlgorithm::CHACHA20_POLY1305,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 12,
  explicit_nonce_len: 0
};

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::RSA,
  bulk: BulkAlgorithm::CHACHA20_POLY1305,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 12,
  explicit_nonce_len: 0
};

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::RSA,
  bulk: BulkAlgorithm::AES_128_GCM,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 16,
  fixed_iv_len: 4,
  explicit_nonce_len: 8
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::RSA,
  bulk: BulkAlgorithm::AES_256_GCM,
  hash: HashAlgorithm::SHA384,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 4,
  explicit_nonce_len: 8
};

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::ECDSA,
  bulk: BulkAlgorithm::AES_128_GCM,
  hash: HashAlgorithm::SHA256,
  mac_key_len: 0,
  enc_key_len: 16,
  fixed_iv_len: 4,
  explicit_nonce_len: 8
};

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
SupportedCipherSuite {
  suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  kx: KeyExchangeAlgorithm::ECDHE,
  sign: SignatureAlgorithm::ECDSA,
  bulk: BulkAlgorithm::AES_256_GCM,
  hash: HashAlgorithm::SHA384,
  mac_key_len: 0,
  enc_key_len: 32,
  fixed_iv_len: 4,
  explicit_nonce_len: 8
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: [&'static SupportedCipherSuite; 6] = [
  &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
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

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with SignatureAlgorithm `sigalg` removed.
pub fn reduce_given_sigalg(all: &Vec<&'static SupportedCipherSuite>, sigalg: &SignatureAlgorithm)
  -> Vec<&'static SupportedCipherSuite> {
  all.iter()
     .filter(|&&suite| &suite.sign == sigalg)
     .cloned()
     .collect()
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
