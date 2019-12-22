use crate::msgs::enums::{CipherSuite, HashAlgorithm, SignatureAlgorithm, SignatureScheme};
use crate::msgs::enums::{NamedGroup, ProtocolVersion};
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};
use crate::msgs::codec::{Reader, Codec};

use ring;

/// Bulk symmetric encryption scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    AES_128_GCM,

    /// AES with 256-bit keys in Galois counter mode.
    AES_256_GCM,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    CHACHA20_POLY1305,
}

/// The result of a key exchange.  This has our public key,
/// and the agreed shared secret (also known as the "premaster secret"
/// in TLS1.0-era protocols, and "Z" in TLS1.3).
pub struct KeyExchangeResult {
    pub pubkey: ring::agreement::PublicKey,
    pub shared_secret: Vec<u8>,
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub struct KeyExchange {
    pub group: NamedGroup,
    alg: &'static ring::agreement::Algorithm,
    privkey: ring::agreement::EphemeralPrivateKey,
    pub pubkey: ring::agreement::PublicKey,
}

impl KeyExchange {
    pub fn named_group_to_ecdh_alg(group: NamedGroup)
                                   -> Option<&'static ring::agreement::Algorithm> {
        match group {
            NamedGroup::X25519 => Some(&ring::agreement::X25519),
            NamedGroup::secp256r1 => Some(&ring::agreement::ECDH_P256),
            NamedGroup::secp384r1 => Some(&ring::agreement::ECDH_P384),
            _ => None,
        }
    }

    pub fn supported_groups() -> &'static [NamedGroup] {
        // in preference order
        &[
            NamedGroup::X25519,
            NamedGroup::secp384r1,
            NamedGroup::secp256r1
        ]
    }

    pub fn client_ecdhe(kx_params: &[u8]) -> Option<KeyExchangeResult> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ServerECDHParams::read(&mut rd)?;

        KeyExchange::start_ecdhe(ecdh_params.curve_params.named_group)?
            .complete(&ecdh_params.public.0)
    }

    pub fn start_ecdhe(named_group: NamedGroup) -> Option<KeyExchange> {
        let alg = KeyExchange::named_group_to_ecdh_alg(named_group)?;
        let rng = ring::rand::SystemRandom::new();
        let ours = ring::agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();

        let pubkey = ours.compute_public_key().unwrap();

        Some(KeyExchange {
            group: named_group,
            alg,
            privkey: ours,
            pubkey,
        })
    }

    pub fn check_client_params(&self, kx_params: &[u8]) -> bool {
        self.decode_client_params(kx_params).is_some()
    }

    fn decode_client_params(&self, kx_params: &[u8]) -> Option<ClientECDHParams> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ClientECDHParams::read(&mut rd).unwrap();
        if rd.any_left() {
            None
        } else {
            Some(ecdh_params)
        }
    }

    pub fn server_complete(self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        self.decode_client_params(kx_params)
            .and_then(|ecdh| self.complete(&ecdh.public.0))
    }

    pub fn complete(self, peer: &[u8]) -> Option<KeyExchangeResult> {
        let peer_key = ring::agreement::UnparsedPublicKey::new(self.alg, peer);
        let secret = ring::agreement::agree_ephemeral(self.privkey,
                                                      &peer_key,
                                                      (),
                                                      |v| {
                                                          let mut r = Vec::new();
                                                          r.extend_from_slice(v);
                                                          Ok(r)
                                                      });

        if secret.is_err() {
            return None;
        }

        Some(KeyExchangeResult {
            pubkey: self.pubkey,
            shared_secret: secret.unwrap(),
        })
    }
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_CIPHERSUITES` array.
#[derive(Debug)]
pub struct SupportedCipherSuite {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

    /// How to do hashing.
    pub hash: HashAlgorithm,

    /// How to sign messages.
    pub sign: SignatureAlgorithm,

    /// Encryption key length, for the bulk algorithm.
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,

    pub(crate) hkdf_algorithm: ring::hkdf::Algorithm,
}

impl PartialEq for SupportedCipherSuite {
    fn eq(&self, other: &SupportedCipherSuite) -> bool {
        self.suite == other.suite
    }
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        self.hkdf_algorithm.hmac_algorithm().digest_algorithm()
    }

    /// We have parameters and a verified public key in `kx_params`.
    /// Generate an ephemeral key, generate the shared secret, and
    /// return it and the public half in a `KeyExchangeResult`.
    pub fn do_client_kx(&self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::client_ecdhe(kx_params),
            _ => None,
        }
    }

    /// Start the KX process with the given group.  This generates
    /// the server's share, but we don't yet have the client's share.
    pub fn start_server_kx(&self, named_group: NamedGroup) -> Option<KeyExchange> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::start_ecdhe(named_group),
            _ => None,
        }
    }

    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self,
                              offered: &[SignatureScheme])
                              -> Vec<SignatureScheme> {
        let mut our_preference = vec![
            // Prefer the designated hash algorithm of this suite, for
            // security level consistency.
            SignatureScheme::make(self.sign, self.hash),

            // Then prefer the right sign algorithm, with the best hashes
            // first.
            SignatureScheme::make(self.sign, HashAlgorithm::SHA512),
            SignatureScheme::make(self.sign, HashAlgorithm::SHA384),
            SignatureScheme::make(self.sign, HashAlgorithm::SHA256)
        ];

        // For RSA, support PSS too
        if self.sign == SignatureAlgorithm::RSA {
            our_preference.push(SignatureScheme::RSA_PSS_SHA512);
            our_preference.push(SignatureScheme::RSA_PSS_SHA384);
            our_preference.push(SignatureScheme::RSA_PSS_SHA256);
        }

        our_preference.retain(|pref| offered.contains(pref));
        our_preference
    }

    /// Which AEAD algorithm to use for this suite.
    pub fn get_aead_alg(&self) -> &'static ring::aead::Algorithm {
        match self.bulk {
            BulkAlgorithm::AES_128_GCM => &ring::aead::AES_128_GCM,
            BulkAlgorithm::AES_256_GCM => &ring::aead::AES_256_GCM,
            BulkAlgorithm::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    /// Length of key block that needs to be output by the key
    /// derivation phase for this suite.
    pub fn key_block_len(&self) -> usize {
        (self.enc_key_len + self.fixed_iv_len) * 2 + self.explicit_nonce_len
    }

    /// Return true if this suite is usable for TLS `version`.
    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => self.sign == SignatureAlgorithm::Anonymous,
            ProtocolVersion::TLSv1_2 => self.sign != SignatureAlgorithm::Anonymous,
            _ => false,
        }
    }

    /// Can a session using suite self resume using suite new_suite?
    pub fn can_resume_to(&self, new_suite: &SupportedCipherSuite) -> bool {
        if self.usable_for_version(ProtocolVersion::TLSv1_3) &&
            new_suite.usable_for_version(ProtocolVersion::TLSv1_3) {
            // TLS1.3 actually specifies requirements here: suites are compatible
            // for resumption if they have the same KDF hash
            self.hash == new_suite.hash
        } else if self.usable_for_version(ProtocolVersion::TLSv1_2) &&
            new_suite.usable_for_version(ProtocolVersion::TLSv1_2) {
            // Previous versions don't specify any constraint, so we don't
            // resume between suites to avoid bad interactions.
            self.suite == new_suite.suite
        } else {
            // Suites for different versions definitely can't resume!
            false
        }
    }
}

pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: SignatureAlgorithm::ECDSA,
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    };

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: SignatureAlgorithm::RSA,
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    };

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::RSA,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::RSA,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
};

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::ECDSA,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::ECDSA,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
};

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::CHACHA20_POLY1305,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
};

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: [&SupportedCipherSuite; 9] =
    [// TLS1.3 suites
     &TLS13_CHACHA20_POLY1305_SHA256,
     &TLS13_AES_256_GCM_SHA384,
     &TLS13_AES_128_GCM_SHA256,

     // TLS1.2 suites
     &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
     &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
     &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(client_suites: &[CipherSuite],
                                            server_suites: &[&'static SupportedCipherSuite])
                                            -> Option<&'static SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites.iter().find(|x| *client_suite == x.suite) {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(client_suites: &[CipherSuite],
                                            server_suites: &[&'static SupportedCipherSuite])
                                            -> Option<&'static SupportedCipherSuite> {
    if let Some(selected) = server_suites.iter().find(|x| client_suites.contains(&x.suite)) {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(all: &[&'static SupportedCipherSuite],
                           sigalg: SignatureAlgorithm)
                           -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.sign == SignatureAlgorithm::Anonymous || suite.sign == sigalg)
        .cloned()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(all: &[&'static SupportedCipherSuite],
                            version: ProtocolVersion)
                            -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_version(version))
        .cloned()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub fn compatible_sigscheme_for_suites(sigscheme: SignatureScheme,
                                       common_suites: &[&'static SupportedCipherSuite]) -> bool {
    let sigalg = sigscheme.sign();

    common_suites.iter()
        .any(|&suite| suite.sign == SignatureAlgorithm::Anonymous || suite.sign == sigalg)
}

#[cfg(test)]
mod test {
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                          CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
        let server = vec![&super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                          &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];
        let chosen = super::choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(),
                   &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server_pref() {
        let client = vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                          CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
        let server = vec![&super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                          &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];
        let chosen = super::choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(),
                   &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }
}
