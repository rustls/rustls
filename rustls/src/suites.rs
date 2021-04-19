use crate::cipher;
use crate::msgs::enums::ProtocolVersion;
use crate::msgs::enums::{CipherSuite, SignatureAlgorithm, SignatureScheme};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::KeyExchangeAlgorithm;

use std::convert::TryFrom;
use std::fmt;

/// Bulk symmetric encryption scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    Aes128Gcm,

    /// AES with 256-bit keys in Galois counter mode.
    Aes256Gcm,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    Chacha20Poly1305,
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_CIPHERSUITES` array.
pub struct SupportedCipherSuite {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

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
    pub(crate) aead_algorithm: &'static ring::aead::Algorithm,

    tls12: Option<Tls12Parameters>,
}

pub(crate) struct Tls12Parameters {
    /// How to sign messages for authentication.
    pub sign: &'static [SignatureScheme],

    pub build_tls12_encrypter: cipher::BuildTls12Encrypter,
    pub build_tls12_decrypter: cipher::BuildTls12Decrypter,
}

#[derive(Clone, Copy)]
pub(crate) struct Tls12CipherSuite {
    scs: &'static SupportedCipherSuite,
    tls12: &'static Tls12Parameters,
}

impl TryFrom<&'static SupportedCipherSuite> for Tls12CipherSuite {
    type Error = VersionNotCompatibleError;

    fn try_from(scs: &'static SupportedCipherSuite) -> Result<Self, Self::Error> {
        scs.tls12
            .as_ref()
            .map(|tls12| Self { scs, tls12 })
            .ok_or(VersionNotCompatibleError(()))
    }
}

impl Tls12CipherSuite {
    #[inline]
    pub fn scs(&self) -> &'static SupportedCipherSuite {
        self.scs
    }

    #[inline]
    pub fn tls12(&self) -> &'static Tls12Parameters {
        self.tls12
    }

    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.tls12
            .sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VersionNotCompatibleError(());

impl PartialEq for SupportedCipherSuite {
    fn eq(&self, other: &SupportedCipherSuite) -> bool {
        self.suite == other.suite
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupportedCipherSuite")
            .field("suite", &self.suite)
            .field("bulk", &self.bulk)
            .field("fixed_iv_len", &self.fixed_iv_len)
            .field("explicit_nonce_len", &self.explicit_nonce_len)
            .finish()
    }
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        self.hmac_algorithm().digest_algorithm()
    }

    pub(crate) fn hmac_algorithm(&self) -> ring::hmac::Algorithm {
        self.hkdf_algorithm.hmac_algorithm()
    }


    /// Return true if this suite is usable for TLS `version`.
    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => self.tls12.is_none(),
            ProtocolVersion::TLSv1_2 => self.tls12.is_some(),
            _ => false,
        }
    }

    /// Return true if this suite is usable for a key only offering `sigalg`
    /// signatures.  This resolves to true for all TLS1.3 suites.
    pub fn usable_for_sigalg(&self, sigalg: SignatureAlgorithm) -> bool {
        match &self.tls12 {
            None => true, // no constraint expressed by ciphersuite (e.g., TLS1.3)
            Some(tls12) => tls12
                .sign
                .iter()
                .any(|scheme| scheme.sign() == sigalg),
        }
    }

    /// Can a session using suite self resume using suite new_suite?
    pub fn can_resume_to(&self, new_suite: &SupportedCipherSuite) -> bool {
        if self.usable_for_version(ProtocolVersion::TLSv1_3)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_3)
        {
            // TLS1.3 actually specifies requirements here: suites are compatible
            // for resumption if they have the same KDF hash
            self.get_hash() == new_suite.get_hash()
        } else if self.usable_for_version(ProtocolVersion::TLSv1_2)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_2)
        {
            // Previous versions don't specify any constraint, so we don't
            // resume between suites to avoid bad interactions.
            self.suite == new_suite.suite
        } else {
            // Suites for different versions definitely can't resume!
            false
        }
    }
}

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
        tls12: Some(Tls12Parameters {
            sign: TLS12_ECDSA_SCHEMES,
            build_tls12_encrypter: cipher::build_tls12_chacha_encrypter,
            build_tls12_decrypter: cipher::build_tls12_chacha_decrypter,
        }),
    };

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hkdf_algorithm: ring::hkdf::HKDF_SHA256,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
        tls12: Some(Tls12Parameters {
            sign: TLS12_RSA_SCHEMES,
            build_tls12_encrypter: cipher::build_tls12_chacha_encrypter,
            build_tls12_decrypter: cipher::build_tls12_chacha_decrypter,
        }),
    };

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    bulk: BulkAlgorithm::Aes128Gcm,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    tls12: Some(Tls12Parameters {
        sign: TLS12_RSA_SCHEMES,
        build_tls12_encrypter: cipher::build_tls12_gcm_encrypter,
        build_tls12_decrypter: cipher::build_tls12_gcm_decrypter,
    }),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    bulk: BulkAlgorithm::Aes256Gcm,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    tls12: Some(Tls12Parameters {
        sign: TLS12_RSA_SCHEMES,
        build_tls12_encrypter: cipher::build_tls12_gcm_encrypter,
        build_tls12_decrypter: cipher::build_tls12_gcm_decrypter,
    }),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    bulk: BulkAlgorithm::Aes128Gcm,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    tls12: Some(Tls12Parameters {
        sign: TLS12_ECDSA_SCHEMES,
        build_tls12_encrypter: cipher::build_tls12_gcm_encrypter,
        build_tls12_decrypter: cipher::build_tls12_gcm_decrypter,
    }),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    bulk: BulkAlgorithm::Aes256Gcm,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    tls12: Some(Tls12Parameters {
        sign: TLS12_ECDSA_SCHEMES,
        build_tls12_encrypter: cipher::build_tls12_gcm_encrypter,
        build_tls12_decrypter: cipher::build_tls12_gcm_decrypter,
    }),
};

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    bulk: BulkAlgorithm::Chacha20Poly1305,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    tls12: None,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::BulkOnly,
    bulk: BulkAlgorithm::Aes256Gcm,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
    aead_algorithm: &ring::aead::AES_256_GCM,
    tls12: None,
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    bulk: BulkAlgorithm::Aes128Gcm,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    aead_algorithm: &ring::aead::AES_128_GCM,
    tls12: None,
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: &[&SupportedCipherSuite] = &[
    // TLS1.3 suites
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The cipher suite configuration that an application should use by default.
///
/// This will be `ALL_CIPHERSUITES` sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHERSUITES: &[&SupportedCipherSuite] = ALL_CIPHERSUITES;

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites
            .iter()
            .find(|x| *client_suite == x.suite)
        {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(
    all: &[&'static SupportedCipherSuite],
    sigalg: SignatureAlgorithm,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_sigalg(sigalg))
        .cloned()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(
    all: &[&'static SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_version(version))
        .cloned()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[&'static SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.sign();
    common_suites
        .iter()
        .any(|&suite| suite.usable_for_sigalg(sigalg))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_pref_fails() {
        assert!(
            choose_ciphersuite_preferring_client(
                &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
                ALL_CIPHERSUITES
            )
            .is_none()
        );
        assert!(
            choose_ciphersuite_preferring_server(
                &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
                ALL_CIPHERSUITES
            )
            .is_none()
        );
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", ALL_CIPHERSUITES);
    }

    #[test]
    fn test_usable_for_version() {
        fn ok_tls13(scs: &SupportedCipherSuite) {
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        fn ok_tls12(scs: &SupportedCipherSuite) {
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        ok_tls13(&TLS13_CHACHA20_POLY1305_SHA256);
        ok_tls13(&TLS13_AES_256_GCM_SHA384);
        ok_tls13(&TLS13_AES_128_GCM_SHA256);

        ok_tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_can_resume_to() {
        assert!(TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_128_GCM_SHA256));
        assert!(!TLS13_CHACHA20_POLY1305_SHA256.can_resume_to(&TLS13_AES_256_GCM_SHA384));
        assert!(
            !TLS13_CHACHA20_POLY1305_SHA256
                .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        );
        assert!(
            !TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        );
        assert!(
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                .can_resume_to(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        );
    }
}
