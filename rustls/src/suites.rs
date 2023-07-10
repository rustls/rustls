use core::fmt;

use crate::crypto;
use crate::enums::{CipherSuite, ProtocolVersion, SignatureAlgorithm, SignatureScheme};
#[cfg(feature = "tls12")]
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
#[cfg(feature = "tls12")]
use crate::versions::TLS12;
use crate::versions::{SupportedProtocolVersion, TLS13};

/// Common state for cipher suites (both for TLS 1.2 and TLS 1.3)
pub struct CipherSuiteCommon {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// Which hash function the suite uses.
    pub hash_provider: &'static dyn crypto::hash::Hash,
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this type are provided by the library in
/// the [`crate::ALL_CIPHER_SUITES`] array.
#[derive(Clone, Copy, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 cipher suite
    #[cfg(feature = "tls12")]
    Tls12(&'static Tls12CipherSuite),
    /// A TLS 1.3 cipher suite
    Tls13(&'static Tls13CipherSuite),
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite().fmt(f)
    }
}

impl SupportedCipherSuite {
    /// The cipher suite's identifier
    pub fn suite(&self) -> CipherSuite {
        self.common().suite
    }

    /// The hash function the ciphersuite uses.
    pub(crate) fn hash_provider(&self) -> &'static dyn crypto::hash::Hash {
        self.common().hash_provider
    }

    pub(crate) fn common(&self) -> &CipherSuiteCommon {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => &inner.common,
            Self::Tls13(inner) => &inner.common,
        }
    }

    #[cfg(any(test, feature = "quic"))]
    /// Return the inner `Tls13CipherSuite` for this suite, if it is a TLS1.3 suite.
    pub fn tls13(&self) -> Option<&'static Tls13CipherSuite> {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => None,
            Self::Tls13(inner) => Some(inner),
        }
    }

    /// Return supported protocol version for the cipher suite.
    pub fn version(&self) -> &'static SupportedProtocolVersion {
        match self {
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => &TLS12,
            Self::Tls13(_) => &TLS13,
        }
    }

    /// Return true if this suite is usable for a key only offering `sig_alg`
    /// signatures.  This resolves to true for all TLS1.3 suites.
    pub fn usable_for_signature_algorithm(&self, _sig_alg: SignatureAlgorithm) -> bool {
        match self {
            Self::Tls13(_) => true, // no constraint expressed by ciphersuite (e.g., TLS1.3)
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => inner
                .sign
                .iter()
                .any(|scheme| scheme.sign() == _sig_alg),
        }
    }
}

// These both O(N^2)!
pub(crate) fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites
            .iter()
            .find(|x| *client_suite == x.suite())
        {
            return Some(*selected);
        }
    }

    None
}

pub(crate) fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite()))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub(crate) fn reduce_given_sigalg(
    all: &[SupportedCipherSuite],
    sigalg: SignatureAlgorithm,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_signature_algorithm(sigalg))
        .copied()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub(crate) fn reduce_given_version(
    all: &[SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.version().version == version)
        .copied()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub(crate) fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.sign();
    common_suites
        .iter()
        .any(|&suite| suite.usable_for_signature_algorithm(sigalg))
}

/// Secrets for transmitting/receiving data over a TLS session.
///
/// After performing a handshake with rustls, these secrets can be extracted
/// to configure kTLS for a socket, and have the kernel take over encryption
/// and/or decryption.
#[cfg(feature = "secret_extraction")]
pub struct ExtractedSecrets {
    /// sequence number and secrets for the "tx" (transmit) direction
    pub tx: (u64, ConnectionTrafficSecrets),

    /// sequence number and secrets for the "rx" (receive) direction
    pub rx: (u64, ConnectionTrafficSecrets),
}

/// [ExtractedSecrets] minus the sequence numbers
#[cfg(feature = "secret_extraction")]
pub(crate) struct PartiallyExtractedSecrets {
    /// secrets for the "tx" (transmit) direction
    pub(crate) tx: ConnectionTrafficSecrets,

    /// secrets for the "rx" (receive) direction
    pub(crate) rx: ConnectionTrafficSecrets,
}

/// Secrets used to encrypt/decrypt data in a TLS session.
///
/// These can be used to configure kTLS for a socket in one direction.
/// The only other piece of information needed is the sequence number,
/// which is in [ExtractedSecrets].
#[cfg(feature = "secret_extraction")]
#[non_exhaustive]
pub enum ConnectionTrafficSecrets {
    /// Secrets for the AES_128_GCM AEAD algorithm
    Aes128Gcm {
        /// key (16 bytes)
        key: [u8; 16],
        /// salt (4 bytes)
        salt: [u8; 4],
        /// initialization vector (8 bytes, chopped from key block)
        iv: [u8; 8],
    },

    /// Secrets for the AES_256_GCM AEAD algorithm
    Aes256Gcm {
        /// key (32 bytes)
        key: [u8; 32],
        /// salt (4 bytes)
        salt: [u8; 4],
        /// initialization vector (8 bytes, chopped from key block)
        iv: [u8; 8],
    },

    /// Secrets for the CHACHA20_POLY1305 AEAD algorithm
    Chacha20Poly1305 {
        /// key (32 bytes)
        key: [u8; 32],
        /// initialization vector (12 bytes)
        iv: [u8; 12],
    },
}

#[cfg(all(test, feature = "ring"))]
mod test {
    use super::crypto::ring::tls13::*;
    use super::*;
    use crate::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ];
        let server = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];
        let chosen = choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ];
        let server = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];
        let chosen = choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_pref_fails() {
        assert!(choose_ciphersuite_preferring_client(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            crate::ALL_CIPHER_SUITES
        )
        .is_none());
        assert!(choose_ciphersuite_preferring_server(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            crate::ALL_CIPHER_SUITES
        )
        .is_none());
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", crate::ALL_CIPHER_SUITES);
    }

    #[test]
    fn test_can_resume_to() {
        assert!(TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .can_resume_from(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL)
            .is_some());
        assert!(TLS13_AES_256_GCM_SHA384
            .tls13()
            .unwrap()
            .can_resume_from(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL)
            .is_none());
    }
}
