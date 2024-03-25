use crate::common_state::Protocol;
use crate::crypto;
use crate::crypto::cipher::{AeadKey, Iv};
use crate::enums::{CipherSuite, ProtocolVersion, SignatureAlgorithm, SignatureScheme};
#[cfg(feature = "tls12")]
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
#[cfg(feature = "tls12")]
use crate::versions::TLS12;
use crate::versions::{SupportedProtocolVersion, TLS13};

use alloc::vec::Vec;
use core::fmt;

/// Common state for cipher suites (both for TLS 1.2 and TLS 1.3)
pub struct CipherSuiteCommon {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// Which hash function the suite uses.
    pub hash_provider: &'static dyn crypto::hash::Hash,

    /// Number of messages that can be safely encrypted with a single key of this type
    ///
    /// Once a `MessageEncrypter` produced for this suite has encrypted more than
    /// `confidentiality_limit` messages, an attacker gains an advantage in distinguishing it
    /// from an ideal pseudorandom permutation (PRP).
    ///
    /// This is to be set on the assumption that messages are maximally sized --
    /// at least 2 ** 14 bytes for TCP-TLS and 2 ** 16 for QUIC.
    pub confidentiality_limit: u64,

    /// Number of messages that can be safely decrypted with a single key of this type
    ///
    /// Once a `MessageDecrypter` produced for this suite has failed to decrypt `integrity_limit`
    /// messages, an attacker gains an advantage in forging messages.
    ///
    /// This is not relevant for TLS over TCP (which is implemented in this crate)
    /// because a single failed decryption is fatal to the connection.  However,
    /// this quantity is used by QUIC.
    pub integrity_limit: u64,
}

/// A cipher suite supported by rustls.
///
/// This type carries both configuration and implementation. Compare with
/// [`CipherSuite`], which carries solely a cipher suite identifier.
#[derive(Clone, Copy, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 cipher suite
    #[cfg(feature = "tls12")]
    Tls12(&'static Tls12CipherSuite),
    /// A TLS 1.3 cipher suite
    Tls13(&'static Tls13CipherSuite),
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

    /// Return true if this suite is usable for the given [`Protocol`].
    ///
    /// All cipher suites are usable for TCP-TLS.  Only TLS1.3 suites
    /// with `Tls13CipherSuite::quic` provided are usable for QUIC.
    pub(crate) fn usable_for_protocol(&self, proto: Protocol) -> bool {
        match proto {
            Protocol::Tcp => true,
            Protocol::Quic => self
                .tls13()
                .and_then(|cs| cs.quic)
                .is_some(),
        }
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite().fmt(f)
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
pub(crate) fn reduce_given_version_and_protocol(
    all: &[SupportedCipherSuite],
    version: ProtocolVersion,
    proto: Protocol,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.version().version == version && suite.usable_for_protocol(proto))
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
pub struct ExtractedSecrets {
    /// sequence number and secrets for the "tx" (transmit) direction
    pub tx: (u64, ConnectionTrafficSecrets),

    /// sequence number and secrets for the "rx" (receive) direction
    pub rx: (u64, ConnectionTrafficSecrets),
}

/// [ExtractedSecrets] minus the sequence numbers
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
#[non_exhaustive]
pub enum ConnectionTrafficSecrets {
    /// Secrets for the AES_128_GCM AEAD algorithm
    Aes128Gcm {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },

    /// Secrets for the AES_256_GCM AEAD algorithm
    Aes256Gcm {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },

    /// Secrets for the CHACHA20_POLY1305 AEAD algorithm
    Chacha20Poly1305 {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },
}

#[cfg(all(test, any(feature = "ring", feature = "aws_lc_rs")))]
mod tests {
    use super::*;
    use crate::test_provider::tls13::*;
    use std::{println, vec};

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
            crate::test_provider::ALL_CIPHER_SUITES
        )
        .is_none());
        assert!(choose_ciphersuite_preferring_server(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            crate::test_provider::ALL_CIPHER_SUITES
        )
        .is_none());
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", crate::test_provider::ALL_CIPHER_SUITES);
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
