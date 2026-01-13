use core::fmt;

use crate::common_state::Protocol;
use crate::crypto::cipher::{AeadKey, Iv};
use crate::crypto::kx::KeyExchangeAlgorithm;
use crate::crypto::{CipherSuite, SignatureScheme, hash};
use crate::enums::ProtocolVersion;
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;

/// Common state for cipher suites (both for TLS 1.2 and TLS 1.3)
#[expect(clippy::exhaustive_structs)]
pub struct CipherSuiteCommon {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// Which hash function the suite uses.
    pub hash_provider: &'static dyn hash::Hash,

    /// Number of TCP-TLS messages that can be safely encrypted with a single key of this type
    ///
    /// Once a `MessageEncrypter` produced for this suite has encrypted more than
    /// `confidentiality_limit` messages, an attacker gains an advantage in distinguishing it
    /// from an ideal pseudorandom permutation (PRP).
    ///
    /// This is to be set on the assumption that messages are maximally sized --
    /// each is 2<sup>14</sup> bytes. It **does not** consider confidentiality limits for
    /// QUIC connections - see the [`quic::PacketKey::confidentiality_limit`] field for
    /// this context.
    ///
    /// For AES-GCM implementations, this should be set to 2<sup>24</sup> to limit attack
    /// probability to one in 2<sup>60</sup>.  See [AEBounds] (Table 1) and [draft-irtf-aead-limits-08]:
    ///
    /// ```python
    /// >>> p = 2 ** -60
    /// >>> L = (2 ** 14 // 16) + 1
    /// >>> qlim = (math.sqrt(p) * (2 ** (129 // 2)) - 1) / (L + 1)
    /// >>> print(int(qlim).bit_length())
    /// 24
    /// ```
    /// [AEBounds]: https://eprint.iacr.org/2024/051.pdf
    /// [draft-irtf-aead-limits-08]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.1.1
    /// [`quic::PacketKey::confidentiality_limit`]: crate::quic::PacketKey::confidentiality_limit
    ///
    /// For chacha20-poly1305 implementations, this should be set to `u64::MAX`:
    /// see <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
    pub confidentiality_limit: u64,
}

impl CipherSuiteCommon {
    /// Return `true` if this is backed by a FIPS-approved implementation.
    ///
    /// This means all the constituent parts that do cryptography return `true` for `fips()`.
    pub fn fips(&self) -> bool {
        self.hash_provider.fips()
    }
}

/// A cipher suite supported by rustls.
///
/// This type carries both configuration and implementation. Compare with
/// [`CipherSuite`], which carries solely a cipher suite identifier.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 cipher suite
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
    pub(crate) fn hash_provider(&self) -> &'static dyn hash::Hash {
        self.common().hash_provider
    }

    pub(crate) fn common(&self) -> &CipherSuiteCommon {
        match self {
            Self::Tls12(inner) => &inner.common,
            Self::Tls13(inner) => &inner.common,
        }
    }

    /// Return true if this suite is usable for the given [`Protocol`].
    pub(crate) fn usable_for_protocol(&self, proto: Protocol) -> bool {
        match self {
            Self::Tls12(tls12) => tls12.usable_for_protocol(proto),
            Self::Tls13(tls13) => tls13.usable_for_protocol(proto),
        }
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite().fmt(f)
    }
}

pub(crate) trait Suite: fmt::Debug {
    fn client_handler(&self) -> &'static dyn crate::client::ClientHandler<Self>;

    fn server_handler(&self) -> &'static dyn crate::server::ServerHandler<Self>;

    fn usable_for_protocol(&self, proto: Protocol) -> bool;

    fn usable_for_signature_scheme(&self, _scheme: SignatureScheme) -> bool;

    fn usable_for_kx_algorithm(&self, _kxa: KeyExchangeAlgorithm) -> bool {
        true
    }

    fn suite(&self) -> CipherSuite {
        self.common().suite
    }

    fn common(&self) -> &CipherSuiteCommon;

    const VERSION: ProtocolVersion;
}

/// Secrets for transmitting/receiving data over a TLS session.
///
/// After performing a handshake with rustls, these secrets can be extracted
/// to configure kTLS for a socket, and have the kernel take over encryption
/// and/or decryption.
#[expect(clippy::exhaustive_structs)]
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

#[cfg(test)]
mod tests {
    use std::println;

    use super::SupportedCipherSuite;
    use crate::crypto::TEST_PROVIDER;

    #[test]
    fn test_scs_is_debug() {
        println!(
            "{:?}",
            SupportedCipherSuite::Tls13(
                TEST_PROVIDER
                    .tls13_cipher_suites
                    .first()
                    .unwrap()
            )
        );
    }
}
