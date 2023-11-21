use crate::crypto;
use crate::crypto::hash;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};

use alloc::vec::Vec;
use core::fmt;

pub(crate) mod key_schedule;

/// A TLS 1.3 cipher suite supported by rustls.
pub struct Tls13CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,

    /// How to complete HKDF with the suite's hash function.
    ///
    /// If you have a HKDF implementation, you should directly implement the `crypto::tls13::Hkdf`
    /// trait (and associated).
    ///
    /// If not, you can implement the [`crypto::hmac::Hmac`] trait (and associated), and then use
    /// [`crypto::tls13::HkdfUsingHmac`].
    pub hkdf_provider: &'static dyn crypto::tls13::Hkdf,

    /// How to produce a [MessageDecrypter] or [MessageEncrypter]
    /// from raw key material.
    ///
    /// [MessageDecrypter]: crate::crypto::cipher::MessageDecrypter
    /// [MessageEncrypter]: crate::crypto::cipher::MessageEncrypter
    pub aead_alg: &'static dyn crypto::cipher::Tls13AeadAlgorithm,

    /// How to create QUIC header and record protection algorithms
    /// for this suite.
    ///
    /// Provide `None` to opt out of QUIC support for this suite.  It will
    /// not be offered in QUIC handshakes.
    pub quic: Option<&'static dyn crate::quic::Algorithm>,
}

impl Tls13CipherSuite {
    /// Can a session using suite self resume from suite prev?
    pub fn can_resume_from(&self, prev: &'static Self) -> Option<&'static Self> {
        (prev.common.hash_provider.algorithm() == self.common.hash_provider.algorithm())
            .then(|| prev)
    }
}

impl From<&'static Tls13CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        Self::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls13CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13CipherSuite")
            .field("suite", &self.common.suite)
            .finish()
    }
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_client_verify_message(handshake_hash: &hash::Output) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, client CertificateVerify\x00")
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_server_verify_message(handshake_hash: &hash::Output) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, server CertificateVerify\x00")
}

fn construct_verify_message(
    handshake_hash: &hash::Output,
    context_string_with_0: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash.as_ref());
    msg
}
