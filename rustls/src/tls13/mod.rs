use core::fmt;

use pki_types::FipsStatus;

use crate::common_state::Protocol;
use crate::crypto::{self, SignatureScheme, hash};
use crate::enums::ProtocolVersion;
use crate::suites::{CipherSuiteCommon, Suite, SupportedCipherSuite};
use crate::version::Tls13Version;

pub(crate) mod key_schedule;

/// A TLS 1.3 cipher suite supported by rustls.
#[expect(clippy::exhaustive_structs)]
pub struct Tls13CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,

    /// The associated protocol version.
    ///
    /// This field should have the value [`rustls::version::TLS13_VERSION`].
    ///
    /// This value contains references to the TLS1.3 protocol handling code.
    /// This means that a program that does not contain any `Tls13CipherSuite`
    /// values also does not contain any reference to the TLS1.3 protocol handling
    /// code, and the linker can remove it.
    ///
    /// [`rustls::version::TLS13_VERSION`]: crate::version::TLS13_VERSION
    pub protocol_version: &'static Tls13Version,

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
            .then_some(prev)
    }

    /// Return the FIPS validation status of this implementation.
    ///
    /// This is the combination of the constituent parts of the cipher suite.
    pub fn fips(&self) -> FipsStatus {
        let Self {
            common,
            protocol_version: _,
            hkdf_provider,
            aead_alg,
            quic,
        } = self;

        let mut status = Ord::min(common.fips(), hkdf_provider.fips());
        status = Ord::min(status, aead_alg.fips());
        match quic {
            Some(quic) => Ord::min(status, quic.fips()),
            None => status,
        }
    }

    /// Returns a `quic::Suite` for the ciphersuite, if supported.
    pub fn quic_suite(&'static self) -> Option<crate::quic::Suite> {
        self.quic
            .map(|quic| crate::quic::Suite { suite: self, quic })
    }
}

impl Suite for Tls13CipherSuite {
    fn client_handler(&self) -> &'static dyn crate::client::ClientHandler<Self> {
        self.protocol_version.client
    }

    fn server_handler(&self) -> &'static dyn crate::server::ServerHandler<Self> {
        self.protocol_version.server
    }

    /// Does this suite support the `proto` protocol?
    ///
    /// All TLS1.3 suites support TCP-TLS. QUIC support is conditional on `quic` slot.
    fn usable_for_protocol(&self, proto: Protocol) -> bool {
        match proto {
            Protocol::Tcp => true,
            Protocol::Quic(_) => self.quic.is_some(),
        }
    }

    fn usable_for_signature_scheme(&self, scheme: SignatureScheme) -> bool {
        scheme.supported_in_tls13()
    }

    fn common(&self) -> &CipherSuiteCommon {
        &self.common
    }

    const VERSION: ProtocolVersion = ProtocolVersion::TLSv1_3;
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
            .finish_non_exhaustive()
    }
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_client_verify_message(handshake_hash: &hash::Output) -> VerifyMessage {
    VerifyMessage::new(handshake_hash, CLIENT_CONSTANT)
}

/// Constructs the signature message specified in section 4.4.3 of RFC8446.
pub(crate) fn construct_server_verify_message(handshake_hash: &hash::Output) -> VerifyMessage {
    VerifyMessage::new(handshake_hash, SERVER_CONSTANT)
}

pub(crate) struct VerifyMessage {
    buf: [u8; MAX_VERIFY_MSG],
    used: usize,
}

impl VerifyMessage {
    fn new(handshake_hash: &hash::Output, context_string_with_0: &[u8; 34]) -> Self {
        let used = 64 + context_string_with_0.len() + handshake_hash.as_ref().len();
        let mut buf = [0x20u8; MAX_VERIFY_MSG];

        let (_spaces, context) = buf.split_at_mut(64);
        let (context, hash) = context.split_at_mut(34);
        context.copy_from_slice(context_string_with_0);
        hash[..handshake_hash.as_ref().len()].copy_from_slice(handshake_hash.as_ref());

        Self { buf, used }
    }
}

impl AsRef<[u8]> for VerifyMessage {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

const SERVER_CONSTANT: &[u8; 34] = b"TLS 1.3, server CertificateVerify\x00";
const CLIENT_CONSTANT: &[u8; 34] = b"TLS 1.3, client CertificateVerify\x00";
const MAX_VERIFY_MSG: usize = 64 + CLIENT_CONSTANT.len() + hash::Output::MAX_LEN;

#[cfg(test)]
mod tests {
    use crate::crypto::{CipherSuite, TEST_PROVIDER, tls13_suite};

    #[test]
    fn test_can_resume_to() {
        let Some(cha_poly) = TEST_PROVIDER
            .tls13_cipher_suites
            .iter()
            .find(|cs| cs.common.suite == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        else {
            return;
        };

        let aes_128_gcm = tls13_suite(CipherSuite::TLS13_AES_128_GCM_SHA256, &TEST_PROVIDER);
        assert!(
            aes_128_gcm
                .can_resume_from(cha_poly)
                .is_some()
        );

        let aes_256_gcm = tls13_suite(CipherSuite::TLS13_AES_256_GCM_SHA384, &TEST_PROVIDER);
        assert!(
            aes_256_gcm
                .can_resume_from(cha_poly)
                .is_none()
        );
    }
}
