#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;

use pki_types::PrivateKeyDer;
use rustls::crypto::CryptoProvider;

mod aead;
mod hash;
mod hmac;
#[cfg(feature = "std")]
mod hpke;
mod kx;
mod sign;
mod verify;

#[cfg(feature = "std")]
pub use hpke::HPKE_PROVIDER;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let key = sign::EcdsaSigningKeyP256::try_from(key_der).map_err(|err| {
            #[cfg(feature = "std")]
            let err = rustls::OtherError(Arc::new(err));
            #[cfg(not(feature = "std"))]
            let err = rustls::Error::General(alloc::format!("{}", err));
            err
        })?;
        Ok(Arc::new(key))
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
    });
