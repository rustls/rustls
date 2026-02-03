#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::borrow::Cow;
use alloc::boxed::Box;
#[cfg(feature = "std")]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use core::error::Error as StdError;
#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use core::time::Duration;

#[cfg(feature = "std")]
use rustls::TicketRotator;
use rustls::crypto::kx::KeyExchangeAlgorithm;
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    CipherSuite, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
    SignatureScheme, SigningKey, TicketProducer, TicketerFactory,
};
use rustls::error::{Error, OtherError};
use rustls::pki_types::{FipsStatus, PrivateKeyDer};
use rustls::version::{TLS12_VERSION, TLS13_VERSION};
use rustls::{Tls12CipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hmac;
pub mod hpke;
mod kx;
mod sign;
#[cfg(feature = "std")]
mod ticketer;
#[cfg(feature = "std")]
use ticketer::AeadTicketer;
mod verify;
pub use verify::SUPPORTED_SIG_ALGS;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(ALL_TLS12_CIPHER_SUITES),
        tls13_cipher_suites: Cow::Borrowed(ALL_TLS13_CIPHER_SUITES),
        kx_groups: Cow::Borrowed(kx::ALL_KX_GROUPS),
        secure_random: &Provider,
        key_provider: &Provider,
        ticketer_factory: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        let PrivateKeyDer::Pkcs8(key_der) = key_der else {
            return Err(Error::General(
                "only PKCS#8 private keys are supported".into(),
            ));
        };

        Ok(Box::new(
            sign::EcdsaSigningKeyP256::try_from(key_der).map_err(other_err)?,
        ))
    }
}

impl TicketerFactory for Provider {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        #[cfg(feature = "std")]
        {
            Ok(Arc::new(TicketRotator::new(SIX_HOURS, AeadTicketer::new)?))
        }
        #[cfg(not(feature = "std"))]
        {
            Err(Error::General(
                "Provider::ticketer() relies on std-only RwLock via TicketRotator".into(),
            ))
        }
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated
    }
}

static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] =
    &[TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256];

static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[TLS13_CHACHA20_POLY1305_SHA256];

pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Sha256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &HkdfUsingHmac(&hmac::Sha256Hmac),
    aead_alg: &aead::Chacha20Poly1305,
    quic: None,
};

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Sha256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &[
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ],
    prf_provider: &PrfUsingHmac(&hmac::Sha256Hmac),
    aead_alg: &aead::Chacha20Poly1305,
};

/// While rustls supports `core::error::Error`, hpke-rs's support is conditional on `std`.
#[cfg(feature = "std")]
fn other_err(err: impl core::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(OtherError::new(err))
}

/// Since hpke-rs does not implement `core::error::Error` for `no_std`, we fall back to
/// using a string representation of the error.
#[cfg(not(feature = "std"))]
fn other_err(error: impl fmt::Display + Send + Sync + 'static) -> Error {
    struct DisplayError<T: fmt::Display>(T);

    impl<T: fmt::Display> StdError for DisplayError<T> {}

    impl<T: fmt::Display> fmt::Display for DisplayError<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl<T: fmt::Display> fmt::Debug for DisplayError<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.0, f)
        }
    }

    Error::Other(OtherError::new(DisplayError(error)))
}

#[cfg(feature = "std")]
const SIX_HOURS: Duration = Duration::from_secs(6 * 60 * 60);
