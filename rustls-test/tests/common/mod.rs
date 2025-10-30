#![allow(dead_code)]
#![allow(clippy::disallowed_types)]

use std::borrow::Cow;

use rustls::SupportedCipherSuite;
use rustls::crypto::CryptoProvider;

pub fn provider_with_one_suite(
    provider: &CryptoProvider,
    suite: SupportedCipherSuite,
) -> CryptoProvider {
    provider_with_suites(provider, &[suite])
}

pub fn provider_with_suites(
    provider: &CryptoProvider,
    suites: &[SupportedCipherSuite],
) -> CryptoProvider {
    let mut tls12_cipher_suites = vec![];
    let mut tls13_cipher_suites = vec![];

    for suite in suites {
        match suite {
            SupportedCipherSuite::Tls12(suite) => {
                tls12_cipher_suites.push(*suite);
            }
            SupportedCipherSuite::Tls13(suite) => {
                tls13_cipher_suites.push(*suite);
            }
            _ => unreachable!(),
        }
    }
    CryptoProvider {
        tls12_cipher_suites: Cow::Owned(tls12_cipher_suites),
        tls13_cipher_suites: Cow::Owned(tls13_cipher_suites),
        ..provider.clone()
    }
}
