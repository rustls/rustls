//! Implement [RFC8701](https://tools.ietf.org/html/rfc8701)
//!
//! This module provides two implementations of RFC8701: one which effectively represents
//! disabling GREASE and another which chooses a single GREASE value for each supported field.

use crate::msgs::enums::CipherSuite;
use crate::rand;

/// Generate a GREASE cipher of the the form 0xRaRa, where R is random.
fn generate_grease_cipher_suite() -> CipherSuite {
    // Generate the lower byte of a u16 in the form 0xRa, where R is a uniformly random
    // four bits. Then, copy the lower byte to the upper byte to get 0xRaRa.
    let low: u16 = (rand::random_u8().overflowing_shl(4).0 | 0x0a) as u16;
    CipherSuite::Unknown(low | low << 8)
}

// Use the `grease` feature flag to determine whether GREASE is enabled by default.
#[cfg(not(feature = "grease"))]
pub type DefaultGreaseGenerator = NoGrease;
#[cfg(feature = "grease")]
pub type DefaultGreaseGenerator = BoringGrease;

/// Abstracts over multiple implementations of RFC8701, allowing these implementations to be
/// configured by the user.
pub trait GreaseGenerator: Send + Sync {
    /// Add zero or more GREASE ciphers to the list of cipher suites, returning the updated list.
    fn cipher_suites(&self, ciphers: Vec<CipherSuite>) -> Vec<CipherSuite>;
}

/// Do not add any GREASE values. Using this implementation effectively disables GREASE.
#[derive(Clone, Default)]
pub struct NoGrease {}

impl GreaseGenerator for NoGrease {
    fn cipher_suites(&self, ciphers: Vec<CipherSuite>) -> Vec<CipherSuite> {
        ciphers
    }
}

/// Mimics BoringSSL's GREASE implementation choices.
#[derive(Clone, Default)]
pub struct BoringGrease {}

impl GreaseGenerator for BoringGrease {
    /// Insert a single GREASE cipher value at the start of the cipher suites list.
    fn cipher_suites(&self, mut ciphers: Vec<CipherSuite>) -> Vec<CipherSuite> {
        ciphers.insert(0, generate_grease_cipher_suite());
        ciphers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_grease_does_not_modify_ciphers() {
        let ciphers = vec![CipherSuite::TLS_NULL_WITH_NULL_NULL];
        let grease = NoGrease::default();
        assert_eq!(grease.cipher_suites(ciphers.clone()), ciphers);
    }

    #[test]
    fn boring_grease_prepends_one_cipher() {
        let ciphers = vec![CipherSuite::TLS_NULL_WITH_NULL_NULL];
        let grease = BoringGrease::default();

        let modified_ciphers = grease.cipher_suites(ciphers.clone());
        assert_eq!(modified_ciphers.len(), 2);
        assert!(if let CipherSuite::Unknown(_) = modified_ciphers[0] {
            true
        } else {
            false
        });
        assert_eq!(modified_ciphers[1], ciphers[0]);
    }
}
