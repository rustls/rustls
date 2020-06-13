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
pub type DefaultGreaseGenerator = SingleGreaseEntry;

/// Abstracts over multiple implementations of RFC8701, allowing these implementations to be
/// configured by the user.
pub trait GreaseGenerator: Send + Sync {
    /// Generate the initial ciphers of the ClientHello cipher list, choosing zero or more GREASE
    /// ciphers for inclusion.
    fn cipher_suites(&self) -> Vec<CipherSuite>;
}

/// Do not add any GREASE values. Using this implementation effectively disables GREASE.
#[derive(Clone, Default)]
pub struct NoGrease {}

impl GreaseGenerator for NoGrease {
    fn cipher_suites(&self) -> Vec<CipherSuite> {
        Vec::new()
    }
}

/// Prepend a single GREASE value before all other entries.
#[derive(Clone, Default)]
pub struct SingleGreaseEntry {}

impl GreaseGenerator for SingleGreaseEntry {
    fn cipher_suites(&self) -> Vec<CipherSuite> {
        vec![generate_grease_cipher_suite()]
    }
}
