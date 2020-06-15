//! Implement [RFC8701](https://tools.ietf.org/html/rfc8701)
//!
//! This module provides two implementations of RFC8701: one which effectively represents
//! disabling GREASE and another which chooses a single GREASE value for each supported field.

use crate::msgs::base::Payload;
use crate::msgs::enums::{CipherSuite, ExtensionType};
use crate::msgs::handshake::{ClientExtension, UnknownExtension};
use crate::rand;

/// Generate a GREASE value of the form 0xRaRa, where R is random.
fn generate_grease_value() -> u16 {
    // Generate the lower byte of a u16 in the form 0xRa, where R is a uniformly random
    // four bits. Then, copy the lower byte to the upper byte to get 0xRaRa.
    let low: u16 = (rand::random_u8().overflowing_shl(4).0 | 0x0a) as u16;
    low | low << 8
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

    /// Add zero or more GREASE ciphers to the list of cipher values, returning the updated list.
    ///
    /// Implementations must preserve the property that the PSK extension is in the final position
    /// of the list. This extension is required to always be last.
    fn client_extensions(&self, extensions: Vec<ClientExtension>) -> Vec<ClientExtension>;
}

/// Do not add any GREASE values. Using this implementation effectively disables GREASE.
#[derive(Clone, Default)]
pub struct NoGrease {}

impl GreaseGenerator for NoGrease {
    fn cipher_suites(&self, ciphers: Vec<CipherSuite>) -> Vec<CipherSuite> {
        ciphers
    }

    fn client_extensions(&self, extensions: Vec<ClientExtension>) -> Vec<ClientExtension> {
        extensions
    }
}

/// Mimics BoringSSL's GREASE implementation choices.
#[derive(Clone, Default)]
pub struct BoringGrease {}

impl GreaseGenerator for BoringGrease {
    /// Insert a single GREASE cipher value at the start of the cipher suites list.
    fn cipher_suites(&self, mut ciphers: Vec<CipherSuite>) -> Vec<CipherSuite> {
        ciphers.insert(0, CipherSuite::Unknown(generate_grease_value()));
        ciphers
    }

    /// Insert an empty GREASE extension at the start of the extensions list. Insert a non-empty
    /// GREASE extension at the end of the extensions list.
    ///
    /// The chosen values of this implementation are not uniformly random.
    fn client_extensions(&self, mut extensions: Vec<ClientExtension>) -> Vec<ClientExtension> {
        let ext1 = generate_grease_value();
        let mut ext2 = generate_grease_value();

        // Duplicate extensions are now allowed. BoringSSL handles this by XORing the second
        // extension by a constant to achieve a unique GREASE value.
        // This has the advantage of being easy to compute, but the disadvantage of not being
        // uniformly random.
        if ext1 == ext2 {
            ext2 ^= 0x1010;
        }

        extensions.insert(
            0,
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::Unknown(ext1),
                payload: Payload(Vec::new()),
            }),
        );

        let non_empty_extension = ClientExtension::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(ext2),
            payload: Payload(vec![0]),
        });
        if let Some(ClientExtension::PresharedKey(_)) = extensions.last() {
            extensions.insert(extensions.len() - 1, non_empty_extension)
        } else {
            extensions.push(non_empty_extension)
        }

        extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::{PresharedKeyBinders, PresharedKeyIdentities, PresharedKeyOffer};

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

    #[test]
    fn no_grease_does_not_modify_extensions() {
        let extensions = vec![ClientExtension::EarlyData];
        let grease = NoGrease::default();
        assert_eq!(grease.client_extensions(extensions.clone()).len(), 1);
    }

    #[test]
    fn boring_grease_prepends_empty_ext_appends_nonempty_ext() {
        let extensions = vec![ClientExtension::EarlyData];
        let grease = BoringGrease::default();

        let modified_extensions = grease.client_extensions(extensions.clone());
        assert_eq!(modified_extensions.len(), 3);
        assert!(
            if let ClientExtension::Unknown(_) = modified_extensions[0] {
                true
            } else {
                false
            }
        );
        assert!(
            if let ClientExtension::Unknown(_) = modified_extensions[2] {
                true
            } else {
                false
            }
        );
    }

    #[test]
    fn boring_grease_preserves_psk_placement() {
        let extensions = vec![
            ClientExtension::EarlyData,
            ClientExtension::PresharedKey(PresharedKeyOffer {
                identities: PresharedKeyIdentities::default(),
                binders: PresharedKeyBinders::default(),
            }),
        ];
        let grease = BoringGrease::default();

        let modified_extensions = grease.client_extensions(extensions.clone());
        assert_eq!(modified_extensions.len(), 4);
        assert!(
            if let ClientExtension::Unknown(_) = modified_extensions[0] {
                true
            } else {
                false
            }
        );
        assert!(if let ClientExtension::EarlyData = modified_extensions[1] {
            true
        } else {
            false
        });
        assert!(
            if let ClientExtension::Unknown(_) = modified_extensions[2] {
                true
            } else {
                false
            }
        );
        assert!(
            if let ClientExtension::PresharedKey(_) = modified_extensions[3] {
                true
            } else {
                false
            },
            "PresharedKey extension was not the final extension"
        );
    }
}
