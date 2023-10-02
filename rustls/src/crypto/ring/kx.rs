use crate::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;

use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::SystemRandom;

use core::fmt;

/// A key-exchange group supported by *ring*.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
struct KxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static ring::agreement::Algorithm,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, GetRandomFailed> {
        let rng = SystemRandom::new();
        let priv_key = EphemeralPrivateKey::generate(self.agreement_algorithm, &rng)
            .map_err(|_| GetRandomFailed)?;

        let pub_key = priv_key
            .compute_public_key()
            .map_err(|_| GetRandomFailed)?;

        Ok(Box::new(KeyExchange {
            name: self.name,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

impl fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &ring::agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &ring::agreement::ECDH_P256,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &ring::agreement::ECDH_P384,
};

/// A list of all the key exchange groups supported by rustls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1];

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
#[derive(Debug)]
struct KeyExchange {
    name: NamedGroup,
    agreement_algorithm: &'static ring::agreement::Algorithm,
    priv_key: EphemeralPrivateKey,
    pub_key: ring::agreement::PublicKey,
}

impl ActiveKeyExchange for KeyExchange {
    /// Completes the key exchange, given the peer's public key.
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer_key = UnparsedPublicKey::new(self.agreement_algorithm, peer);
        agree_ephemeral(self.priv_key, &peer_key, (), |secret| {
            Ok(SharedSecret::from(secret))
        })
        .map_err(|()| PeerMisbehaved::InvalidKeyShare.into())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.name
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}
