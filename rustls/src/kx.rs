use std::fmt;

use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;

use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::SystemRandom;

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub(crate) struct KeyExchange {
    skxg: &'static SupportedKxGroup,
    privkey: EphemeralPrivateKey,
    pubkey: ring::agreement::PublicKey,
}

impl KeyExchange {
    pub(crate) fn choose(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Result<Self, KeyExchangeError> {
        let skxg = match supported
            .iter()
            .find(|skxg| skxg.name == name)
        {
            Some(skxg) => skxg,
            None => return Err(KeyExchangeError::UnsupportedGroup),
        };

        Self::start(skxg).map_err(KeyExchangeError::KeyExchangeFailed)
    }

    pub(crate) fn start(skxg: &'static SupportedKxGroup) -> Result<Self, GetRandomFailed> {
        let rng = SystemRandom::new();
        let privkey = match EphemeralPrivateKey::generate(skxg.agreement_algorithm, &rng) {
            Ok(privkey) => privkey,
            Err(_) => return Err(GetRandomFailed),
        };

        let pubkey = match privkey.compute_public_key() {
            Ok(pubkey) => pubkey,
            Err(_) => return Err(GetRandomFailed),
        };

        Ok(Self {
            skxg,
            privkey,
            pubkey,
        })
    }

    /// Return the group being used.
    pub(crate) fn group(&self) -> NamedGroup {
        self.skxg.name
    }

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    pub(crate) fn complete<T>(
        self,
        peer: &[u8],
        f: impl FnOnce(&[u8]) -> Result<T, ()>,
    ) -> Result<T, Error> {
        let peer_key = UnparsedPublicKey::new(self.skxg.agreement_algorithm, peer);
        agree_ephemeral(self.privkey, &peer_key, (), f)
            .map_err(|()| PeerMisbehaved::InvalidKeyShare.into())
    }

    /// Return the public key being used.
    pub(crate) fn pub_key(&self) -> &[u8] {
        self.pubkey.as_ref()
    }
}

pub(crate) enum KeyExchangeError {
    UnsupportedGroup,
    KeyExchangeFailed(GetRandomFailed),
}

/// A key-exchange group supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static ring::agreement::Algorithm,
}

impl fmt::Debug for SupportedKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &ring::agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &ring::agreement::ECDH_P256,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &ring::agreement::ECDH_P384,
};

/// A list of all the key exchange groups supported by rustls.
pub static ALL_KX_GROUPS: [&SupportedKxGroup; 3] = [&X25519, &SECP256R1, &SECP384R1];
