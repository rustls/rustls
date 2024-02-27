#![allow(clippy::duplicate_mod)]

use crate::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;

use super::ring_like::agreement;
use super::ring_like::rand::SystemRandom;

use alloc::boxed::Box;
use core::fmt;

/// A key-exchange group supported by *ring*.
///
/// All possible instances of this class are provided by the library in
/// the [`ALL_KX_GROUPS`] array.
struct KxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static agreement::Algorithm,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let rng = SystemRandom::new();
        let priv_key = agreement::EphemeralPrivateKey::generate(self.agreement_algorithm, &rng)
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
    agreement_algorithm: &agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
};

/// A list of all the key exchange groups supported by rustls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1];

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
struct KeyExchange {
    name: NamedGroup,
    agreement_algorithm: &'static agreement::Algorithm,
    priv_key: agreement::EphemeralPrivateKey,
    pub_key: agreement::PublicKey,
}

impl ActiveKeyExchange for KeyExchange {
    /// Completes the key exchange, given the peer's public key.
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer_key = agreement::UnparsedPublicKey::new(self.agreement_algorithm, peer);
        super::ring_shim::agree_ephemeral(self.priv_key, &peer_key)
            .map_err(|_| PeerMisbehaved::InvalidKeyShare.into())
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

#[cfg(test)]
mod tests {
    use std::format;

    #[test]
    fn kxgroup_fmt_yields_name() {
        assert_eq!("X25519", format!("{:?}", super::X25519));
    }
}

#[cfg(bench)]
mod benchmarks {
    #[bench]
    fn bench_x25519(b: &mut test::Bencher) {
        bench_any(b, super::X25519);
    }

    #[bench]
    fn bench_ecdh_p256(b: &mut test::Bencher) {
        bench_any(b, super::SECP256R1);
    }

    #[bench]
    fn bench_ecdh_p384(b: &mut test::Bencher) {
        bench_any(b, super::SECP384R1);
    }

    fn bench_any(b: &mut test::Bencher, kxg: &dyn super::SupportedKxGroup) {
        b.iter(|| {
            let akx = kxg.start().unwrap();
            let pub_key = akx.pub_key().to_vec();
            test::black_box(akx.complete(&pub_key).unwrap());
        });
    }
}
