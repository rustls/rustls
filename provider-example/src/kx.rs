use alloc::boxed::Box;

use rustls::crypto::kx::{
    ActiveKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange, SupportedKxGroup,
};
use rustls::error::PeerMisbehaved;

pub(crate) struct KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let their_pub = x25519_dalek::PublicKey::from(peer_array);
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        Ok(SharedSecret::from(&shared_secret.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        X25519.name()
    }
}

pub(crate) const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519];

#[derive(Debug)]
pub(crate) struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<StartedKeyExchange, rustls::Error> {
        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        Ok(StartedKeyExchange::Single(Box::new(KeyExchange {
            pub_key: (&priv_key).into(),
            priv_key,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
