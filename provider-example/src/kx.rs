use alloc::boxed::Box;

use crypto::SupportedKxGroup;
use rustls::crypto;
use rustls::ffdhe_groups::FfdheGroup;

pub struct KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let their_pub = x25519_dalek::PublicKey::from(peer_array);
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        Ok(crypto::SharedSecret::from(&shared_secret.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519 as &dyn SupportedKxGroup];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        Ok(Box::new(KeyExchange {
            pub_key: (&priv_key).into(),
            priv_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}
