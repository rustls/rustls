use crypto::SupportedGroup;
use rustls::crypto;

pub struct KeyExchange {
    priv_key: x25519_dalek::EphemeralSecret,
    pub_key: x25519_dalek::PublicKey,
}

impl crypto::KeyExchange for KeyExchange {
    type SupportedGroup = X25519;

    fn start(
        name: rustls::NamedGroup,
        _: &[&'static Self::SupportedGroup],
    ) -> Result<Self, crypto::KeyExchangeError> {
        if name == rustls::NamedGroup::X25519 {
            let priv_key = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
            let pub_key = (&priv_key).into();
            Ok(KeyExchange { priv_key, pub_key })
        } else {
            Err(crypto::KeyExchangeError::UnsupportedGroup)
        }
    }

    fn complete<T>(
        self,
        peer: &[u8],
        f: impl FnOnce(&[u8]) -> Result<T, ()>,
    ) -> Result<T, rustls::Error> {
        let peer_array: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let their_pub = x25519_dalek::PublicKey::from(peer_array);
        let shared_secret = self.priv_key.diffie_hellman(&their_pub);
        f(shared_secret.as_bytes())
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }

    fn all_kx_groups() -> &'static [&'static Self::SupportedGroup] {
        &ALL_KX_GROUPS
    }
}

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedGroup for X25519 {
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

const ALL_KX_GROUPS: &[&X25519] = &[&X25519];
