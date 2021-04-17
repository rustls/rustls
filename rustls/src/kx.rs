use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::NamedGroup;

/// The result of a key exchange.  This has our public key,
/// and the agreed shared secret (also known as the "premaster secret"
/// in TLS1.0-era protocols, and "Z" in TLS1.3).
pub struct KeyExchangeResult {
    pub pubkey: ring::agreement::PublicKey,
    pub shared_secret: Vec<u8>,
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
pub struct KeyExchange {
    skxg: &'static SupportedKxGroup,
    privkey: ring::agreement::EphemeralPrivateKey,
    pub pubkey: ring::agreement::PublicKey,
}

impl KeyExchange {
    /// Choose a SupportedKxGroup by name, from a list of supported groups.
    pub fn choose(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Option<&'static SupportedKxGroup> {
        supported
            .iter()
            .find(|skxg| skxg.name == name)
            .cloned()
    }

    /// Start a key exchange, using the given SupportedKxGroup.
    ///
    /// This generates an ephemeral key pair and stores it in the returned KeyExchange object.
    pub fn start(skxg: &'static SupportedKxGroup) -> Option<KeyExchange> {
        let rng = ring::rand::SystemRandom::new();
        let ours =
            ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &rng).ok()?;

        let pubkey = ours.compute_public_key().ok()?;

        Some(KeyExchange {
            skxg,
            privkey: ours,
            pubkey,
        })
    }

    /// Return the group being used.
    pub fn group(&self) -> NamedGroup {
        self.skxg.name
    }

    pub fn decode_ecdh_params<T: Codec>(kx_params: &[u8]) -> Option<T> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = T::read(&mut rd)?;
        match rd.any_left() {
            false => Some(ecdh_params),
            true => None,
        }
    }

    /// Completes the key exchange, given the peer's public key.  The shared
    /// secret is returned as a KeyExchangeResult.
    pub fn complete(self, peer: &[u8]) -> Option<KeyExchangeResult> {
        let peer_key = ring::agreement::UnparsedPublicKey::new(self.skxg.agreement_algorithm, peer);
        let pubkey = self.pubkey;
        ring::agreement::agree_ephemeral(self.privkey, &peer_key, (), move |v| {
            Ok(KeyExchangeResult {
                pubkey,
                shared_secret: Vec::from(v),
            })
        })
        .ok()
    }
}

/// A key-exchange group supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
#[derive(Debug)]
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static ring::agreement::Algorithm,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = KeyExchange::start(&X25519).unwrap();
        let server_params = ServerECDHParams::new(X25519.name, key.pubkey.as_ref());
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);
        assert!(KeyExchange::decode_ecdh_params::<ServerECDHParams>(&server_buf).is_none());
    }

    #[test]
    fn client_ecdhe_invalid() {
        assert!(KeyExchange::decode_ecdh_params::<ClientECDHParams>(&[34]).is_none());
    }
}
