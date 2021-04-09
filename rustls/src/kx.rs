use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

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
    /// From a TLS1.2 client's point of view, start a key exchange: `kx_params` is the server's ServerECDHParams
    /// saying which group to use and the server's public key.  `supported` is the list of
    /// supported key exchange groups.
    pub fn client_ecdhe(
        kx_params: &[u8],
        supported: &[&'static SupportedKxGroup],
    ) -> Option<KeyExchangeResult> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ServerECDHParams::read(&mut rd)?;

        KeyExchange::choose(ecdh_params.curve_params.named_group, supported)
            .and_then(KeyExchange::start)
            .and_then(|kx| kx.complete(&ecdh_params.public.0))
    }

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
            ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &rng).unwrap();

        let pubkey = ours.compute_public_key().unwrap();

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

    fn decode_client_params(&self, kx_params: &[u8]) -> Option<ClientECDHParams> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ClientECDHParams::read(&mut rd).unwrap();
        if rd.any_left() {
            None
        } else {
            Some(ecdh_params)
        }
    }

    /// Complete the server-side computation, by decoding the client's ClientECDHParams
    /// and then using the contained public key to invoke complete().
    pub fn server_complete(self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        self.decode_client_params(kx_params)
            .and_then(|ecdh| self.complete(&ecdh.public.0))
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
