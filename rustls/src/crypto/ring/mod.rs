use crate::crypto::{CryptoProvider, KeyExchangeError, SupportedGroup};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;
use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;

use ring::aead;
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::{SecureRandom, SystemRandom};

use alloc::sync::Arc;
use core::fmt;

pub(crate) mod hash;
pub(crate) mod hmac;

/// Default crypto provider.
#[derive(Debug)]
pub struct Ring;

impl CryptoProvider for Ring {
    type KeyExchange = KeyExchange;

    fn fill_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
#[derive(Debug)]
pub struct KeyExchange {
    group: &'static SupportedKxGroup,
    priv_key: EphemeralPrivateKey,
    pub_key: ring::agreement::PublicKey,
}

impl super::KeyExchange for KeyExchange {
    type SupportedGroup = SupportedKxGroup;

    fn start(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Result<Self, KeyExchangeError> {
        let group = match supported
            .iter()
            .find(|group| group.name == name)
        {
            Some(group) => group,
            None => return Err(KeyExchangeError::UnsupportedGroup),
        };

        let rng = SystemRandom::new();
        let priv_key = match EphemeralPrivateKey::generate(group.agreement_algorithm, &rng) {
            Ok(priv_key) => priv_key,
            Err(_) => return Err(KeyExchangeError::GetRandomFailed),
        };

        let pub_key = match priv_key.compute_public_key() {
            Ok(pub_key) => pub_key,
            Err(_) => return Err(KeyExchangeError::GetRandomFailed),
        };

        Ok(Self {
            group,
            priv_key,
            pub_key,
        })
    }

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    fn complete<T>(self, peer: &[u8], f: impl FnOnce(&[u8]) -> Result<T, ()>) -> Result<T, Error> {
        let peer_key = UnparsedPublicKey::new(self.group.agreement_algorithm, peer);
        agree_ephemeral(self.priv_key, &peer_key, (), f)
            .map_err(|()| PeerMisbehaved::InvalidKeyShare.into())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.group.name
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Return all supported key exchange groups.
    fn all_kx_groups() -> &'static [&'static Self::SupportedGroup] {
        &ALL_KX_GROUPS
    }
}

/// A key-exchange group supported by *ring*.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static ring::agreement::Algorithm,
}

impl SupportedGroup for SupportedKxGroup {
    fn name(&self) -> NamedGroup {
        self.name
    }
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

/// All defined key exchange groups supported by *ring* appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
pub mod kx_group {
    pub use crate::crypto::ring::SECP256R1;
    pub use crate::crypto::ring::SECP384R1;
    pub use crate::crypto::ring::X25519;
}

/// A concrete, safe ticket creation mechanism.
pub struct Ticketer {}

impl Ticketer {
    /// Make the recommended Ticketer.  This produces tickets
    /// with a 12 hour life and randomly generated keys.
    ///
    /// The encryption mechanism used is Chacha20Poly1305.
    pub fn new() -> Result<Arc<dyn ProducesTickets>, Error> {
        Ok(Arc::new(crate::ticketer::TicketSwitcher::new(
            6 * 60 * 60,
            make_ticket_generator,
        )?))
    }
}

fn make_ticket_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed> {
    let mut key = [0u8; 32];
    Ring::fill_random(&mut key)?;

    let alg = &aead::CHACHA20_POLY1305;
    let key = aead::UnboundKey::new(alg, &key).unwrap();

    Ok(Box::new(AeadTicketer {
        alg,
        key: aead::LessSafeKey::new(key),
        lifetime: 60 * 60 * 12,
    }))
}

/// This is a `ProducesTickets` implementation which uses
/// any *ring* `aead::Algorithm` to encrypt and authentication
/// the ticket payload.  It does not enforce any lifetime
/// constraint.
struct AeadTicketer {
    alg: &'static aead::Algorithm,
    key: aead::LessSafeKey,
    lifetime: u32,
}

impl ProducesTickets for AeadTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce_buf = [0u8; 12];
        Ring::fill_random(&mut nonce_buf).ok()?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);
        let aad = ring::aead::Aad::empty();

        let mut ciphertext =
            Vec::with_capacity(nonce_buf.len() + message.len() + self.key.algorithm().tag_len());
        ciphertext.extend(nonce_buf);
        ciphertext.extend(message);
        self.key
            .seal_in_place_separate_tag(nonce, aad, &mut ciphertext[nonce_buf.len()..])
            .map(|tag| {
                ciphertext.extend(tag.as_ref());
                ciphertext
            })
            .ok()
    }

    /// Decrypt `ciphertext` and recover the original message.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Non-panicking `let (nonce, ciphertext) = ciphertext.split_at(...)`.
        let nonce = ciphertext.get(..self.alg.nonce_len())?;
        let ciphertext = ciphertext.get(nonce.len()..)?;

        // This won't fail since `nonce` has the required length.
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;

        let mut out = Vec::from(ciphertext);

        let plain_len = self
            .key
            .open_in_place(nonce, aead::Aad::empty(), &mut out)
            .ok()?
            .len();
        out.truncate(plain_len);

        Some(out)
    }
}

#[cfg(test)]
use crate::ticketer::TimeBase;

#[test]
fn basic_pairwise_test() {
    let t = Ticketer::new().unwrap();
    assert!(t.enabled());
    let cipher = t.encrypt(b"hello world").unwrap();
    let plain = t.decrypt(&cipher).unwrap();
    assert_eq!(plain, b"hello world");
}

#[test]
fn ticketswitcher_switching_test() {
    let t = Arc::new(crate::ticketer::TicketSwitcher::new(1, make_ticket_generator).unwrap());
    let now = TimeBase::now().unwrap();
    let cipher1 = t.encrypt(b"ticket 1").unwrap();
    assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
    {
        // Trigger new ticketer
        t.maybe_roll(TimeBase(now.0 + core::time::Duration::from_secs(10)));
    }
    let cipher2 = t.encrypt(b"ticket 2").unwrap();
    assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
    assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
    {
        // Trigger new ticketer
        t.maybe_roll(TimeBase(now.0 + core::time::Duration::from_secs(20)));
    }
    let cipher3 = t.encrypt(b"ticket 3").unwrap();
    assert!(t.decrypt(&cipher1).is_none());
    assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
    assert_eq!(t.decrypt(&cipher3).unwrap(), b"ticket 3");
}

#[cfg(test)]
fn fail_generator() -> Result<Box<dyn ProducesTickets>, GetRandomFailed> {
    Err(GetRandomFailed)
}

#[test]
fn ticketswitcher_recover_test() {
    let mut t = crate::ticketer::TicketSwitcher::new(1, make_ticket_generator).unwrap();
    let now = TimeBase::now().unwrap();
    let cipher1 = t.encrypt(b"ticket 1").unwrap();
    assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
    t.generator = fail_generator;
    {
        // Failed new ticketer
        t.maybe_roll(TimeBase(now.0 + core::time::Duration::from_secs(10)));
    }
    t.generator = make_ticket_generator;
    let cipher2 = t.encrypt(b"ticket 2").unwrap();
    assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
    assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
    {
        // recover
        t.maybe_roll(TimeBase(now.0 + core::time::Duration::from_secs(20)));
    }
    let cipher3 = t.encrypt(b"ticket 3").unwrap();
    assert!(t.decrypt(&cipher1).is_none());
    assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
    assert_eq!(t.decrypt(&cipher3).unwrap(), b"ticket 3");
}
