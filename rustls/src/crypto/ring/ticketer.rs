#![allow(clippy::duplicate_mod)]

use crate::error::Error;
use crate::rand::GetRandomFailed;
use crate::server::ProducesTickets;

use super::ring_like::aead;
use super::ring_like::rand::{SecureRandom, SystemRandom};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::{Debug, Formatter};

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
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| GetRandomFailed)?;

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
        SystemRandom::new()
            .fill(&mut nonce_buf)
            .ok()?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_buf);
        let aad = aead::Aad::empty();

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

impl Debug for AeadTicketer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Note: we deliberately omit the key from the debug output.
        f.debug_struct("AeadTicketer")
            .field("alg", &self.alg)
            .field("lifetime", &self.lifetime)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::time::Duration;
    use pki_types::UnixTime;

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
        let now = UnixTime::now();
        let cipher1 = t.encrypt(b"ticket 1").unwrap();
        assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
        {
            // Trigger new ticketer
            t.maybe_roll(UnixTime::since_unix_epoch(Duration::from_secs(
                now.as_secs() + 10,
            )));
        }
        let cipher2 = t.encrypt(b"ticket 2").unwrap();
        assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
        assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
        {
            // Trigger new ticketer
            t.maybe_roll(UnixTime::since_unix_epoch(Duration::from_secs(
                now.as_secs() + 20,
            )));
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
        let now = UnixTime::now();
        let cipher1 = t.encrypt(b"ticket 1").unwrap();
        assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
        t.generator = fail_generator;
        {
            // Failed new ticketer
            t.maybe_roll(UnixTime::since_unix_epoch(Duration::from_secs(
                now.as_secs() + 10,
            )));
        }
        t.generator = make_ticket_generator;
        let cipher2 = t.encrypt(b"ticket 2").unwrap();
        assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
        assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
        {
            // recover
            t.maybe_roll(UnixTime::since_unix_epoch(Duration::from_secs(
                now.as_secs() + 20,
            )));
        }
        let cipher3 = t.encrypt(b"ticket 3").unwrap();
        assert!(t.decrypt(&cipher1).is_none());
        assert_eq!(t.decrypt(&cipher2).unwrap(), b"ticket 2");
        assert_eq!(t.decrypt(&cipher3).unwrap(), b"ticket 3");
    }

    #[test]
    fn aeadticketer_is_debug_and_producestickets() {
        use super::*;
        use alloc::format;

        let t = make_ticket_generator().unwrap();

        assert_eq!(
            format!("{:?}", t),
            "AeadTicketer { alg: CHACHA20_POLY1305, lifetime: 43200 }"
        );
        assert!(t.enabled());
        assert_eq!(t.lifetime(), 43200);
    }
}
