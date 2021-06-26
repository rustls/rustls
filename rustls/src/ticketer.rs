use crate::rand;
use crate::server::ProducesTickets;
use crate::Error;

use ring::aead;
use std::mem;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time;

/// The timebase for expiring and rolling tickets and ticketing
/// keys.  This is UNIX wall time in seconds.
///
/// This is guaranteed to be on or after the UNIX epoch.
#[derive(Clone, Copy, Debug)]
pub struct TimeBase(time::Duration);

impl TimeBase {
    #[inline]
    pub fn now() -> Result<Self, time::SystemTimeError> {
        Ok(Self(
            time::SystemTime::now().duration_since(time::UNIX_EPOCH)?,
        ))
    }

    #[inline]
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
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

impl AeadTicketer {
    /// Make a ticketer with recommended configuration and a random key.
    fn new() -> Result<Self, rand::GetRandomFailed> {
        let mut key = [0u8; 32];
        rand::fill_random(&mut key)?;

        let alg = &aead::CHACHA20_POLY1305;
        let key = aead::UnboundKey::new(alg, &key).unwrap();

        Ok(Self {
            alg,
            key: aead::LessSafeKey::new(key),
            lifetime: 60 * 60 * 12,
        })
    }
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
        rand::fill_random(&mut nonce_buf).ok()?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_buf);
        let aad = ring::aead::Aad::empty();

        let mut ciphertext =
            Vec::with_capacity(nonce_buf.len() + message.len() + self.key.algorithm().tag_len());
        ciphertext.extend(&nonce_buf);
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
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;

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

struct TicketSwitcherState {
    current: Box<dyn ProducesTickets>,
    previous: Option<Box<dyn ProducesTickets>>,
    next_switch_time: u64,
}

/// A ticketer that has a 'current' sub-ticketer and a single
/// 'previous' ticketer.  It creates a new ticketer every so
/// often, demoting the current ticketer.
struct TicketSwitcher {
    generator: fn() -> Result<Box<dyn ProducesTickets>, rand::GetRandomFailed>,
    lifetime: u32,
    state: Mutex<TicketSwitcherState>,
}

impl TicketSwitcher {
    /// `lifetime` is in seconds, and is how long the current ticketer
    /// is used to generate new tickets.  Tickets are accepted for no
    /// longer than twice this duration.  `generator` produces a new
    /// `ProducesTickets` implementation.
    fn new(
        lifetime: u32,
        generator: fn() -> Result<Box<dyn ProducesTickets>, rand::GetRandomFailed>,
    ) -> Result<Self, Error> {
        let now = TimeBase::now()?;
        Ok(Self {
            generator,
            lifetime,
            state: Mutex::new(TicketSwitcherState {
                current: generator()?,
                previous: None,
                next_switch_time: now.as_secs() + u64::from(lifetime),
            }),
        })
    }

    /// If it's time, demote the `current` ticketer to `previous` (so it
    /// does no new encryptions but can do decryption) and make a fresh
    /// `current` ticketer.
    ///
    /// Calling this regularly will ensure timely key erasure.  Otherwise,
    /// key erasure will be delayed until the next encrypt/decrypt call.
    fn maybe_roll(
        &self,
        now: TimeBase,
        state: &mut MutexGuard<TicketSwitcherState>,
    ) -> Result<(), rand::GetRandomFailed> {
        let now = now.as_secs();
        if now > state.next_switch_time {
            state.previous = Some(mem::replace(&mut state.current, (self.generator)()?));
            state.next_switch_time = now + u64::from(self.lifetime);
        }
        Ok(())
    }
}

impl ProducesTickets for TicketSwitcher {
    fn lifetime(&self) -> u32 {
        self.lifetime * 2
    }

    fn enabled(&self) -> bool {
        true
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock().ok()?;
        self.maybe_roll(TimeBase::now().ok()?, &mut state)
            .ok()?;

        state.current.encrypt(message)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock().ok()?;

        self.maybe_roll(TimeBase::now().ok()?, &mut state)
            .ok()?;

        // Decrypt with the current key; if that fails, try with the previous.
        state
            .current
            .decrypt(ciphertext)
            .or_else(|| {
                state
                    .previous
                    .as_ref()
                    .and_then(|previous| previous.decrypt(ciphertext))
            })
    }
}

/// A concrete, safe ticket creation mechanism.
pub struct Ticketer {}

fn generate_inner() -> Result<Box<dyn ProducesTickets>, rand::GetRandomFailed> {
    Ok(Box::new(AeadTicketer::new()?))
}

impl Ticketer {
    /// Make the recommended Ticketer.  This produces tickets
    /// with a 12 hour life and randomly generated keys.
    ///
    /// The encryption mechanism used in Chacha20Poly1305.
    pub fn new() -> Result<Arc<dyn ProducesTickets>, Error> {
        Ok(Arc::new(TicketSwitcher::new(6 * 60 * 60, generate_inner)?))
    }
}

#[test]
fn basic_pairwise_test() {
    let t = Ticketer::new().unwrap();
    assert_eq!(true, t.enabled());
    let cipher = t.encrypt(b"hello world").unwrap();
    let plain = t.decrypt(&cipher).unwrap();
    assert_eq!(plain, b"hello world");
}
