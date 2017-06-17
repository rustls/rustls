
use server::ProducesTickets;
use rand;

use time;
use std::mem;
use std::sync::{Mutex, Arc};
use ring::aead;

/// This is a `ProducesTickets` implementation which uses
/// any *ring* `aead::Algorithm` to encrypt and authentication
/// the ticket payload.  It does not enforce any lifetime
/// constraint.
pub struct AEADTicketer {
    alg: &'static aead::Algorithm,
    enc: aead::SealingKey,
    dec: aead::OpeningKey,
    lifetime: u32,
}

impl AEADTicketer {
    /// Make a new `AEADTicketer` using the given `alg`, `key` material
    /// and advertised `lifetime_seconds`.  Note that `lifetime_seconds`
    /// does not affect the lifetime of the key.  `key` must be the
    /// right length for `alg` or this will panic.
    pub fn new_custom(alg: &'static aead::Algorithm,
                      key: &[u8],
                      lifetime_seconds: u32)
                      -> AEADTicketer {
        AEADTicketer {
            alg: alg,
            enc: aead::SealingKey::new(alg, key).unwrap(),
            dec: aead::OpeningKey::new(alg, key).unwrap(),
            lifetime: lifetime_seconds,
        }
    }

    /// Make a ticketer with recommended configuration and a random key.
    pub fn new() -> AEADTicketer {
        let mut key = [0u8; 32];
        rand::fill_random(&mut key);
        AEADTicketer::new_custom(&aead::CHACHA20_POLY1305, &key, 60 * 60 * 12)
    }
}

impl ProducesTickets for AEADTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn get_lifetime(&self) -> u32 {
        self.lifetime
    }

    /// Encrypt `message` and return the ciphertext.
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Random nonce, because a counter is a privacy leak.
        let mut nonce = [0u8; 12];
        rand::fill_random(&mut nonce);

        let mut out = Vec::new();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(message);
        out.resize(nonce.len() + message.len() + self.alg.tag_len(), 0u8);

        let rc = aead::seal_in_place(&self.enc,
                                     &nonce,
                                     &[],
                                     &mut out[nonce.len()..],
                                     self.alg.tag_len());
        if rc.is_err() { None } else { Some(out) }
    }

    /// Decrypt `ciphertext` and recover the original message.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce_len = self.alg.nonce_len();
        let tag_len = self.alg.tag_len();

        if ciphertext.len() < nonce_len + tag_len {
            return None;
        }

        let nonce = &ciphertext[0..nonce_len];
        let mut out = Vec::new();
        out.extend_from_slice(&ciphertext[nonce_len..]);

        let plain_len = match aead::open_in_place(&self.dec, nonce, &[], 0, &mut out) {
            Ok(plaintext) => plaintext.len(),
            Err(..) => { return None; }
        };

        out.truncate(plain_len);
        Some(out)
    }
}

struct TicketSwitcherState {
    current: Box<ProducesTickets>,
    previous: Option<Box<ProducesTickets>>,
    next_switch_time: i64,
}

/// A ticketer that has a 'current' sub-ticketer and a single
/// 'previous' ticketer.  It creates a new ticketer every so
/// often, demoting the current ticketer.
pub struct TicketSwitcher {
    generator: fn() -> Box<ProducesTickets>,
    lifetime: u32,
    state: Mutex<TicketSwitcherState>,
}

impl TicketSwitcher {
    /// `lifetime` is in seconds, and is how long the current ticketer
    /// is used to generate new tickets.  Tickets are accepted for no
    /// longer than twice this duration.  `generator` produces a new
    /// `ProducesTickets` implementation.
    pub fn new(lifetime: u32,
               generator: fn() -> Box<ProducesTickets>)
               -> TicketSwitcher {
        TicketSwitcher {
            generator: generator,
            lifetime: lifetime,
            state: Mutex::new(TicketSwitcherState {
                current: generator(),
                previous: None,
                next_switch_time: time::get_time().sec + lifetime as i64,
            }),
        }
    }

    /// If it's time, demote the `current` ticketer to `previous` (so it
    /// does no new encryptions but can do decryptions) and make a fresh
    /// `current` ticketer.
    ///
    /// Calling this regularly will ensure timely key erasure.  Otherwise,
    /// key erasure will be delayed until the next encrypt/decrypt call.
    pub fn maybe_roll(&self) {
        let mut state = self.state.lock().unwrap();
        let now = time::get_time().sec;

        if now > state.next_switch_time {
            state.previous = Some(mem::replace(&mut state.current, (self.generator)()));
            state.next_switch_time = now + self.lifetime as i64;
        }
    }
}

impl ProducesTickets for TicketSwitcher {
    fn get_lifetime(&self) -> u32 {
        self.lifetime * 2
    }
    fn enabled(&self) -> bool {
        true
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.maybe_roll();

        self.state
            .lock()
            .unwrap()
            .current
            .encrypt(message)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.maybe_roll();

        let state = self.state.lock().unwrap();
        let rc = state.current.decrypt(ciphertext);

        if rc.is_none() && state.previous.is_some() {
            state.previous.as_ref().unwrap().decrypt(ciphertext)
        } else {
            rc
        }
    }
}

/// A concrete, safe ticket creation mechanism.
pub struct Ticketer {}

fn generate_inner() -> Box<ProducesTickets> {
    Box::new(AEADTicketer::new())
}

impl Ticketer {
    /// Make the recommended Ticketer.  This produces tickets
    /// with a 12 hour life and randomly generated keys.
    ///
    /// The encryption mechanism used in Chacha20Poly1305.
    pub fn new() -> Arc<ProducesTickets> {
        Arc::new(TicketSwitcher::new(6 * 60 * 60, generate_inner))
    }
}
