use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use core::time::Duration;
use std::sync::{RwLock, RwLockReadGuard};

use pki_types::UnixTime;

use crate::crypto::TicketProducer;
use crate::error::Error;

/// A ticketer that has a 'current' sub-ticketer and a single
/// 'previous' ticketer.  It creates a new ticketer every so
/// often, demoting the current ticketer.
#[cfg(feature = "std")]
pub struct TicketRotator {
    pub(crate) generator: fn() -> Result<Box<dyn TicketProducer>, Error>,
    lifetime: Duration,
    state: RwLock<TicketRotatorState>,
}

#[cfg(feature = "std")]
impl TicketRotator {
    /// Creates a new `TicketRotator`, which rotates through sub-ticketers
    /// based on the passage of time.
    ///
    /// `lifetime` is in seconds, and is how long the current ticketer
    /// is used to generate new tickets.  Tickets are accepted for no
    /// longer than twice this duration.  This means a given ticket will
    /// be usable for at least one `lifetime`, and at most two `lifetime`s
    /// (depending on when its creation falls in the replacement cycle.)
    ///
    /// `generator` produces a new [`TicketProducer`] implementation.
    pub fn new(
        lifetime: Duration,
        generator: fn() -> Result<Box<dyn TicketProducer>, Error>,
    ) -> Result<Self, Error> {
        Ok(Self {
            generator,
            lifetime,
            state: RwLock::new(TicketRotatorState {
                current: Some(Generation {
                    producer: generator()?,
                    expires_at: UnixTime::now()
                        .as_secs()
                        .saturating_add(lifetime.as_secs()),
                }),
                previous: None,
            }),
        })
    }

    fn encrypt_at(&self, message: &[u8], now: UnixTime) -> Option<Vec<u8>> {
        let state = self.maybe_roll(now)?;

        // If we have a current ticketer, use it. We don't need to check its
        // expiration time; if it would have expired, we would have rolled above.
        if let Some(current) = &state.current {
            return current.producer.encrypt(message);
        }

        // If we don't have a previous ticketer, we can't encrypt.
        let Some(prev) = &state.previous else {
            return None;
        };

        // If the previous ticketer is more than one `lifetime` old, decline to encrypt.
        if !prev.in_grace_period(now, self.lifetime) {
            return None;
        }

        prev.producer.encrypt(message)
    }

    fn decrypt_at(&self, ciphertext: &[u8], now: UnixTime) -> Option<Vec<u8>> {
        let state = self.maybe_roll(now)?;

        // If we have a current ticketer, use it. We don't need to check its
        // expiration time; if it would have expired, we would have rolled above.
        if let Some(current) = &state.current {
            // If decryption fails, we're going to try the previous ticketer below.
            if let Some(plain) = current.producer.decrypt(ciphertext) {
                return Some(plain);
            }
        }

        // If we don't have a previous ticketer, we can't decrypt.
        let Some(prev) = &state.previous else {
            return None;
        };

        // If the previous ticketer is more than one `lifetime` old, decline to decrypt.
        if !prev.in_grace_period(now, self.lifetime) {
            return None;
        }

        prev.producer.decrypt(ciphertext)
    }

    /// If it's time, demote the `current` ticketer to `previous` (so it
    /// does no new encryptions but can do decryption) and replace it
    /// with a new one.
    ///
    /// Calling this regularly will ensure timely key erasure.  Otherwise,
    /// key erasure will be delayed until the next encrypt/decrypt call.
    ///
    /// For efficiency, this is also responsible for locking the state rwlock
    /// and returning it for read.
    pub(crate) fn maybe_roll(
        &self,
        now: UnixTime,
    ) -> Option<RwLockReadGuard<'_, TicketRotatorState>> {
        let now = now.as_secs();

        // Fast, common, & read-only path in case we do not need to switch
        // to the next ticketer yet
        {
            let read = self.state.read().ok()?;
            match &read.current {
                Some(current) if now <= current.expires_at => return Some(read),
                _ => {}
            }
        }

        let mut write = self.state.write().ok()?;
        if let Some(current) = &write.current {
            if now <= current.expires_at {
                // Another thread beat us to it. Nothing to do.
                drop(write);
                return self.state.read().ok();
            }
        }

        // We need to switch ticketers, and make a new one.
        // Generate a potential "next" ticketer outside the lock.
        let next = (self.generator)()
            .ok()
            .map(|producer| Generation {
                producer,
                expires_at: now.saturating_add(self.lifetime.as_secs()),
            });

        // Now we have:
        // - confirmed we need rotation
        // - confirmed we are the thread that will do it
        // - successfully made the replacement ticketer
        let prev = mem::replace(&mut write.current, next);
        if prev.is_some() {
            write.previous = prev;
        }
        drop(write);

        self.state.read().ok()
    }

    #[cfg(feature = "aws-lc-rs")]
    pub(crate) const SIX_HOURS: Duration = Duration::from_secs(6 * 60 * 60);
}

impl TicketProducer for TicketRotator {
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.encrypt_at(message, UnixTime::now())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.decrypt_at(ciphertext, UnixTime::now())
    }

    fn lifetime(&self) -> Duration {
        self.lifetime
    }
}

impl core::fmt::Debug for TicketRotator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TicketRotator")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct TicketRotatorState {
    current: Option<Generation>,
    previous: Option<Generation>,
}

#[derive(Debug)]
struct Generation {
    producer: Box<dyn TicketProducer>,
    expires_at: u64,
}

impl Generation {
    fn in_grace_period(&self, now: UnixTime, lifetime: Duration) -> bool {
        now.as_secs()
            .saturating_sub(self.expires_at)
            <= lifetime.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU8, Ordering};
    use core::time::Duration;

    use pki_types::UnixTime;

    use super::*;

    #[test]
    fn ticketrotator_switching_test() {
        let t = TicketRotator::new(Duration::from_secs(1), FakeTicketer::new).unwrap();
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

    #[test]
    fn ticketrotator_remains_usable_over_temporary_ticketer_creation_failure() {
        let mut t = TicketRotator::new(Duration::from_secs(1), FakeTicketer::new).unwrap();
        let expiry = t
            .state
            .read()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .expires_at;
        let cipher1 = t.encrypt(b"ticket 1").unwrap();
        assert_eq!(t.decrypt(&cipher1).unwrap(), b"ticket 1");
        t.generator = fail_generator;

        // Failed new ticketer; this means we still need to rotate.
        let t1 = UnixTime::since_unix_epoch(Duration::from_secs(expiry));
        drop(t.maybe_roll(t1));
        assert!(t.encrypt_at(b"ticket 2", t1).is_some());

        // check post-failure encryption/decryption still works
        let t2 = UnixTime::since_unix_epoch(Duration::from_secs(expiry + 1));
        let cipher3 = t.encrypt_at(b"ticket 3", t2).unwrap();
        assert_eq!(t.decrypt_at(&cipher1, t2).unwrap(), b"ticket 1");
        assert_eq!(t.decrypt_at(&cipher3, t2).unwrap(), b"ticket 3");

        let t3 = UnixTime::since_unix_epoch(Duration::from_secs(expiry + 2));
        assert_eq!(t.encrypt_at(b"ticket 4", t3), None);
        assert_eq!(t.decrypt_at(&cipher3, t3), None);

        // do the rotation for real
        t.generator = FakeTicketer::new;
        let t4 = UnixTime::since_unix_epoch(Duration::from_secs(expiry + 3));
        drop(t.maybe_roll(t4));

        let t5 = UnixTime::since_unix_epoch(Duration::from_secs(expiry + 4));
        let cipher5 = t.encrypt_at(b"ticket 5", t5).unwrap();
        assert!(t.decrypt_at(&cipher1, t5).is_none());
        assert!(t.decrypt_at(&cipher3, t5).is_none());
        assert_eq!(t.decrypt_at(&cipher5, t5).unwrap(), b"ticket 5");

        // Cover the case where both ticketers are unavailable
        t.generator = fail_generator;
        let mut write = t.state.write().unwrap();
        write.current = None;
        write.previous = None;
        drop(write);
        assert!(t.encrypt(b"ticket 6").is_none());
    }

    #[derive(Debug)]
    struct FakeTicketer {
        gen: u8,
    }

    impl FakeTicketer {
        #[expect(clippy::new_ret_no_self)]
        fn new() -> Result<Box<dyn TicketProducer>, Error> {
            Ok(Box::new(Self {
                gen: std::dbg!(FAKE_GEN.fetch_add(1, Ordering::SeqCst)),
            }))
        }
    }

    impl TicketProducer for FakeTicketer {
        fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
            let mut v = Vec::with_capacity(1 + message.len());
            v.push(self.gen);
            v.extend(
                message
                    .iter()
                    .copied()
                    .map(|b| b ^ self.gen),
            );
            Some(v)
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            if ciphertext.first()? != &self.gen {
                return None;
            }

            Some(
                ciphertext[1..]
                    .iter()
                    .copied()
                    .map(|b| b ^ self.gen)
                    .collect(),
            )
        }

        fn lifetime(&self) -> Duration {
            Duration::ZERO // Left to the rotator
        }
    }

    static FAKE_GEN: AtomicU8 = AtomicU8::new(0);

    fn fail_generator() -> Result<Box<dyn TicketProducer>, Error> {
        Err(Error::FailedToGetRandomBytes)
    }
}
