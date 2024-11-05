use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use std::sync::{RwLock, RwLockReadGuard};

use pki_types::UnixTime;

use crate::server::ProducesTickets;
use crate::{rand, Error};

#[derive(Debug)]
pub(crate) struct TicketSwitcherState {
    current: Box<dyn ProducesTickets>,
    previous: Option<Box<dyn ProducesTickets>>,
    next_switch_time: u64,
}

/// A ticketer that has a 'current' sub-ticketer and a single
/// 'previous' ticketer.  It creates a new ticketer every so
/// often, demoting the current ticketer.
#[derive(Debug)]
pub struct TicketSwitcher {
    pub(crate) generator: fn() -> Result<Box<dyn ProducesTickets>, rand::GetRandomFailed>,
    lifetime: u32,
    state: RwLock<TicketSwitcherState>,
}

impl TicketSwitcher {
    /// Creates a new `TicketSwitcher`, which rotates through sub-ticketers
    /// based on the passage of time.
    ///
    /// `lifetime` is in seconds, and is how long the current ticketer
    /// is used to generate new tickets.  Tickets are accepted for no
    /// longer than twice this duration.  `generator` produces a new
    /// `ProducesTickets` implementation.
    #[cfg(feature = "std")]
    pub fn new(
        lifetime: u32,
        generator: fn() -> Result<Box<dyn ProducesTickets>, rand::GetRandomFailed>,
    ) -> Result<Self, Error> {
        Ok(Self {
            generator,
            lifetime,
            state: RwLock::new(TicketSwitcherState {
                current: generator()?,
                previous: None,
                next_switch_time: UnixTime::now()
                    .as_secs()
                    .saturating_add(u64::from(lifetime)),
            }),
        })
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
    ) -> Option<RwLockReadGuard<'_, TicketSwitcherState>> {
        let now = now.as_secs();

        // Fast, common, & read-only path in case we do not need to switch
        // to the next ticketer yet
        {
            let read = self.state.read().ok()?;

            if now <= read.next_switch_time {
                return Some(read);
            }
        }

        // We need to switch ticketers, and make a new one.
        // Generate a potential "next" ticketer outside the lock.
        let next = (self.generator)().ok()?;

        let mut write = self.state.write().ok()?;

        if now > write.next_switch_time {
            // Now we have:
            // - confirmed we need rotation
            // - confirmed we are the thread that will do it
            // - successfully made the replacement ticketer
            write.previous = Some(mem::replace(&mut write.current, next));
            write.next_switch_time = now.saturating_add(u64::from(self.lifetime));
        } else {
            // Another thread beat us to it.  Nothing to do.
        }
        drop(write);

        self.state.read().ok()
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
        self.maybe_roll(UnixTime::now())?
            .current
            .encrypt(message)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let state = self.maybe_roll(UnixTime::now())?;

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
