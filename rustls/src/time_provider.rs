//! The library's source of time.

use core::fmt::Debug;

use pki_types::UnixTime;

/// An object that provides the current time.
///
/// This is used to, for example, check if a certificate has expired during
/// certificate validation, or to check the age of a ticket.
pub trait TimeProvider: Debug + Send + Sync {
    /// Returns the current wall time.
    ///
    /// This is not required to be monotonic.
    ///
    /// Return `None` if unable to retrieve the time.
    fn current_time(&self) -> Option<UnixTime>;
}

/// Default `TimeProvider` implementation that uses `std`
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct DefaultTimeProvider;

impl TimeProvider for DefaultTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}
