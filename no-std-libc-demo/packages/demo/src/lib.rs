#![no_std]

extern crate alloc;

use ministd::time::{SystemTime, UNIX_EPOCH};
use pki_types::UnixTime;
use rustls::time_provider::{GetCurrentTime, TimeProvider};

pub fn time_provider() -> TimeProvider {
    TimeProvider::new(DemoTimeProvider)
}

#[derive(Debug)]
struct DemoTimeProvider;

impl GetCurrentTime for DemoTimeProvider {
    fn get_current_time(&self) -> Option<UnixTime> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(UnixTime::since_unix_epoch)
    }
}
