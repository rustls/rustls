// based on `$(rustc +1.72.0 --print sysroot)/lib/rustlib/src/rust/library/std/src/sys/unix/time.rs`

use core::{ptr, time::Duration};

use crate::{
    libc::{self, timeval},
    sys,
};

const NSEC_PER_SEC: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug)]
pub struct SystemTimeError;

#[derive(Clone, Copy)]
pub struct SystemTime {
    t: Timespec,
}

pub const UNIX_EPOCH: SystemTime = SystemTime {
    t: Timespec::zero(),
};

impl SystemTime {
    pub fn now() -> Self {
        let mut s = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        unsafe {
            sys::cvt(libc::gettimeofday(&mut s, ptr::null_mut())).unwrap();
        }
        Self::from(s)
    }

    pub fn duration_since(&self, earlier: Self) -> Result<Duration, SystemTimeError> {
        self.sub_time(&earlier)
            .map_err(|_| SystemTimeError)
    }

    fn sub_time(&self, other: &Self) -> Result<Duration, Duration> {
        self.t.sub_timespec(&other.t)
    }
}

impl From<timeval> for Timespec {
    fn from(t: timeval) -> Self {
        Self::new(t.tv_sec, 1000 * t.tv_usec)
    }
}

impl From<timeval> for SystemTime {
    fn from(t: timeval) -> Self {
        Self {
            t: Timespec::from(t),
        }
    }
}

#[derive(Clone, Copy, PartialOrd, PartialEq)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: Nanoseconds,
}

impl Timespec {
    const fn zero() -> Self {
        Self::new(0, 0)
    }

    const fn new(tv_sec: i64, tv_nsec: i64) -> Timespec {
        assert!(tv_nsec >= 0 && tv_nsec < NSEC_PER_SEC as i64);
        // SAFETY: The assert above checks tv_nsec is within the valid range
        Timespec {
            tv_sec,
            tv_nsec: Nanoseconds(tv_nsec as u32),
        }
    }

    fn sub_timespec(&self, other: &Self) -> Result<Duration, Duration> {
        if self >= other {
            let (secs, nsec) = if self.tv_nsec.0 >= other.tv_nsec.0 {
                (
                    (self.tv_sec - other.tv_sec) as u64,
                    self.tv_nsec.0 - other.tv_nsec.0,
                )
            } else {
                (
                    (self.tv_sec - other.tv_sec - 1) as u64,
                    self.tv_nsec.0 + (NSEC_PER_SEC as u32) - other.tv_nsec.0,
                )
            };

            Ok(Duration::new(secs, nsec))
        } else {
            match other.sub_timespec(self) {
                Ok(d) => Err(d),
                Err(d) => Ok(d),
            }
        }
    }
}

#[derive(Clone, Copy, PartialOrd, PartialEq)]
struct Nanoseconds(u32);
