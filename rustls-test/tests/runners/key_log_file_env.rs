#![allow(clippy::disallowed_types)]

use std::env;
use std::sync::Mutex;

#[macro_use]
mod macros;

#[cfg(feature = "ring")]
#[path = "."]
mod tests_with_ring {
    use super::serialized;

    provider_ring!();

    #[path = "../key_log_file_env.rs"]
    mod tests;
}

#[cfg(feature = "aws-lc-rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    use super::serialized;

    provider_aws_lc_rs!();

    #[path = "../key_log_file_env.rs"]
    mod tests;
}

/// Approximates `#[serial]` from the `serial_test` crate.
///
/// No attempt is made to recover from a poisoned mutex, which will
/// happen when `f` panics. In other words, all the tests that use
/// `serialized` will start failing after one test panics.
#[allow(dead_code)]
fn serialized(f: impl FnOnce()) {
    // Ensure every test is run serialized
    static MUTEX: Mutex<()> = const { Mutex::new(()) };

    let _guard = MUTEX.lock().unwrap();

    // XXX: NOT thread safe.
    unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

    f()
}
