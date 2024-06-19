use std::env;
use std::sync::{Mutex, Once};

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

#[cfg(feature = "aws_lc_rs")]
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
    // TODO: Use `std::sync::Lazy` once that is stable.
    static mut MUTEX: Option<Mutex<()>> = None;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        MUTEX = Some(Mutex::new(()));
    });
    let mutex = unsafe { MUTEX.as_mut() };

    let _guard = mutex.unwrap().get_mut().unwrap();

    // XXX: NOT thread safe.
    env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt");

    f()
}
