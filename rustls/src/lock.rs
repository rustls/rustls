pub use std_lock::*;

mod std_lock {
    pub use std::sync::MutexGuard;
    use std::sync::{LockResult, Mutex as StdMutex};

    /// A wrapper around [`std::sync::Mutex`].
    #[derive(Debug)]
    pub struct Mutex<T> {
        inner: StdMutex<T>,
    }

    impl<T> Mutex<T> {
        /// Creates a new mutex in an unlocked state ready for use.
        pub fn new(data: T) -> Self {
            Self {
                inner: StdMutex::new(data),
            }
        }

        /// Acquires the mutex, blocking the current thread until it is able to do so.
        ///
        /// This will return `None` in the case the mutex is poisoned.
        #[inline]
        pub fn lock(&self) -> Option<MutexGuard<'_, T>> {
            self.inner.lock().ok()
        }

        /// Consumes the mutex, returning the underlying data.
        pub fn into_inner(self) -> LockResult<T> {
            self.inner.into_inner()
        }
    }
}
