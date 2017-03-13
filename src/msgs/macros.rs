/// A macro which takes an Option<T> and returns None if it
/// is None, otherwise unwraps().
macro_rules! try_ret(
    ($e:expr) => (match $e { Some(e) => e, None => return None })
);
