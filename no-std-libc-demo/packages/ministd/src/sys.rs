use core::{ffi::c_int, num::NonZeroU32};

use crate::{
    io::{self, ErrorKind},
    libc,
};

pub fn abort() -> ! {
    unsafe { libc::abort() }
}

pub fn errno() -> Option<NonZeroU32> {
    let errno = unsafe { libc::__errno_location().read() };
    if errno < 0 {
        None
    } else {
        NonZeroU32::new(errno as u32)
    }
}

pub fn exit(status: i32) -> ! {
    unsafe { libc::exit(status) }
}

pub fn write(fd: c_int, buf: &[u8]) -> io::Result<usize> {
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        Err(errno()
            .map(io::Error::Os)
            .unwrap_or(io::Error::ErrnoNotPositive))
    } else {
        Ok(ret as usize)
    }
}

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(errno()
            .map(io::Error::Os)
            .unwrap_or(io::Error::ErrnoNotPositive))
    } else {
        Ok(t)
    }
}

pub fn cvt_r<T>(mut f: impl FnMut() -> T) -> io::Result<T>
where
    T: IsMinusOne,
{
    loop {
        match cvt(f()) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! is_minus_one {
    ($($ty:ty),*) => {
        $(
            impl IsMinusOne for $ty {
                fn is_minus_one(&self) -> bool {
                    *self == -1
                }
            }
        )*

    };
}

is_minus_one!(c_int, isize);

pub fn decode_error_kind(errno: NonZeroU32) -> ErrorKind {
    use ErrorKind::*;

    match errno.get() as c_int {
        libc::EINTR => Interrupted,
        _ => Uncategorized,
    }
}
