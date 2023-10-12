use core::{ffi::c_int, fmt, num::NonZeroU32};

use crate::sys;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    AddressLookup,
    ErrnoNotPositive,
    InvalidInput,
    Os(NonZeroU32),
    WriteFmt,
    WriteZero,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorKind {
    Interrupted,
    Uncategorized,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Os(errno) => sys::decode_error_kind(*errno),
            Error::ErrnoNotPositive
            | Error::WriteFmt
            | Error::WriteZero
            | Error::AddressLookup
            | Error::InvalidInput => ErrorKind::Uncategorized,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct Stream {
    fd: c_int,
}

impl Stream {
    pub const STDOUT: Self = Self { fd: 0 };
    pub const STDERR: Self = Self { fd: 1 };
}

impl fmt::Write for Stream {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Write::write_all(self, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        sys::write(self.fd, buf)
    }
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::WriteZero);
                }
                Ok(n) => buf = &buf[n..],
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        struct Adapter<'a, T: ?Sized + 'a> {
            inner: &'a mut T,
            error: Result<()>,
        }

        impl<T: Write + ?Sized> fmt::Write for Adapter<'_, T> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.inner
                    .write_all(s.as_bytes())
                    .map_err(|e| {
                        self.error = Err(e);
                        fmt::Error
                    })
            }
        }

        let mut adapter = Adapter {
            inner: self,
            error: Ok(()),
        };
        match fmt::Write::write_fmt(&mut adapter, args) {
            Ok(()) => Ok(()),
            Err(_) => {
                if adapter.error.is_err() {
                    adapter.error
                } else {
                    Err(Error::WriteFmt)
                }
            }
        }
    }
}
