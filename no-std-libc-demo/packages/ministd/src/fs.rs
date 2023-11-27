use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_int, CStr};

use crate::io::{ErrorKind, Read};
use crate::sys::cvt;
use crate::{io, libc, sys};

pub fn read(path: &CStr) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open_c(path)?;
    let mut contents = vec![0; 8 * 1024];
    let mut read = 0;
    loop {
        let len = contents.len();
        if len == read {
            contents.resize(2 * len, 0);
        }

        match file.read(&mut contents[read..]) {
            Ok(0) => break,
            Ok(additional) => read += additional,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    contents.truncate(read);
    Ok(contents)
}

struct File {
    fd: c_int,
}

impl File {
    fn open_c(path: &CStr) -> Result<File, io::Error> {
        let flags = libc::O_CLOEXEC | libc::O_RDONLY;

        let fd = sys::cvt(unsafe { libc::open64(path.as_ptr(), flags) })?;
        Ok(File { fd })
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(cvt(unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) })? as usize)
    }
}
