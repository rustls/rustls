use getrandom::{register_custom_getrandom, Error};

use crate::{
    io::{self, ErrorKind},
    libc, sys,
};

register_custom_getrandom!(getrandom);

fn getrandom(mut dest: &mut [u8]) -> Result<(), Error> {
    while !dest.is_empty() {
        match sys::cvt(unsafe {
            libc::getrandom(dest.as_mut_ptr().cast(), dest.len(), libc::GRND_RANDOM)
        }) {
            Ok(read) => dest = &mut dest[read as usize..],
            Err(e) => {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                } else {
                    let err = if let io::Error::Os(errno) = e {
                        errno.into()
                    } else {
                        Error::ERRNO_NOT_POSITIVE
                    };

                    return Err(err);
                }
            }
        }
    }

    Ok(())
}
