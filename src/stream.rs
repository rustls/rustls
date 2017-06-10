use std::io::{Read, Write, Result};
use session::Session;

/// This type implements `io::Read` and `io::Write`, encapsulating
/// a Session `S` and an underlying blocking transport `T`, such as
/// a socket.
///
/// This allows you to use a rustls Session like a normal stream.
pub struct Stream<'a, S: 'a + Session, T: 'a + Read + Write> {
    /// Our session
    pub sess: &'a mut S,

    /// The underlying transport, like a socket
    pub sock: &'a mut T,
}

impl<'a, S, T> Stream<'a, S, T> where S: 'a + Session, T: 'a + Read + Write {
    /// Make a new Stream using the Session `sess` and socket-like object
    /// `sock`.  This does not fail and does no IO.
    pub fn new(sess: &'a mut S, sock: &'a mut T) -> Stream<'a, S, T> {
        Stream { sess, sock }
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> Result<()> {
        if self.sess.is_handshaking() {
            self.sess.complete_io(self.sock)?;
        }

        if self.sess.wants_write() {
            self.sess.complete_io(self.sock)?;
        }

        Ok(())
    }
}

impl<'a, S, T> Read for Stream<'a, S, T> where S: 'a + Session, T: 'a + Read + Write {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.complete_prior_io()?;

        if self.sess.wants_read() {
            self.sess.complete_io(self.sock)?;
        }

        self.sess.read(buf)
    }
}

impl<'a, S, T> Write for Stream<'a, S, T> where S: 'a + Session, T: 'a + Read + Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.sess.write(buf)?;
        self.sess.complete_io(self.sock)?;
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.sess.flush()?;
        if self.sess.wants_write() {
            self.sess.complete_io(self.sock)?;
        }
        Ok(())
    }
}
