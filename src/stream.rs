use std::io::{Read, Write, Result};
use session::Session;

/// This type implements `io::Read` and `io::Write`, encapsulating
/// a Session `S` and an underlying blocking transport `T`, such as
/// a socket.
///
/// This allows you to use a rustls Session like a normal stream.
pub struct Stream<'a, S: 'a + Session + ?Sized, T: 'a + Read + Write + ?Sized> {
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

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. Otherwise, we will prematurely signal EOF by returning 0. We
        // determine if EOF has actually been hit by checking if 0 bytes were
        // read from the underlying transport.
        while
            self.sess.wants_read() &&
            self.sess.complete_io(self.sock)?.0 != 0
        { }

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

#[cfg(test)]
mod tests {
    use super::Stream;
    use session::Session;
    use std::net::TcpStream;

    #[test]
    fn session_can_be_instantiated_with() {
        fn _foo<'a>(sess: &'a mut Session, sock: &'a mut TcpStream) -> Stream<'a, Session, TcpStream> {
            Stream {
                sess: sess,
                sock: sock,
            }
        }
    }
}
