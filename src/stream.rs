use std::io::{Read, Write, Result};
use session::Session;

pub struct Stream<'a, S: 'a + Session, T: 'a + Read + Write> {
    pub sess: &'a mut S,
    pub sock: &'a mut T,
}

impl<'a, S, T> Stream<'a, S, T> where S: 'a + Session, T: 'a + Read + Write {
    pub fn new(sess: &'a mut S, sock: &'a mut T) -> Stream<'a, S, T> {
        Stream { sess, sock }
    }

    pub fn complete_prior_io(&mut self) -> Result<()> {
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
