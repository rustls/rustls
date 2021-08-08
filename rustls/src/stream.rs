use crate::conn::{ConnectionCommon, SideData};

use std::io::{IoSlice, Read, Result, Write};
use std::ops::{Deref, DerefMut};

/// This type implements `io::Read` and `io::Write`, encapsulating
/// a Connection `C` and an underlying transport `T`, such as a socket.
///
/// This allows you to use a rustls Connection like a normal stream.
#[derive(Debug)]
pub struct Stream<'a, C: 'a + ?Sized, T: 'a + Read + Write + ?Sized> {
    /// Our TLS connection
    pub conn: &'a mut C,

    /// The underlying transport, like a socket
    pub sock: &'a mut T,
}

impl<'a, C, T, S> Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    /// Make a new Stream using the Connection `conn` and socket-like object
    /// `sock`.  This does not fail and does no IO.
    pub fn new(conn: &'a mut C, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> Result<()> {
        if self.conn.is_handshaking() {
            self.conn.complete_io(self.sock)?;
        }

        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }

        Ok(())
    }
}

impl<'a, C, T, S> Read for Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. Otherwise, we will prematurely signal EOF by returning 0. We
        // determine if EOF has actually been hit by checking if 0 bytes were
        // read from the underlying transport.
        while self.conn.wants_read() {
            let at_eof = self.conn.complete_io(self.sock)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.conn.process_new_packets() {
                    if at_eof && io_state.plaintext_bytes_to_read() == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        self.conn.reader().read(buf)
    }
}

impl<'a, C, T, S> Write for Stream<'a, C, T>
where
    C: 'a + DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: 'a + Read + Write,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.conn.writer().write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self.conn.complete_io(self.sock);

        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self
            .conn
            .writer()
            .write_vectored(bufs)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self.conn.complete_io(self.sock);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.conn.writer().flush()?;
        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }
        Ok(())
    }
}

/// This type implements `io::Read` and `io::Write`, encapsulating
/// and owning a Connection `C` and an underlying blocking transport
/// `T`, such as a socket.
///
/// This allows you to use a rustls Connection like a normal stream.
#[derive(Debug)]
pub struct StreamOwned<C: Sized, T: Read + Write + Sized> {
    /// Our conneciton
    pub conn: C,

    /// The underlying transport, like a socket
    pub sock: T,
}

impl<C, T, S> StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    /// Make a new StreamOwned taking the Connection `conn` and socket-like
    /// object `sock`.  This does not fail and does no IO.
    ///
    /// This is the same as `Stream::new` except `conn` and `sock` are
    /// moved into the StreamOwned.
    pub fn new(conn: C, sock: T) -> Self {
        Self { conn, sock }
    }

    /// Get a reference to the underlying socket
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }
}

impl<'a, C, T, S> StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn as_stream(&'a mut self) -> Stream<'a, C, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T, S> Read for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, T, S> Write for StreamOwned<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.as_stream().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, StreamOwned};
    use crate::client::ClientConnection;
    use crate::server::ServerConnection;
    use std::net::TcpStream;

    #[test]
    fn stream_can_be_created_for_connection_and_tcpstream() {
        type _Test<'a> = Stream<'a, ClientConnection, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_client_and_tcpstream() {
        type _Test = StreamOwned<ClientConnection, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_server_and_tcpstream() {
        type _Test = StreamOwned<ServerConnection, TcpStream>;
    }
}
