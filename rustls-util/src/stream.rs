use std::io::{BufRead, IoSlice, Read, Result, Write};

use rustls::Connection;

use crate::complete_io;

/// This type implements `io::Read` and `io::Write`, encapsulating
/// a Connection `C` and an underlying transport `T`, such as a socket.
///
/// Relies on [`complete_io()`] to perform the necessary I/O.
///
/// This allows you to use a rustls Connection like a normal stream.
///
/// [`complete_io()`]: crate::complete_io()
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct Stream<'a, C: 'a + ?Sized, T: 'a + Read + Write + ?Sized> {
    /// Our TLS connection
    pub conn: &'a mut C,

    /// The underlying transport, like a socket
    pub sock: &'a mut T,
}

impl<'a, C, T> Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
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
            complete_io(self.sock, self.conn)?;
        }

        if self.conn.wants_write() {
            complete_io(self.sock, self.conn)?;
        }

        Ok(())
    }

    fn prepare_read(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit.
        while self.conn.wants_read() {
            if complete_io(self.sock, self.conn)?.0 == 0 {
                break;
            }
        }

        Ok(())
    }

    // Implements `BufRead::fill_buf` but with more flexible lifetimes, so StreamOwned can reuse it
    fn fill_buf(mut self) -> Result<&'a [u8]> {
        self.prepare_read()?;
        self.conn.reader().into_first_chunk()
    }
}

impl<'a, C, T> Read for Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.prepare_read()?;
        self.conn.reader().read(buf)
    }
}

impl<'a, C, T> BufRead for Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    fn fill_buf(&mut self) -> Result<&[u8]> {
        // reborrow to get an owned `Stream`
        Stream {
            conn: self.conn,
            sock: self.sock,
        }
        .fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.conn.reader().consume(amt)
    }
}

impl<'a, C, T> Write for Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.conn.writer().write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = complete_io(self.sock, self.conn);

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
        let _ = complete_io(self.sock, self.conn);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.conn.writer().flush()?;
        if self.conn.wants_write() {
            complete_io(self.sock, self.conn)?;
        }
        Ok(())
    }
}

/// This type implements `io::Read` and `io::Write`, encapsulating
/// and owning a Connection `C` and an underlying transport `T`, such as a socket.
///
/// Relies on [`complete_io()`] to perform the necessary I/O.
///
/// This allows you to use a rustls Connection like a normal stream.
///
/// [`complete_io()`]: crate::complete_io()
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct StreamOwned<C: Sized, T: Read + Write + Sized> {
    /// Our connection
    pub conn: C,

    /// The underlying transport, like a socket
    pub sock: T,
}

impl<C, T> StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
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

    /// Extract the `conn` and `sock` parts from the `StreamOwned`
    pub fn into_parts(self) -> (C, T) {
        (self.conn, self.sock)
    }
}

impl<'a, C, T> StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn as_stream(&'a mut self) -> Stream<'a, C, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T> Read for StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, T> BufRead for StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn fill_buf(&mut self) -> Result<&[u8]> {
        self.as_stream().fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.as_stream().consume(amt)
    }
}

impl<C, T> Write for StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
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
    use std::net::TcpStream;

    use rustls::{ClientConnection, ServerConnection};

    use super::{Stream, StreamOwned};

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
