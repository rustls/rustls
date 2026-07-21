#![allow(clippy::std_instead_of_core)] // awaits core::io::IoSlice in stable (1.98)
use std::io::{self, BufRead, IoSlice, Read, Result, Write};
use std::marker::PhantomData;

use rustls::{Connection, SideData, TlsInputBuffer, VecInput};

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
pub struct Stream<'a, C: 'a + ?Sized, S, T: 'a + Read + Write + ?Sized> {
    /// Our TLS connection
    pub conn: &'a mut C,

    /// The underlying transport, like a socket
    pub sock: &'a mut T,

    /// The input buffer
    pub input: &'a mut VecInput,

    /// The buffer to store received plaintext
    pub received_plaintext: &'a mut Vec<u8>,

    /// Marker for the side of the connection (client or server)
    pub side: PhantomData<S>,
}

impl<'a, C, S, T> Stream<'a, C, S, T>
where
    C: 'a + Connection<S>,
    S: SideData,
    T: 'a + Read + Write,
{
    /// Make a new Stream using the Connection `conn` and socket-like object
    /// `sock`.  This does not fail and does no IO.
    pub fn new(
        input: &'a mut VecInput,
        received_plaintext: &'a mut Vec<u8>,
        conn: &'a mut C,
        sock: &'a mut T,
    ) -> Self {
        Self {
            conn,
            sock,
            input,
            received_plaintext,
            side: PhantomData,
        }
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> Result<()> {
        if self.conn.is_handshaking() {
            complete_io(self.sock, self.input, self.received_plaintext, self.conn)?;
        }

        if self.conn.wants_write() {
            complete_io(self.sock, self.input, self.received_plaintext, self.conn)?;
        }

        Ok(())
    }

    fn prepare_read(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. We stop as soon as we have some plaintext to return, since
        // `wants_read()` stays true even when plaintext is available.
        while self.received_plaintext.is_empty() && self.conn.wants_read() {
            if complete_io(self.sock, self.input, self.received_plaintext, self.conn)?.0 == 0 {
                break;
            }
        }

        // If we have no plaintext to return and the peer closed the connection without
        // sending a `close_notify`, surface that as an unexpected EOF.  A clean closure
        // (via `close_notify`) is instead reported as `Ok(0)`/an empty buffer.
        if self.received_plaintext.is_empty() && self.input.has_seen_eof() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed connection without sending TLS close_notify",
            ));
        }

        Ok(())
    }
}

impl<'a, C, S, T> Read for Stream<'a, C, S, T>
where
    C: 'a + Connection<S>,
    S: SideData,
    T: 'a + Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.prepare_read()?;
        let len = Ord::min(buf.len(), self.received_plaintext.len());
        let Some((src, _)) = self
            .received_plaintext
            .split_at_checked(len)
        else {
            return Ok(0);
        };

        let Some((dst, _)) = buf.split_at_mut_checked(len) else {
            return Ok(0);
        };

        dst.copy_from_slice(src);
        self.received_plaintext.drain(..len);
        Ok(len)
    }
}

impl<'a, C, S, T> BufRead for Stream<'a, C, S, T>
where
    C: 'a + Connection<S>,
    T: 'a + Read + Write,
    S: SideData,
{
    fn fill_buf(&mut self) -> Result<&[u8]> {
        self.prepare_read()?;
        Ok(self.received_plaintext)
    }

    fn consume(&mut self, amt: usize) {
        self.received_plaintext.drain(..amt);
    }
}

impl<'a, C, S, T> Write for Stream<'a, C, S, T>
where
    C: 'a + Connection<S>,
    S: SideData,
    T: 'a + Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.conn.writer().write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = complete_io(self.sock, self.input, self.received_plaintext, self.conn);

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
        let _ = complete_io(self.sock, self.input, self.received_plaintext, self.conn);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.conn.writer().flush()?;
        if self.conn.wants_write() {
            complete_io(self.sock, self.input, self.received_plaintext, self.conn)?;
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
pub struct StreamOwned<C: Sized, S, T: Read + Write + Sized> {
    /// Our connection
    pub conn: C,

    /// The underlying transport, like a socket
    pub sock: T,

    /// The input buffer
    pub input: VecInput,

    /// The buffer to store received plaintext
    pub received_plaintext: Vec<u8>,

    /// Marker for the side of the connection (client or server)
    pub side: PhantomData<S>,
}

impl<C, S, T> StreamOwned<C, S, T>
where
    C: Connection<S>,
    S: SideData,
    T: Read + Write,
{
    /// Make a new StreamOwned taking the Connection `conn` and socket-like
    /// object `sock`.  This does not fail and does no IO.
    ///
    /// This is the same as `Stream::new` except `conn` and `sock` are
    /// moved into the StreamOwned.
    pub fn new(conn: C, sock: T) -> Self {
        Self {
            conn,
            sock,
            input: VecInput::default(),
            received_plaintext: Vec::new(),
            side: PhantomData,
        }
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

impl<'a, C, S, T> StreamOwned<C, S, T>
where
    C: Connection<S>,
    S: SideData,
    T: Read + Write,
{
    fn as_stream(&'a mut self) -> Stream<'a, C, S, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
            input: &mut self.input,
            received_plaintext: &mut self.received_plaintext,
            side: PhantomData,
        }
    }
}

impl<C, S, T> Read for StreamOwned<C, S, T>
where
    C: Connection<S>,
    S: SideData,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, S, T> BufRead for StreamOwned<C, S, T>
where
    C: Connection<S>,
    S: SideData,
    T: Read + Write,
{
    fn fill_buf(&mut self) -> Result<&[u8]> {
        self.as_stream().prepare_read()?;
        Ok(&self.received_plaintext)
    }

    fn consume(&mut self, amt: usize) {
        self.as_stream().consume(amt)
    }
}

impl<C, S, T> Write for StreamOwned<C, S, T>
where
    C: Connection<S>,
    S: SideData,
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

    use rustls::client::ClientSide;
    use rustls::server::ServerSide;
    use rustls::{ClientConnection, ServerConnection};

    use super::{Stream, StreamOwned};

    #[test]
    fn stream_can_be_created_for_connection_and_tcpstream() {
        type _Test<'a> = Stream<'a, ClientConnection, ClientSide, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_client_and_tcpstream() {
        type _Test = StreamOwned<ClientConnection, ServerSide, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_server_and_tcpstream() {
        type _Test = StreamOwned<ServerConnection, ClientSide, TcpStream>;
    }
}
