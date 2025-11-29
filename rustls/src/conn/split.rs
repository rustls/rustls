//! A split reader-writer interface.
//!
//! This module offers an alternative API for TLS connections with completed
//! handshakes.  It separates the read and write halves of the connection into
//! [`Reader`] and [`Writer`] respectively.  These halves can be used fairly
//! independently, making it easier to pipeline and maximize throughput.

use std::{
    io,
    sync::{Arc, Mutex},
};

use crate::client::ClientConnection;

//----------- split ----------------------------------------------------------

/// Split a [`ClientConnection`] into reader-writer halves.
///
/// # Panics
///
/// Panics if `conn.is_handshaking()`.
pub fn split_client(conn: ClientConnection) -> (ClientReader, ClientWriter) {
    assert!(
        !conn.is_handshaking(),
        "the connection must be post-handshake"
    );

    let conn = Arc::new(Mutex::new(conn));
    (
        ClientReader { conn: conn.clone() },
        ClientWriter { conn: conn.clone() },
    )
}

//----------- Reader ---------------------------------------------------------

/// The reading half of a client-side TLS connection.
pub struct ClientReader {
    /// The underlying connection.
    conn: Arc<Mutex<ClientConnection>>,
}

impl ClientReader {
    /// A reader for plaintext data.
    pub fn reader(&mut self) -> PlaintextReader<'_> {
        PlaintextReader { reader: self }
    }

    /// Receive TLS messages from the network.
    pub fn recv_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let mut total = 0;
        let mut eof = false;
        while !eof && conn.wants_read() {
            match conn.read_tls(rd) {
                Ok(0) => eof = true,
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        return Ok(total);
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }

            conn.process_new_packets()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }
        Ok(total)
    }
}

/// A reader of plaintext data from a [`ClientReader`].
pub struct PlaintextReader<'a> {
    /// The underlying reader.
    reader: &'a mut ClientReader,
}

impl io::Read for PlaintextReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader
            .conn
            .lock()
            .unwrap()
            .reader()
            .read(buf)
    }
}

//----------- Writer ---------------------------------------------------------

/// The writing half of a client-side TLS connection.
pub struct ClientWriter {
    /// The underlying connection.
    conn: Arc<Mutex<ClientConnection>>,
}

impl ClientWriter {
    /// A writer for plaintext data.
    pub fn writer(&mut self) -> PlaintextWriter<'_> {
        PlaintextWriter { writer: self }
    }

    /// Send prepared TLS messages over the network.
    pub fn send_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let mut total = 0;
        while conn.wants_write() {
            match conn.write_tls(wr) {
                Ok(0) => return Ok(total),
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        return Ok(total);
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(total)
    }
}

/// A writer of plaintext data into a [`ClientWriter`].
pub struct PlaintextWriter<'a> {
    /// The underlying writer.
    writer: &'a mut ClientWriter,
}

impl io::Write for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer
            .conn
            .lock()
            .unwrap()
            .writer()
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .conn
            .lock()
            .unwrap()
            .writer()
            .flush()
    }
}
