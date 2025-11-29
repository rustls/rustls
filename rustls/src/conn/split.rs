//! A split reader-writer interface.
//!
//! This module offers an alternative API for TLS connections with completed
//! handshakes.  It separates the read and write halves of the connection into
//! [`Reader`] and [`Writer`] respectively.  These halves can be used fairly
//! independently, making it easier to pipeline and maximize throughput.

use std::{
    boxed::Box,
    io,
    ops::Deref,
    sync::{Arc, Mutex},
    vec::Vec,
};

use crate::{
    ConnectionCommon,
    client::{ClientConnection, ClientConnectionData},
    conn::{ConnectionCore, connection::PlaintextSink},
    crypto::cipher::OutboundChunks,
    msgs::deframer::DeframerVecBuffer,
    vecbuf::ChunkVecBuffer,
};

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

    let ClientConnection {
        inner:
            ConnectionCommon {
                core,
                deframer_buffer,
                sendable_plaintext,
            },
    } = conn;

    let conn = Arc::new(Mutex::new(core));
    (
        ClientReader {
            core: conn.clone(),
            deframer_buffer,
        },
        ClientWriter {
            core: conn.clone(),
            sendable_plaintext,
        },
    )
}

//----------- Reader ---------------------------------------------------------

/// The reading half of a client-side TLS connection.
pub struct ClientReader {
    /// The underlying connection.
    core: Arc<Mutex<ConnectionCore<ClientConnectionData>>>,

    /// A buffer of received TLS frames to coalesce.
    deframer_buffer: DeframerVecBuffer,
}

impl ClientReader {
    /// A reader for plaintext data.
    pub fn reader(&mut self) -> PlaintextReader<'_> {
        PlaintextReader { reader: self }
    }

    /// Receive TLS messages from the network.
    pub fn recv_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<Received> {
        let mut core = self.core.lock().unwrap();
        let mut total = 0;
        let mut eof = false;
        let mut sendable_plaintext = ChunkVecBuffer::new(None);

        while !eof && core.common_state.wants_read() {
            match Self::read_tls(&mut core, &mut self.deframer_buffer, rd) {
                Ok(0) => eof = true,
                Ok(n) => total += n,

                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if total != 0 {
                        break;
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
            }

            core.process_new_packets(&mut self.deframer_buffer, &mut sendable_plaintext)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }

        let writer_action = WriterAction {
            sendable_plaintext: (!sendable_plaintext.is_empty()).then(|| {
                let mut buffer = (0..sendable_plaintext.len())
                    .map(|_| 0u8)
                    .collect::<Box<[u8]>>();
                sendable_plaintext
                    .read(&mut buffer)
                    .expect("just moving data");
                buffer
            }),
        };

        Ok(Received {
            bytes_read: total,
            writer_action: Some(writer_action).filter(|a| !a.is_empty()),
        })
    }

    // ConnectionCommon::read_tls()
    fn read_tls(
        core: &mut ConnectionCore<ClientConnectionData>,
        deframer_buffer: &mut DeframerVecBuffer,
        rd: &mut dyn io::Read,
    ) -> io::Result<usize> {
        if core
            .common_state
            .received_plaintext
            .is_full()
        {
            return Err(io::Error::other("received plaintext buffer full"));
        }

        if core
            .common_state
            .has_received_close_notify
        {
            return Ok(0);
        }

        let res = deframer_buffer.read(rd, core.hs_deframer.is_active());
        if let Ok(0) = res {
            core.common_state.has_seen_eof = true;
        }
        res
    }
}

/// The output of [`Reader::recv_tls()`].
pub struct Received {
    /// The number of bytes read.
    pub bytes_read: usize,

    /// An action the writer should take, if any.
    pub writer_action: Option<WriterAction>,
}

/// A reader of plaintext data from a [`ClientReader`].
pub struct PlaintextReader<'a> {
    /// The underlying reader.
    reader: &'a mut ClientReader,
}

impl io::Read for PlaintextReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut core = self.reader.core.lock().unwrap();
        let common = &mut core.common_state;
        crate::Reader {
            received_plaintext: &mut common.received_plaintext,
            has_received_close_notify: common.has_received_close_notify,
            has_seen_eof: common.has_seen_eof,
        }
        .read(buf)
    }
}

//----------- Writer ---------------------------------------------------------

/// The writing half of a client-side TLS connection.
pub struct ClientWriter {
    /// The underlying connection.
    core: Arc<Mutex<ConnectionCore<ClientConnectionData>>>,

    /// A buffer of plaintext to encrypt and send.
    sendable_plaintext: ChunkVecBuffer,
}

impl ClientWriter {
    /// A writer for plaintext data.
    pub fn writer(&mut self) -> PlaintextWriter<'_> {
        PlaintextWriter { writer: self }
    }

    /// Enact a [`WriterAction`] sent by the [`Reader`].
    pub fn enact(&mut self, action: WriterAction) {
        let WriterAction { sendable_plaintext } = action;

        if let Some(sendable_plaintext) = sendable_plaintext {
            self.sendable_plaintext
                .append(sendable_plaintext.into_vec());
        }
    }

    /// Send prepared TLS messages over the network.
    pub fn send_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        let mut core = self.core.lock().unwrap();
        let mut total = 0;
        while core.common_state.wants_write() {
            match Self::write_tls(&mut core, wr) {
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

    // ConnectionCommon::write_tls()
    fn write_tls(
        core: &mut ConnectionCore<ClientConnectionData>,
        wr: &mut dyn io::Write,
    ) -> io::Result<usize> {
        core.common_state
            .sendable_tls
            .write_to(wr)
    }
}

/// A writer of plaintext data into a [`ClientWriter`].
pub struct PlaintextWriter<'a> {
    /// The underlying writer.
    writer: &'a mut ClientWriter,
}

impl PlaintextSink for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut core = self.writer.core.lock().unwrap();
        let len = core
            .common_state
            .buffer_plaintext(buf.into(), &mut self.writer.sendable_plaintext);
        core.maybe_refresh_traffic_keys();
        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let payload_owner: Vec<&[u8]>;
        let payload = match bufs.len() {
            0 => return Ok(0),
            1 => OutboundChunks::Single(bufs[0].deref()),
            _ => {
                payload_owner = bufs
                    .iter()
                    .map(|io_slice| io_slice.deref())
                    .collect();

                OutboundChunks::new(&payload_owner)
            }
        };

        let mut core = self.writer.core.lock().unwrap();
        let len = core
            .common_state
            .buffer_plaintext(payload, &mut self.writer.sendable_plaintext);
        core.maybe_refresh_traffic_keys();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for PlaintextWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        crate::Writer::new(self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        crate::Writer::new(self).flush()
    }
}

/// An action commanded by the [`Reader`].
pub struct WriterAction {
    /// A buffer to append to `sendable_plaintext`.
    sendable_plaintext: Option<Box<[u8]>>,
}

impl WriterAction {
    /// Whether this action is a no-op.
    fn is_empty(&self) -> bool {
        matches!(
            self,
            Self {
                sendable_plaintext: None,
            }
        )
    }
}
