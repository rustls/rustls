use std::{fs, io};

use pki_types::{CertificateDer, PrivateKeyDer};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

impl KeyType {
    pub(crate) fn path_for(&self, part: &str) -> String {
        match self {
            Self::Rsa => format!("../test-ca/rsa/{}", part),
            Self::Ecdsa => format!("../test-ca/ecdsa/{}", part),
        }
    }

    pub(crate) fn get_chain(&self) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(self.path_for("end.fullchain")).unwrap(),
        ))
        .map(|result| result.unwrap())
        .collect()
    }

    pub(crate) fn get_key(&self) -> PrivateKeyDer<'static> {
        rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
            fs::File::open(self.path_for("end.key")).unwrap(),
        ))
        .next()
        .unwrap()
        .unwrap()
        .into()
    }
}

pub mod transport {
    //! This module implements custom functions to interact between rustls clients and a servers.
    //!
    //! The goal of these functions is to ensure messages are exchanged in chunks of a fixed size, to make
    //! instruction counts more deterministic. This is particularly important for the receiver of the
    //! data. Without it, the amount of bytes received in a single `read` call can wildly differ among
    //! benchmark runs, which in turn influences the resizing of rustls' internal buffers, and therefore
    //! affects the instruction count (resulting in consistent noise above 2% for the client-side of the
    //! data transfer benchmarks, which is unacceptable).
    //!
    //! Note that this approach introduces extra copies, because we are using an intermediate buffer,
    //! but that doesn't matter (we are measuring performance differences, and overhead is automatically
    //! ignored as long as it remains constant).

    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use rustls::{ClientConnection, ConnectionCommon, ServerConnection, SideData};
    use std::io::{Read, Write};

    /// Sends one side's handshake data to the other side in one go.
    ///
    /// Because it is not possible for the receiver to know beforehand how many bytes are contained in
    /// the message, the transmission consists of a leading big-endian u32 specifying the message's
    /// length, followed by the message itself.
    ///
    /// The receiving end should use [`read_handshake_message`] to process the transmission.
    pub fn send_handshake_message<T: SideData>(
        conn: &mut ConnectionCommon<T>,
        writer: &mut dyn Write,
        buf: &mut [u8],
    ) -> anyhow::Result<()> {
        // Write all bytes the connection wants to send to an intermediate buffer
        let mut written = 0;
        while conn.wants_write() {
            if written >= buf.len() {
                anyhow::bail!(
                    "Not enough space in buffer for outgoing message (buf len = {})",
                    buf.len()
                );
            }

            written += conn.write_tls(&mut &mut buf[written..])?;
        }

        if written == 0 {
            return Ok(());
        }

        // Write the whole buffer in one go, preceded by its length
        writer.write_u32::<BigEndian>(written as u32)?;
        writer.write_all(&buf[..written])?;
        writer.flush()?;

        Ok(())
    }

    /// Receives one side's handshake data to the other side in one go.
    ///
    /// Used in combination with [`send_handshake_message`] (see that function's documentation for
    /// more details).
    pub fn read_handshake_message<T: SideData>(
        conn: &mut ConnectionCommon<T>,
        reader: &mut dyn Read,
        buf: &mut [u8],
    ) -> anyhow::Result<usize> {
        // Read the message to an intermediate buffer
        let length = reader.read_u32::<BigEndian>()? as usize;
        if length >= buf.len() {
            anyhow::bail!(
            "Not enough space in buffer for incoming message (msg len = {length}, buf len = {})",
            buf.len()
        );
        }
        reader.read_exact(&mut buf[..length])?;

        // Feed the data to rustls
        let in_memory_reader = &mut &buf[..length];
        while conn.read_tls(in_memory_reader)? != 0 {
            conn.process_new_packets()?;
        }

        Ok(length)
    }

    /// Reads plaintext until the reader reaches EOF, using a bounded amount of memory.
    ///
    /// Returns the amount of plaintext bytes received.
    pub fn read_plaintext_to_end_bounded(
        client: &mut ClientConnection,
        reader: &mut dyn Read,
    ) -> anyhow::Result<usize> {
        let mut chunk_buf = [0u8; 262_144];
        let mut plaintext_buf = [0u8; 262_144];
        let mut total_plaintext_bytes_read = 0;

        loop {
            // Read until the whole chunk is received
            let mut chunk_buf_end = 0;
            while chunk_buf_end != chunk_buf.len() {
                let read = reader.read(&mut chunk_buf[chunk_buf_end..])?;
                if read == 0 {
                    // Stream closed
                    break;
                }

                chunk_buf_end += read;
            }

            if chunk_buf_end == 0 {
                // Stream closed
                break;
            }

            // Load the buffer's bytes into rustls
            let mut chunk_buf_offset = 0;
            while chunk_buf_offset < chunk_buf_end {
                let read = client.read_tls(&mut &chunk_buf[chunk_buf_offset..chunk_buf_end])?;
                chunk_buf_offset += read;

                // Process packets to free space in the message buffer
                let state = client.process_new_packets()?;
                let available_plaintext_bytes = state.plaintext_bytes_to_read();
                let mut plaintext_bytes_read = 0;
                while plaintext_bytes_read < available_plaintext_bytes {
                    plaintext_bytes_read += client
                        .reader()
                        .read(&mut plaintext_buf)?;
                }

                total_plaintext_bytes_read += plaintext_bytes_read;
            }
        }

        Ok(total_plaintext_bytes_read)
    }

    /// Writes a plaintext of size `plaintext_size`, using a bounded amount of memory
    pub fn write_all_plaintext_bounded(
        server: &mut ServerConnection,
        writer: &mut dyn Write,
        plaintext_size: usize,
    ) -> anyhow::Result<()> {
        let send_buf = [0u8; 262_144];
        assert_eq!(plaintext_size % send_buf.len(), 0);
        let iterations = plaintext_size / send_buf.len();

        for _ in 0..iterations {
            server.writer().write_all(&send_buf)?;

            // Empty the server's buffer, so we can re-fill it in the next iteration
            while server.wants_write() {
                server.write_tls(writer)?;
                writer.flush()?;
            }
        }

        Ok(())
    }
}
