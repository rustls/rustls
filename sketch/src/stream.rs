//! Example re-implementation of `rustls::Stream` (v0.21.6) on top of the proposed `Connection` API

use core::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::{IncomingTls, LlClientConnection, WebPkiServerCertVerifier, MAX_HANDSHAKE_SIZE};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(crate::Error),
}

impl From<crate::Error> for Error {
    fn from(err: crate::Error) -> Self {
        Self::Tls(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Tls(e) => write!(f, "{e}"),
        }
    }
}

impl From<crate::Error> for io::Error {
    fn from(err: crate::Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    }
}

pub struct Stream {
    cert_verifier: WebPkiServerCertVerifier,
    conn: LlClientConnection,
    early_data: Vec<u8>,
    incoming_tls: IncomingTls<Vec<u8>>,
    outgoing_tls: Vec<u8>,
    sock: TcpStream,
}

#[derive(Clone, Copy, Default, PartialEq)]
struct Status {
    did_send: bool,
    received_app_data: bool,
}

impl Stream {
    pub fn new(sock: TcpStream, conn: LlClientConnection) -> Self {
        Self {
            cert_verifier: WebPkiServerCertVerifier,
            early_data: Vec::new(),
            sock,
            conn,
            incoming_tls: IncomingTls::new(vec![0; MAX_HANDSHAKE_SIZE]),
            outgoing_tls: Vec::new(),
        }
    }

    pub fn set_early_data(&mut self, early_data: Vec<u8>) {
        self.early_data = early_data;
    }

    // TODO update these methods
    //     fn inner_read(&mut self, buf: &mut [u8], mut do_read_once: bool) -> io::Result<usize> {
    //         let capacity = buf.len();
    //         let mut cursor = 0;

    //         for _ in 0..2 {
    //             // first read out buffered data first
    //             let incoming_appdata = self.conn.decrypt_incoming(&mut self.incoming_tls);
    //             for res in incoming_appdata {
    //                 let new_data = res?;

    //                 let available = capacity - cursor;
    //                 let tocopy = new_data.len().min(available);
    //                 buf[cursor..cursor + tocopy].copy_from_slice(&new_data[..tocopy]);
    //                 cursor += tocopy;

    //                 if cursor == capacity {
    //                     // `buf` is full; do not decrypt in place any other record
    //                     break;
    //                 }
    //             }

    //             // NOTE we don't want to call this inside the previous for loop to avoid
    //             // excesive memcpy-ing
    //             self.incoming_tls.discard_app_data(cursor);

    //             if cursor == capacity {
    //                 break;
    //             }

    //             if do_read_once {
    //                 let read = self.sock.read(self.incoming_tls.unfilled())?;
    //                 self.incoming_tls.advance(read);
    //                 do_read_once = false;
    //             } else {
    //                 break;
    //             }
    //         }

    //         Ok(cursor)
    //     }

    //     fn event_loop(&mut self, mut write_buffer: Option<&[u8]>) -> Result<Status> {
    //         let mut stream_status = Status::default();

    //         let mut did_encrypt = false;
    //         loop {
    //             let tls_status = self
    //                 .conn
    //                 .handle_tls_records(&mut self.incoming_tls, &mut self.outgoing_tls)?;

    //             if tls_status.received_app_data() {
    //                 stream_status.received_app_data = true;
    //                 break;
    //             }

    //             if tls_status.may_send_early_data() && !self.early_data.is_empty() {
    //                 self.conn.encrypt_early_data(
    //                     &std::mem::replace(&mut self.early_data, vec![]),
    //                     &mut self.outgoing_tls,
    //                 );
    //             }

    //             if tls_status.may_send_app_data() {
    //                 // we use `Option::take` to avoid encryting this more than once
    //                 if let Some(write_buffer) = write_buffer.take() {
    //                     self.conn
    //                         .encrypt_outgoing(write_buffer, &mut self.outgoing_tls);

    //                     did_encrypt = true;
    //                 }
    //             }

    //             if tls_status.wants_write() {
    //                 self.sock.write_all(&self.outgoing_tls)?; // <<IO>>
    //                 self.outgoing_tls.clear();

    //                 if did_encrypt {
    //                     stream_status.did_send = true;
    //                 }
    //             }

    //             if tls_status.wants_read() {
    //                 let read = self.sock.read(self.incoming_tls.unfilled())?; // <<IO>>
    //                 self.incoming_tls.advance(read);

    //                 // must call `handle_tls_records` again
    //                 continue;
    //             } else {
    //                 if write_buffer.is_some() {
    //                     // io::Write
    //                     if did_encrypt {
    //                         break;
    //                     }
    //                 } else {
    //                     // io::Read
    //                     if tls_status.may_receive_app_data() {
    //                         break;
    //                     }
    //                 }
    //             }
    //         }

    //         Ok(stream_status)
    //     }
    // }

    // impl io::Read for Stream {
    //     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    //         let status = self.event_loop(None)?;

    //         self.inner_read(buf, !status.received_app_data)
    //     }
    // }

    // impl io::Write for Stream {
    //     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    //         let status = self.event_loop(Some(buf))?;

    //         if !status.did_send {
    //             let written = self.sock.write(&self.outgoing_tls)?;
    //             self.outgoing_tls.drain(0..written);
    //         }

    //         Ok(buf.len())
    //     }

    //     fn flush(&mut self) -> io::Result<()> {
    //         self.sock.write_all(&self.outgoing_tls)?;
    //         self.outgoing_tls.clear();

    //         Ok(())
    //     }
}
