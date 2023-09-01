//! Example re-implementation of `rustls::Stream` (v0.21.6) on top of the proposed `Connection` API

use core::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::status::State;
use crate::{
    CertificateEntry, CertificateVerificationOutcome, DigitallySignedStruct, IncomingTls,
    LlClientConnection, ServerCertVerifier, WebPkiServerCertVerifier, MAX_HANDSHAKE_SIZE,
};

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
    certificates: Vec<CertificateEntry>,
    conn: LlClientConnection,
    dss: Option<DigitallySignedStruct>,
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
            certificates: Vec::new(),
            conn,
            dss: None,
            early_data: Vec::new(),
            incoming_tls: IncomingTls::new(vec![0; MAX_HANDSHAKE_SIZE]),
            outgoing_tls: Vec::new(),
            sock,
        }
    }

    pub fn set_early_data(&mut self, early_data: Vec<u8>) {
        self.early_data = early_data;
    }

    fn inner_read(&mut self, buf: &mut [u8], mut do_read_once: bool) -> io::Result<usize> {
        let capacity = buf.len();
        let mut cursor = 0;

        for _ in 0..2 {
            // first read out buffered data first
            let incoming_appdata = self
                .conn
                .decrypt_incoming(&mut self.incoming_tls);
            for res in incoming_appdata {
                let new_data = res?;

                let available = capacity - cursor;
                let tocopy = new_data.len().min(available);
                buf[cursor..cursor + tocopy].copy_from_slice(&new_data[..tocopy]);
                cursor += tocopy;

                if cursor == capacity {
                    // `buf` is full; do not decrypt in place any other record
                    break;
                }
            }

            // NOTE we don't want to call this inside the previous for loop to avoid
            // excesive memcpy-ing
            self.incoming_tls
                .discard_app_data(cursor);

            if cursor == capacity {
                break;
            }

            if do_read_once {
                let read = self
                    .sock
                    .read(self.incoming_tls.unfilled())?;
                self.incoming_tls.advance(read);
                do_read_once = false;
            } else {
                break;
            }
        }

        Ok(cursor)
    }

    fn event_loop(&mut self, mut write_buffer: Option<&[u8]>) -> Result<Status> {
        let mut stream_status = Status::default();

        let mut did_encrypt = false;
        loop {
            let status = self
                .conn
                .handle_tls_records(&mut self.incoming_tls, &mut self.outgoing_tls)?;

            match status.state {
                State::NeedsSupportedVerifySchemes => {
                    let schemes = self
                        .cert_verifier
                        .supported_verify_schemes();
                    self.conn
                        .add_supported_verify_schemes(schemes);
                }

                State::MustTransmitTlsData => {
                    if status.caps.may_encrypt_app_data {
                        if let Some(write_buffer) = write_buffer.take() {
                            self.conn
                                .encrypt_outgoing(write_buffer, &mut self.outgoing_tls);
                            stream_status.did_send = true;
                        }
                    }

                    if status.caps.may_encrypt_early_data {
                        if !self.early_data.is_empty() {
                            self.conn
                                .encrypt_early_data(&self.early_data, &mut self.outgoing_tls);

                            self.early_data.clear();
                        }
                    }

                    self.sock
                        .write_all(&self.outgoing_tls)?;
                    self.outgoing_tls.clear();

                    if stream_status.did_send {
                        break;
                    }
                }

                State::NeedsMoreTlsData => {
                    let read = self
                        .sock
                        .read(self.incoming_tls.unfilled())?;
                    self.incoming_tls.advance(read);
                }

                State::ReceivedAppData => {
                    stream_status.received_app_data = true;
                    break;
                }

                State::ReceivedEarlyData => {
                    // XXX should this be signaled as an error? e.g. `Stream::write` was used but
                    // during handshake early data was received; the early data needs to be read or
                    // discarded, since it can't be buffered by ServerConnection, to complete the
                    // handshake

                    todo!()
                }

                State::TrafficTransit => break,

                State::ReceivedCertificate(new_certificates) => self
                    .certificates
                    .extend(new_certificates),

                State::ReceivedSignature(dss) => {
                    self.dss = Some(dss);
                }

                State::NeedsSignature { message, version } => {
                    let (end_entity, intermediates) = self
                        .certificates
                        .split_first()
                        .ok_or(crate::Error::Fatal)?;

                    // normally, this would come from the `ext` field of `end_entity` but it was not mocked
                    let ocsp_response = &[];

                    let intermediates = intermediates
                        .iter()
                        .map(|entry| entry.cert)
                        .collect::<Vec<_>>();

                    let cert_verified = self.cert_verifier.verify_server_cert(
                        &end_entity.cert,
                        &intermediates,
                        &self.conn.server_name,
                        ocsp_response,
                    )?;

                    let dss = self
                        .dss
                        .as_ref()
                        .ok_or(crate::Error::Fatal)?;
                    let sig_verified = self
                        .cert_verifier
                        .verify_tls13_signature(&message, &end_entity.cert, dss)?;

                    let verification_outcome = CertificateVerificationOutcome::Success {
                        cert_verified,
                        sig_verified,
                    };
                    self.conn
                        .certificate_verification_outcome(verification_outcome);
                }
            }
        }

        Ok(stream_status)
    }
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let status = self.event_loop(None)?;

        self.inner_read(buf, !status.received_app_data)
    }
}

impl io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let status = self.event_loop(Some(buf))?;

        if !status.did_send {
            let written = self.sock.write(&self.outgoing_tls)?;
            self.outgoing_tls.drain(0..written);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.outgoing_tls.is_empty() {
            self.sock
                .write_all(&self.outgoing_tls)?;
            self.outgoing_tls.clear();
        }

        Ok(())
    }
}
