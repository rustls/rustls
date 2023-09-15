//! Example re-implementation of `rustls::Stream` (v0.21.6) on top of
//! the proposed `LlConnection` API

use core::mem;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use alloc::sync::Arc;

use crate::{
    AppDataRecord, CertificateEntry, DigitallySignedStruct, EncryptError, LlClientConnection,
    ServerCertVerifier, State, Status, TlsError, VerificationOutcome, WebPkiServerCertVerifier,
};

impl From<TlsError> for io::Error {
    fn from(err: TlsError) -> Self {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    }
}

pub struct Stream {
    cert_verifier: WebPkiServerCertVerifier,
    certificates: Vec<CertificateEntry<'static>>,
    conn: LlClientConnection,
    dss: Option<DigitallySignedStruct<'static>>,
    early_data: Vec<u8>,
    incoming_tls: Vec<u8>,
    incoming_used: usize,
    outgoing_tls: Vec<u8>,
    outgoing_used: usize,
    received_plaintext: Vec<u8>,
    server_name: Arc<str>,
    sock: TcpStream,
}

impl Stream {
    pub fn new(sock: TcpStream, conn: LlClientConnection) -> Self {
        let server_name = conn.server_name.clone();
        Self {
            cert_verifier: WebPkiServerCertVerifier,
            certificates: vec![],
            conn,
            dss: None,
            early_data: vec![],
            incoming_tls: vec![],
            incoming_used: 0,
            outgoing_tls: vec![],
            outgoing_used: 0,
            received_plaintext: vec![],
            server_name,
            sock,
        }
    }

    fn event_loop(
        &mut self,
        mut rd_buf: Option<&mut [u8]>,
        mut wr_buf: Option<&[u8]>,
    ) -> io::Result<usize> {
        let mut num_bytes = 0;

        while rd_buf.is_some() || wr_buf.is_some() {
            let Status { mut discard, state } = self
                .conn
                .process_tls_records(&mut self.incoming_tls)?;

            match state {
                State::NeedsSupportedVerifySchemes(mut conn) => {
                    let schemes = self
                        .cert_verifier
                        .supported_verify_schemes();
                    conn.add_supported_verify_schemes(schemes);
                }

                State::MustEncryptTlsData(mut encrypter) => {
                    let res = encrypter.encrypt(&mut self.outgoing_tls[self.outgoing_used..]);

                    match res {
                        Ok(written) => {
                            self.outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            // example of on-the-fly buffer resizing
                            let new_len = self.outgoing_used + required_size;
                            self.outgoing_tls.resize(new_len, 0);

                            // don't forget to encrypt the handshake record after resizing!
                            let written = encrypter
                                .encrypt(&mut self.outgoing_tls[self.outgoing_used..])
                                .expect("should not fail this time");

                            self.outgoing_used += written;
                        }
                    }
                }

                State::AppDataAvailable(records) => {
                    for res in records {
                        let AppDataRecord {
                            discard: new_discard,
                            payload,
                        } = res?;

                        if let Some(buf) = rd_buf.take() {
                            if payload.len() < buf.len() {
                                let (head, tail) = buf.split_at_mut(payload.len());
                                head.copy_from_slice(payload);
                                num_bytes += payload.len();

                                rd_buf = Some(tail);
                            } else {
                                let (head, tail) = payload.split_at(buf.len());
                                buf.copy_from_slice(head);
                                num_bytes += buf.len();

                                self.received_plaintext
                                    .extend_from_slice(tail);
                            }
                        } else {
                            self.received_plaintext
                                .extend_from_slice(payload);
                        }

                        discard += new_discard.get();
                    }

                    // break the event loop to prevent doing more than one `self.sock.read` per
                    // `Read::read`
                    rd_buf = None;
                }

                State::EarlyDataAvailable(_) => todo!(),

                State::MayEncryptAppData(mut encrypter) => {
                    if let Some(wr_buf) = wr_buf.take() {
                        let res = encrypter.encrypt(wr_buf, &mut self.outgoing_tls);

                        match res {
                            Ok(written) => {
                                self.outgoing_used += written;
                            }

                            Err(EncryptError { required_size }) => {
                                // example of on-the-fly buffer resizing
                                let new_len = self.outgoing_used + required_size;
                                self.outgoing_tls.resize(new_len, 0);

                                // don't forget to encrypt the handshake record after resizing!
                                let written = encrypter
                                    .encrypt(wr_buf, &mut self.outgoing_tls[self.outgoing_used..])
                                    .expect("should not fail this time");

                                self.outgoing_used += written;
                            }
                        }
                    } else {
                        encrypter.done()
                    }
                }

                State::MayEncryptEarlyData(encrypter) => {
                    // encrypt `self.early_data` if needed

                    encrypter.done()
                }

                State::MustTransmitTlsData(conn) => {
                    self.sock
                        .write_all(&self.outgoing_tls[..self.outgoing_used])?;

                    self.outgoing_used = 0;

                    conn.done()
                }

                State::NeedsMoreTlsData { num_bytes } => {
                    // XXX real code needs to handle resizing
                    let read = self
                        .sock
                        .read(&mut self.incoming_tls[self.incoming_used..])?;

                    self.incoming_used += read;
                }

                State::NeedsSignature(state) => {
                    let message = state.message();

                    let mut certificates = mem::take(&mut self.certificates);
                    if certificates.is_empty() {
                        return Err(TlsError::Fatal.into());
                    }
                    let end_entity = certificates.remove(0);
                    let intermediates = certificates;

                    // normally, this would come from the `ext` field of `end_entity` but it was not mocked
                    let ocsp_response = &[];

                    let intermediates = intermediates
                        .into_iter()
                        .map(|entry| entry.cert)
                        .collect::<Vec<_>>();

                    let cert_verified = self.cert_verifier.verify_server_cert(
                        &end_entity.cert,
                        &intermediates,
                        &self.server_name,
                        ocsp_response,
                    )?;

                    let dss = self.dss.take().ok_or(TlsError::Fatal)?;
                    let sig_verified = self
                        .cert_verifier
                        .verify_tls13_signature(message, &end_entity.cert, &dss)?;

                    let verification_outcome = VerificationOutcome::Valid {
                        cert_verified,
                        sig_verified,
                    };

                    state.done(verification_outcome);
                }

                State::ReceivedCertificate(record) => {
                    let new_certificates = record.decrypt();

                    for certificate in new_certificates {
                        self.certificates
                            .push(certificate?.into_owned())
                    }
                }

                State::ReceivedSignature(record) => {
                    self.dss = Some(record.decrypt()?.into_owned());
                }

                State::TrafficTransit(mut conn) => {
                    if let Some(wr_buf) = wr_buf.take() {
                        let res = conn.encrypt(wr_buf, &mut self.outgoing_tls);

                        match res {
                            Ok(written) => {
                                self.outgoing_used += written;
                            }

                            Err(EncryptError { required_size }) => {
                                let new_len = self.outgoing_used + required_size;
                                self.outgoing_tls.resize(new_len, 0);
                                eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                                let written = conn
                                    .encrypt(wr_buf, &mut self.outgoing_tls[self.outgoing_used..])
                                    .expect("should not fail this time");

                                self.outgoing_used += written;
                            }
                        }

                        self.sock
                            .write_all(&self.outgoing_tls[..self.outgoing_used])?;
                        self.outgoing_used = 0;
                        num_bytes = wr_buf.len();
                    }
                }
            }

            // discard TLS record
            if discard != 0 {
                debug_assert!(discard <= self.incoming_used);

                self.incoming_tls
                    .copy_within(discard..self.incoming_used, 0);
                self.incoming_used -= discard;
            }
        }

        Ok(num_bytes)
    }
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.event_loop(Some(buf), None)
    }
}

impl io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.event_loop(None, Some(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}
