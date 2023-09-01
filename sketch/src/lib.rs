#![cfg_attr(not(test), no_std)]
#![allow(warnings)]

extern crate alloc;

use core::{fmt, ops};

use alloc::{string::String, vec, vec::Vec};
use status::{Capabilities, State, Status};

pub use crate::incoming::{IncomingAppData, IncomingTls};
#[cfg(test)]
use crate::mock::{ClientState, ServerState};

mod incoming;
#[cfg(test)]
mod mock;
mod status;
#[cfg(test)] // this would be `cfg(feature = "std")` in the real rustls
pub mod stream;

const ENCRYPTED_TLS_SIZE_OVERHEAD: usize = 22;
const MAX_HANDSHAKE_SIZE: usize = 0xffff;

type Result<T> = core::result::Result<T, Error>;

pub trait ServerCertVerifier: Send + Sync {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        ocsp_response: &[u8],
        // now: SystemTime,
    ) -> Result<ServerCertVerified>;

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid>;

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid>;

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;
}

#[derive(Debug)]
pub enum Error {
    Fatal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fatal TLS error")
    }
}

pub struct LlConnectionCommon {
    #[cfg(test)]
    is_client: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SignatureScheme;

#[derive(Clone, Copy, Debug)]
pub struct Certificate;

#[derive(Clone, Debug)]
pub struct CertificateEntry {
    pub cert: Certificate,
    pub exts: Vec<CertificateExtension>,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificateExtension;

#[derive(Clone, Copy, Debug)]
pub struct DigitallySignedStruct;

pub struct ServerCertVerified;

#[derive(Clone, Copy, Debug)]
pub enum ProtocolVersion {
    TLSv1_2,
    TLSv1_3,
}

impl LlConnectionCommon {
    /// Handles TLS-level records
    ///
    /// This method must always be called and its returned `Status` checked prior to
    /// calling either `encrypt_outgoing` or `decrypt_incoming`
    pub fn handle_tls_records<B>(
        &mut self,
        _incoming_tls: &mut IncomingTls<B>,
        _outgoing_tls: &mut Vec<u8>,
    ) -> Result<Status>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut caps = Capabilities::default();
        let mut state = State::TrafficTransit;

        let mut incoming_tls_new_end = 0;

        #[cfg(test)]
        if self.is_client {
            eprintln!(
                "\n<<<LlClientConnection::handle_tls_records>>>
found {}B of data in incoming_tls",
                _incoming_tls.filled().len()
            );

            match ClientState.advance() {
                0 => {
                    state = State::NeedsSupportedVerifySchemes;
                }

                1 => {
                    mock::append(236, "HS::ClientHello", _outgoing_tls);

                    state = State::MustTransmitTlsData;
                }

                2 => {
                    state = State::NeedsMoreTlsData;
                }

                3 => {
                    mock::process(127, "HS::ServerHello", &mut incoming_tls_new_end);

                    mock::append(6, "ChangeCipherSpec", _outgoing_tls);

                    mock::process(6, "ChangeCipherSpec", &mut incoming_tls_new_end);
                    mock::process(
                        32,
                        "encrypted HS::EncryptedExtensions",
                        &mut incoming_tls_new_end,
                    );
                    mock::process(1055, "encrypted HS::Certificate", &mut incoming_tls_new_end);

                    state = State::ReceivedCertificate(vec![CertificateEntry {
                        cert: Certificate,
                        exts: vec![],
                    }]);
                }

                4 => {
                    mock::process(
                        286,
                        "encrypted HS::CertificateVerify",
                        &mut incoming_tls_new_end,
                    );

                    state = State::ReceivedSignature(DigitallySignedStruct);
                }

                5 => {
                    state = State::NeedsSignature {
                        message: vec![],
                        version: ProtocolVersion::TLSv1_3,
                    };
                }

                6 => {
                    mock::process(74, "encrypted HS::Finished", &mut incoming_tls_new_end);
                    mock::append(79, "encrypted HS::Finished", _outgoing_tls);

                    caps.may_encrypt_app_data = true;

                    state = State::MustTransmitTlsData;
                }

                7 => {
                    state = State::NeedsMoreTlsData;
                }

                8 => {
                    for _ in 0..4 {
                        mock::process(
                            103,
                            "encrypted HS::NewSessionTicket",
                            &mut incoming_tls_new_end,
                        );
                    }

                    state = State::ReceivedAppData;
                }

                i => {
                    unreachable!("unexpected ClientState: {i}")
                }
            }
        } else {
            eprintln!(
                "\n<<<LlServerConnection::handle_tls_records>>>
{}B of data in incoming_tls",
                _incoming_tls.filled().len()
            );

            match ServerState.advance() {
                0 => {
                    // need a ClientHello to start the handshake
                    state = State::NeedsMoreTlsData;
                }

                1 => {
                    mock::process(236, "HS::ClientHello", &mut incoming_tls_new_end);

                    mock::append(127, "HS::ServerHello", _outgoing_tls);
                    mock::append(6, "ChangeCipherSpec", _outgoing_tls);
                    for (size, packet_type) in [
                        (32, "HS::EncryptedExtensions"),
                        (1055, "HS::Certificate"),
                        (286, "HS::CertificateVerify"),
                        (74, "HS::Finished"),
                    ] {
                        mock::append(size, packet_type, _outgoing_tls);
                    }

                    state = State::MustTransmitTlsData;
                }

                2 => {
                    state = State::NeedsMoreTlsData;
                }

                3 => {
                    mock::process(6, "ChangeCipherSpec", &mut incoming_tls_new_end);

                    mock::process(74, "encrypted HS::Finished", &mut incoming_tls_new_end);

                    for _ in 0..4 {
                        mock::append(103, "encrypted HS::NewSessionTicket", _outgoing_tls)
                    }

                    caps.may_encrypt_app_data = true;

                    // peeking into `incoming_tls` shows that there's an app-data record
                    // favor that over flushing the current `outgoing_tls`
                    state = State::ReceivedAppData;
                }

                6 => {
                    state = State::MustTransmitTlsData;
                }

                7 => {
                    state = State::TrafficTransit;
                }

                i => unreachable!("unexpected ServerState: {i}"),
            }
        }

        _incoming_tls.discard_handshake_data(incoming_tls_new_end);

        #[cfg(test)]
        eprintln!("state: {state:?}");

        Ok(Status { caps, state })
    }

    /// Encrypts `app_data` into the `outgoing_tls` buffer
    pub fn encrypt_outgoing(&self, _app_data: &[u8], _outgoing_tls: &mut Vec<u8>) {
        let before = _app_data.len();
        let after = before + ENCRYPTED_TLS_SIZE_OVERHEAD;
        _outgoing_tls.extend_from_slice(_app_data);
        _outgoing_tls.extend(core::iter::repeat(0).take(ENCRYPTED_TLS_SIZE_OVERHEAD));

        #[cfg(test)]
        eprintln!("encrypted {before}B of app data and appended {after}B to outgoing_tls")
    }

    /// Decrypts the application data in the `incoming_tls` buffer
    pub fn decrypt_incoming<'a, B>(
        &self,
        incoming_tls: &'a mut IncomingTls<B>,
    ) -> IncomingAppData<'a, B> {
        IncomingAppData {
            _incoming_tls: incoming_tls,
            #[cfg(test)]
            is_client: self.is_client,
        }
    }

    /// Provide the verify schemes supported by the certificate verifier
    pub fn add_supported_verify_schemes(&mut self, _schemes: Vec<SignatureScheme>) {
        #[cfg(test)]
        eprintln!("added {} verify schemes", _schemes.len());
    }

    /// Provide the result of the certificate verification process
    pub fn certificate_verification_outcome(&mut self, outcome: CertificateVerificationOutcome) {}
}

/// The outcome of the certificate verification process
pub enum CertificateVerificationOutcome {
    Success {
        cert_verified: ServerCertVerified,
        sig_verified: HandshakeSignatureValid,
    },

    Failure,
}

pub struct HandshakeSignatureValid;

pub struct LlClientConnection {
    conn: LlConnectionCommon,
    server_name: String,
}

impl ops::Deref for LlClientConnection {
    type Target = LlConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl ops::DerefMut for LlClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

pub type ServerName = str;

impl LlClientConnection {
    pub fn new(server_name: &ServerName) -> Self {
        Self {
            conn: LlConnectionCommon {
                #[cfg(test)]
                is_client: true,
            },
            server_name: String::from(server_name),
        }
    }

    /// Encrypts `early_data` and appends it to the `outgoing_tls` buffer
    pub fn encrypt_early_data(&mut self, _early_data: &[u8], _outgoing_tls: &mut Vec<u8>) {}
}

pub struct LlServerConnection {
    conn: LlConnectionCommon,
}

impl ops::Deref for LlServerConnection {
    type Target = LlConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl ops::DerefMut for LlServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl LlServerConnection {
    pub fn new() -> Self {
        Self {
            conn: LlConnectionCommon {
                #[cfg(test)]
                is_client: false,
            },
        }
    }

    /// Decrypts the early ("0-RTT") record that's in the front of the `incoming_tls` buffer
    ///
    /// returns `None` if a record of said type is not available
    pub fn decrypt_early_data<'a, B>(
        &mut self,
        incoming_tls: &'a mut IncomingTls<B>,
    ) -> Option<Result<&'a [u8]>>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        None
    }

    /// Discards the early ("0-RTT") record that's in the front of the `incoming_tls` buffer
    pub fn discard_early_data(&mut self) {}
}

pub struct WebPkiServerCertVerifier;

impl ServerCertVerifier for WebPkiServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        ocsp_response: &[u8],
        // now: SystemTime,
    ) -> Result<ServerCertVerified> {
        #[cfg(test)]
        eprintln!("verified the server certificate of {server_name}");

        Ok(ServerCertVerified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid> {
        #[cfg(test)]
        eprintln!("signed TLS 1.2 message");

        Ok(HandshakeSignatureValid)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid> {
        #[cfg(test)]
        eprintln!("signed TLS 1.3 message");

        Ok(HandshakeSignatureValid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme; 9]
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    struct MockTcpStream {
        is_client: bool,
    }

    impl MockTcpStream {
        fn connect(_addr: &str) -> io::Result<Self> {
            Ok(Self { is_client: true })
        }

        fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
            eprintln!("\nwrote {}B to socket", bytes.len());
            Ok(())
        }

        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            let num_bytes = if self.is_client {
                match ClientState.current() {
                    3 => 1580,
                    8 => 531,

                    i => unreachable!("unexpected ClientState: {i}"),
                }
            } else {
                match ServerState.current() {
                    1 => 236,
                    3 => 183,

                    i => unreachable!("unexpected ServerState: {i}"),
                }
            };

            eprintln!("\nread {num_bytes}B from socket");
            Ok(num_bytes)
        }

        fn read_to_end(&self, _buf: &mut [u8]) -> io::Result<()> {
            Ok(())
        }
    }

    // this is a replay of tlsclient-mio interacting with tlsserver-mio
    #[test]
    fn simple_client() -> io::Result<()> {
        let server_name = "localhost";
        let sock = MockTcpStream::connect(&format!("{server_name}:443"))?;
        let mut conn = LlClientConnection::new(server_name);

        let mut incoming_tls = IncomingTls::new(vec![0; MAX_HANDSHAKE_SIZE]);
        let mut outgoing_tls = Vec::new();

        let mut some_request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\
             \r\n",
            server_name
        )
        .into_bytes();

        let cert_verifier = WebPkiServerCertVerifier;
        let mut certificates = vec![];
        let mut dss = None;

        let mut wants_read = false;
        let mut did_send_app_data = false;
        loop {
            let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls)?;

            match status.state {
                State::NeedsSupportedVerifySchemes => {
                    let schemes = cert_verifier.supported_verify_schemes();
                    conn.add_supported_verify_schemes(schemes);
                }

                State::MustTransmitTlsData => {
                    if status.caps.may_encrypt_app_data {
                        if !some_request.is_empty() {
                            conn.encrypt_outgoing(&some_request, &mut outgoing_tls);
                            did_send_app_data = true;

                            some_request.clear();
                        }
                    }

                    sock.write_all(&outgoing_tls)?;
                    outgoing_tls.clear();
                }

                State::NeedsMoreTlsData => {
                    let read = sock.read(incoming_tls.unfilled())?;
                    incoming_tls.advance(read);
                }

                State::ReceivedCertificate(new_certificates) => {
                    // NOTE here, an async CertVerifier could have started cert verification in a separate async task
                    certificates.extend(new_certificates);
                }

                State::ReceivedSignature(new_dss) => dss = Some(new_dss),

                State::NeedsSignature { message, version } => {
                    let (end_entity, intermediates) = certificates
                        .split_first()
                        .ok_or(Error::Fatal)?;

                    // normally, this would come from the `ext` field of `end_entity` but it was not mocked
                    let ocsp_response = &[];

                    let intermediates = intermediates
                        .iter()
                        .map(|entry| entry.cert)
                        .collect::<Vec<_>>();

                    let cert_verified = cert_verifier.verify_server_cert(
                        &end_entity.cert,
                        &intermediates,
                        server_name,
                        ocsp_response,
                    )?;

                    let dss = dss.as_ref().ok_or(Error::Fatal)?;
                    let sig_verified =
                        cert_verifier.verify_tls13_signature(&message, &end_entity.cert, dss)?;

                    let outcome = CertificateVerificationOutcome::Success {
                        cert_verified,
                        sig_verified,
                    };
                    conn.certificate_verification_outcome(outcome);
                }

                // both indicate a complete handshake
                State::ReceivedAppData | State::TrafficTransit => break,

                State::ReceivedEarlyData => {
                    // server-only state
                    unreachable!()
                }
            }
        }

        // this should have been fully flushed
        assert!(outgoing_tls.is_empty());

        if !did_send_app_data {
            // not reachable in this TLS 1.3 example
            conn.encrypt_outgoing(&some_request, &mut outgoing_tls);

            sock.write_all(&outgoing_tls)?;
        }

        if incoming_tls.buf.is_empty() {
            // not reachable in this TLS 1.3 example
            sock.read_to_end(&mut incoming_tls.buf)?;
        } else {
            // server responded to the request during the previous loop and the response is
            // already in the `IncomingTls` buffer
        }

        let messages = conn.decrypt_incoming(&mut incoming_tls);

        let mut did_get_a_response = false;
        let mut num_read_bytes = 0;
        for res in messages {
            let message = res?;
            eprintln!("\ngot a response record");
            num_read_bytes += message.len();
            did_get_a_response = true;
        }

        // not strictly necessary in this example as the buffer won't be used anymore
        // NOTE this should not be run inside the loop to avoid unnecessary memcpy-ing
        incoming_tls.discard_app_data(num_read_bytes);

        assert!(did_get_a_response);

        // it's possible to resize the TLS buffer but care must be taken not to discard TLS data
        if incoming_tls.filled().is_empty() {
            println!("resizing IncomingTls buffer");

            let mut buf = incoming_tls.into_inner();
            buf.shrink_to(4 * 1024);
            let mut incoming_tls = IncomingTls::new(buf);
        }

        Ok(())
    }

    // an async version of the above example should be about the same but with `write_all().await`
    // and `read().await` calls

    struct MockTcpListener {}

    struct StubSocketAddr;

    impl MockTcpListener {
        fn bind(_addr: &str) -> io::Result<Self> {
            Ok(Self {})
        }

        fn accept(&self) -> io::Result<(MockTcpStream, StubSocketAddr)> {
            Ok((MockTcpStream { is_client: false }, StubSocketAddr))
        }
    }

    // this is a replay of tlsserver-mio interacting with tlsclient-mio
    #[test]
    fn simple_server() -> io::Result<()> {
        fn handle(http_request: &[u8]) -> Vec<u8> {
            vec![0; 73]
        }

        let listener = MockTcpListener::bind("localhost:443")?;
        let (sock, _) = listener.accept()?;

        let mut conn = LlServerConnection::new();

        let mut incoming_tls = IncomingTls::new(vec![0; MAX_HANDSHAKE_SIZE]);
        let mut outgoing_tls = Vec::new();

        let mut did_respond = false;
        let mut must_transmit_app_data = false;
        loop {
            let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls)?;

            match status.state {
                State::NeedsMoreTlsData => {
                    let read = sock.read(incoming_tls.unfilled())?;
                    incoming_tls.advance(read);
                }

                State::MustTransmitTlsData => {
                    sock.write_all(&outgoing_tls)?;
                    outgoing_tls.clear();

                    if must_transmit_app_data {
                        did_respond = true;
                        must_transmit_app_data = false;
                    }
                }

                State::ReceivedAppData => {
                    let incoming_app_data = conn.decrypt_incoming(&mut incoming_tls);
                    let mut num_bytes_read = 0;
                    for res in incoming_app_data {
                        let request = res?;

                        num_bytes_read += request.len();
                        if status.caps.may_encrypt_app_data {
                            let response = handle(request);
                            conn.encrypt_outgoing(&response, &mut outgoing_tls);
                            must_transmit_app_data = true;
                        } else {
                            // not reachable in this example but in this branch the data should likely
                            // be buffered for later processing
                        }
                    }

                    incoming_tls.discard_app_data(num_bytes_read);
                }

                State::TrafficTransit => break,

                // client-only state
                State::NeedsSupportedVerifySchemes => todo!(),

                // not exercised in this example
                State::ReceivedEarlyData
                | State::ReceivedCertificate(_)
                | State::ReceivedSignature(_)
                | State::NeedsSignature { .. } => unreachable!(),
            }
        }

        // this should have been fully flushed
        assert!(outgoing_tls.is_empty());

        assert!(did_respond);

        Ok(())
    }
}
