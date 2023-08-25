#![cfg_attr(not(test), no_std)]
#![allow(warnings)]

extern crate alloc;

use core::{fmt, ops};

use alloc::vec::Vec;
use status::Status;

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
        let mut status = Status::default();

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
                    mock::append(236, "HS::ClientHello", _outgoing_tls);

                    status.wants_write = true;
                    status.wants_read = true;
                }

                1 => {
                    mock::process(127, "HS::ServerHello", &mut incoming_tls_new_end);

                    mock::append(6, "ChangeCipherSpec", _outgoing_tls);

                    mock::process(6, "ChangeCipherSpec", &mut incoming_tls_new_end);
                    mock::process(
                        32,
                        "encrypted HS::EncryptedExtensions",
                        &mut incoming_tls_new_end,
                    );
                    mock::process(1055, "encrypted HS::Certificate", &mut incoming_tls_new_end);
                    mock::process(
                        286,
                        "encrypted HS::CertificateVerify",
                        &mut incoming_tls_new_end,
                    );

                    // FIXME this should not happen inside `handshake` because it may perform IO
                    eprintln!("verified server certificate");

                    mock::process(74, "encrypted HS::Finished", &mut incoming_tls_new_end);

                    mock::append(79, "encrypted HS::Finished", _outgoing_tls);

                    status.may_send_app_data = true;
                    status.wants_write = true;
                    status.wants_read = true;
                }

                2 => {
                    for _ in 0..4 {
                        mock::process(
                            103,
                            "encrypted HS::NewSessionTicket",
                            &mut incoming_tls_new_end,
                        );
                    }

                    // next record is an application-data one; it won't be processed here
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
                    status.wants_read = true;
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

                    status.wants_write = true;
                    status.wants_read = true;
                }

                2 => {
                    mock::process(6, "ChangeCipherSpec", &mut incoming_tls_new_end);

                    mock::process(74, "encrypted HS::Finished", &mut incoming_tls_new_end);

                    for _ in 0..4 {
                        mock::append(103, "encrypted HS::NewSessionTicket", _outgoing_tls)
                    }

                    status.wants_write = true;

                    status.may_send_app_data = true;
                    // peeking into `incoming_tls` shows that there's an app-data record
                    status.received_app_data = true;
                }

                i => unreachable!("unexpected ServerState: {i}"),
            }
        }

        _incoming_tls.discard_handshake_data(incoming_tls_new_end);

        Ok(status)
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
}

pub struct LlClientConnection {
    conn: LlConnectionCommon,
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

impl LlClientConnection {
    pub fn new(_server_name: &str) -> Self {
        Self {
            conn: LlConnectionCommon {
                #[cfg(test)]
                is_client: true,
            },
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
                    1 => 1580,
                    2 => 531,

                    i => unreachable!("unexpected ClientState: {i}"),
                }
            } else {
                match ServerState.current() {
                    1 => 236,
                    2 => 183,

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
        let domain_name = "localhost";
        let sock = MockTcpStream::connect(&format!("{domain_name}:443"))?;
        let mut conn = LlClientConnection::new(domain_name);

        let mut incoming_tls = IncomingTls::new(vec![0; MAX_HANDSHAKE_SIZE]);
        let mut outgoing_tls = Vec::new();

        let mut some_request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\
             \r\n",
            domain_name
        )
        .into_bytes();

        let mut wants_read = false;
        let mut did_send_app_data = false;
        while !did_send_app_data || wants_read {
            let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls)?;

            if status.may_send_early_data() {
                let some_early_data = b"0-RTT packet";
                conn.encrypt_early_data(some_early_data, &mut outgoing_tls);
            }

            let mut wants_to_send_app_data = false;
            if status.may_send_app_data() && !some_request.is_empty() {
                conn.encrypt_outgoing(&some_request, &mut outgoing_tls);
                wants_to_send_app_data = true;
                // ensure we don't send this more than once
                some_request.clear();
            }

            if status.wants_write() || wants_to_send_app_data {
                sock.write_all(&outgoing_tls)?;
                outgoing_tls.clear();

                if wants_to_send_app_data {
                    did_send_app_data = true;
                }
            }

            wants_read = status.wants_read();
            if wants_read {
                let read = sock.read(incoming_tls.unfilled())?;
                incoming_tls.advance(read);
            }
        }

        // this should have been fully flushed
        assert!(outgoing_tls.is_empty());

        if !did_send_app_data {
            conn.encrypt_outgoing(&some_request, &mut outgoing_tls);

            sock.write_all(&outgoing_tls)?;
        }

        if incoming_tls.buf.is_empty() {
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
        while !did_respond {
            let status = conn.handle_tls_records(&mut incoming_tls, &mut outgoing_tls)?;

            if status.received_app_data() {
                let incoming_app_data = conn.decrypt_incoming(&mut incoming_tls);
                let mut num_bytes_read = 0;
                for res in incoming_app_data {
                    let request = res?;

                    num_bytes_read += request.len();
                    if status.may_send_app_data() {
                        let response = handle(request);
                        conn.encrypt_outgoing(&response, &mut outgoing_tls);
                        did_respond = true;
                    } else {
                        // not reachable in this example but in this branch the data should likely
                        // be buffered for later processing
                    }
                }

                incoming_tls.discard_app_data(num_bytes_read);
            }

            if status.wants_write() {
                sock.write_all(&outgoing_tls)?;
                outgoing_tls.clear();
            }

            if status.wants_read() {
                let read = sock.read(incoming_tls.unfilled())?;
                incoming_tls.advance(read);
            }
        }

        // this should have been fully flushed
        assert!(outgoing_tls.is_empty());

        assert!(did_respond);

        Ok(())
    }
}
