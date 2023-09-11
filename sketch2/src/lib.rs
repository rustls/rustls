#![allow(dead_code)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, feature(read_buf))]

extern crate alloc;

use alloc::{borrow::Cow, vec, vec::Vec};
use core::{fmt, iter, num::NonZeroUsize, ops};

#[cfg(test)]
mod mock;

const ENCRYPTED_TLS_SIZE_OVERHEAD: usize = 22;

#[derive(Debug)]
pub enum TlsError {
    Fatal,
    // ..
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TLS error")
    }
}

#[cfg(test)]
impl std::error::Error for TlsError {}

pub type TlsResult<T> = Result<T, TlsError>;

pub struct LlClientConnection {
    inner: LlConnectionCommon,
}

impl ops::Deref for LlClientConnection {
    type Target = LlConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ops::DerefMut for LlClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl LlClientConnection {
    pub fn new(_server_name: &str) -> TlsResult<Self> {
        Ok(Self {
            inner: LlConnectionCommon {
                #[cfg(test)]
                is_client: true,
            },
        })
    }
}

pub struct LlConnectionCommon {
    #[cfg(test)]
    is_client: bool,
}

pub struct Status<'c, 'i> {
    pub discard: usize,
    pub state: State<'c, 'i>,
}

/// Handshake / connection state
pub enum State<'c, 'i> {
    /// An application data record is available
    // NOTE Alert records are implicitly handled by `process_tls_records` and not exposed through
    // this `enum`. Fatal alerts make `process_tls_records` return an `Err`or
    AppDataAvailable(AppDataAvailable<'c, 'i>),

    /// An early data record is available
    EarlyDataAvailable(EarlyDataAvailable<'c, 'i>),

    /// application data may be encrypted at this stage of the handshake
    MayEncryptAppData(MayEncryptAppData<'c>),

    /// early (0-RTT) data may be encrypted
    MayEncryptEarlyData(MayEncryptEarlyData<'c>),

    /// A Handshake record must be encrypted into the `outgoing_tls` buffer
    MustEncryptTlsData(MustEncryptTlsData<'c>),

    /// TLS records related to the handshake have been placed in the `outgoing_tls` buffer and must
    /// be transmitted to continue with the handshake process
    MustTransmitTlsData(MustTransmitTlsData<'c>),

    /// More TLS data needs to be added to the `incoming_tls` buffer to continue with the handshake
    NeedsMoreTlsData {
        /// number of bytes required to complete a TLS record. `None` indicates that
        /// no information is available
        num_bytes: Option<NonZeroUsize>,
    },

    /// Needs to send back the `message` signed. provide it with the either `handshake_signature`
    NeedsSignature(NeedsSignature<'c>),

    /// the supported verify schemes must be provided using to continue with the handshake
    NeedsSupportedVerifySchemes(NeedsSupportedVerifySchemes<'c>),

    /// Received a `Certificate` message
    ReceivedCertificate(ReceivedCertificate<'c, 'i>),

    /// Received a `ServerKeyExchange` (TLS 1.2) / `CertificateVerify` (TLS 1.3) message
    ReceivedSignature(ReceivedSignature<'c, 'i>),

    /// Handshake is complete.
    TrafficTransit(TrafficTransit<'c>),
    // NOTE omitting certificate verification variants for now
}

impl State<'_, '_> {
    fn variant_name(&self) -> &str {
        match self {
            State::AppDataAvailable(_) => "AppDataAvailable",
            State::EarlyDataAvailable(_) => "EarlyDataAvailable",
            State::MayEncryptAppData(_) => "MayEncryptAppData",
            State::MayEncryptEarlyData(_) => "MayEncryptEarlyData",
            State::MustEncryptTlsData(_) => "MustEncryptTlsData",
            State::MustTransmitTlsData(_) => "MustTransmitTlsData",
            State::NeedsMoreTlsData { .. } => "NeedsMoreTlsData",
            State::NeedsSignature(_) => "NeedsSignature",
            State::NeedsSupportedVerifySchemes(_) => "NeedsSupportedVerifySchemes",
            State::ReceivedCertificate(_) => "ReceivedCertificate",
            State::ReceivedSignature(_) => "ReceivedSignature",
            State::TrafficTransit(_) => "TrafficTransit",
        }
    }
}

/// A single TLS record containing application data
pub struct AppDataAvailable<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> AppDataAvailable<'c, 'i> {
    // decrypts the first record in `_incoming_tls` in-place and returns a slice into its payload
    // this advances `incoming_tls`'s cursor *fully* discarding the TLS record
    pub fn decrypt(self) -> TlsResult<&'i [u8]> {
        #[cfg(test)]
        mock::ClientState.advance();

        Ok(&[])
    }
}

/// A single TLS record containing early data
pub struct EarlyDataAvailable<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> EarlyDataAvailable<'c, 'i> {
    // decrypts the first record in `_incoming_tls` in-place and returns a slice into its payload
    // this advances `incoming_tls`'s cursor *fully* discarding the TLS record
    pub fn decrypt(self) -> TlsResult<&'i [u8]> {
        todo!()
    }

    // XXX consider adding a `discard` method to drop the entire early-data record (and advance
    // incoming_tls's cursor) without decrypting the record
}

/// provided `outgoing_tls` buffer is too small
#[derive(Debug)]
pub struct EncryptError {
    /// buffer must be at least this size
    pub required_size: usize,
}

pub struct MayEncryptAppData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MayEncryptAppData<'c> {
    /// Encrypts `app_data` into the `outgoing_tls` buffer
    ///
    /// returns the part of `outgoing_tls` that was not used, or an error if the provided buffer was
    /// too small
    // XXX can more than one application data record be sent during the same handshake round-trip?
    // if not, then this can take `self` by value
    pub fn encrypt(
        &mut self,
        _app_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        let before = _app_data.len();
        let after = before + ENCRYPTED_TLS_SIZE_OVERHEAD;

        if _outgoing_tls.len() < after {
            Err(EncryptError {
                required_size: after,
            })
        } else {
            #[cfg(test)]
            eprintln!("encrypted {before}B of app data and appended {after}B to outgoing_tls");

            Ok(after)
        }
    }

    /// Continue with the handshake process
    pub fn done(self) {
        #[cfg(test)]
        mock::ClientState.advance();
    }
}

pub struct MayEncryptEarlyData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MayEncryptEarlyData<'c> {
    /// Encrypts `early_data` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        _early_data: &[u8],
        _outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        todo!()
    }

    /// Continue with the handshake process
    pub fn done(self) {}
}

pub struct MustEncryptTlsData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> MustEncryptTlsData<'c> {
    /// Encrypts a handshake record into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    // calling this again does nothing
    pub fn encrypt(&mut self, _outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        let mut used = 0;

        #[cfg(test)]
        if self._conn.is_client {
            match mock::ClientState.current() {
                1 => {
                    used += mock::append(236, "HS::ClientHello", _outgoing_tls)?;
                }

                4 => {
                    used += mock::append(6, "ChangeCipherSpec", _outgoing_tls)?;
                }

                8 => {
                    used += mock::append(79, "encrypted HS::FInished", _outgoing_tls)?;
                }

                state => unimplemented!("client state: {state}"),
            }

            mock::ClientState.advance();
        } else {
            unimplemented!()
        }

        Ok(used)
    }

    // no `done` method because successfully encrypting advances the state machine
}

pub struct MustTransmitTlsData<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl MustTransmitTlsData<'_> {
    pub fn done(self) {
        #[cfg(test)]
        mock::ClientState.advance();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SignatureScheme;

pub enum VerificationOutcome {
    Valid {
        cert_verified: ServerCertVerified,
        sig_verified: HandshakeSignatureValid,
    },

    Failed,
}

pub struct NeedsSignature<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl NeedsSignature<'_> {
    /// Message that needs to be signed
    pub fn message(&self) -> &[u8] {
        &[]
    }

    pub fn done(self, _verification_outcome: VerificationOutcome) {
        #[cfg(test)]
        mock::ClientState.advance();
    }
}

pub struct NeedsSupportedVerifySchemes<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl NeedsSupportedVerifySchemes<'_> {
    pub fn add_supported_verify_schemes(&mut self, _schemes: Vec<SignatureScheme>) {
        #[cfg(test)]
        {
            eprintln!("added {} verify schemes", _schemes.len());

            if self._conn.is_client {
                mock::ClientState.advance();
            }
        }
    }
}

pub struct ReceivedCertificate<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> ReceivedCertificate<'c, 'i> {
    pub fn decrypt(self) -> impl Iterator<Item = TlsResult<CertificateEntry<'i>>> {
        #[cfg(test)]
        mock::ClientState.advance();

        iter::once(Ok(CertificateEntry {
            cert: Certificate(Cow::Borrowed(&[])),
            exts: vec![],
        }))
    }
}

pub struct ReceivedSignature<'c, 'i> {
    _conn: &'c mut LlConnectionCommon,
    _incoming_tls: &'i mut [u8],
}

impl<'c, 'i> ReceivedSignature<'c, 'i> {
    pub fn decrypt(self) -> TlsResult<DigitallySignedStruct<'i>> {
        #[cfg(test)]
        mock::ClientState.advance();

        Ok(DigitallySignedStruct {
            sig: PayloadU16(Cow::Borrowed(&[])),
        })
    }
}

/// Handshake complete
pub struct TrafficTransit<'c> {
    _conn: &'c mut LlConnectionCommon,
}

impl<'c> TrafficTransit<'c> {
    /// Encrypts `outgoing_plaintext` into the `outgoing_tls` buffer
    ///
    /// returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer was too small. in the error case, `outgoing_tls` is not modified
    pub fn encrypt<'o>(
        &mut self,
        _outgoing_plaintext: &[u8],
        _outgoing_tls: &'o mut [u8],
    ) -> Result<&'o mut [u8], EncryptError> {
        todo!()
    }
}

impl LlConnectionCommon {
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        // NOTE using `&mut [u8]` for simplicity / brevity but this still needs to be `IncomingTls`
        // or an `enum` to support the `read_buf` API (`std::io::BorrowedBuf`)
        _incoming_tls: &'i mut [u8],
    ) -> TlsResult<Status<'c, 'i>> {
        let mut discard = 0;

        #[cfg(not(test))]
        let state = State::NeedsMoreTlsData { num_bytes: None };

        #[cfg(test)]
        let state = if self.is_client {
            eprintln!(
                "\n<<<LlClientConnection::process_tls_records>>>
found {}B of data in incoming_tls",
                _incoming_tls.len()
            );

            match mock::ClientState.current() {
                0 => {
                    State::NeedsSupportedVerifySchemes(NeedsSupportedVerifySchemes { _conn: self })
                }

                1 => State::MustEncryptTlsData(MustEncryptTlsData { _conn: self }),

                2 => State::MustTransmitTlsData(MustTransmitTlsData { _conn: self }),

                3 => State::NeedsMoreTlsData { num_bytes: None },

                4 => {
                    discard += mock::process(127, "HS::ServerHello");

                    State::MustEncryptTlsData(MustEncryptTlsData { _conn: self })
                }

                5 => {
                    discard += mock::process(6, "ChangeCipherSpec");
                    discard += mock::process(32, "encrypted HS::EncryptedExtensions");
                    discard += mock::process(1055, "encrypted HS::Certificate");

                    State::ReceivedCertificate(ReceivedCertificate {
                        _conn: self,
                        _incoming_tls,
                    })
                }

                6 => {
                    discard += mock::process(286, "encrypted HS::CertificateVerify");

                    State::ReceivedSignature(ReceivedSignature {
                        _conn: self,
                        _incoming_tls,
                    })
                }

                7 => State::NeedsSignature(NeedsSignature { _conn: self }),

                8 => {
                    discard += mock::process(74, "encrypted HS::Finished");

                    State::MustEncryptTlsData(MustEncryptTlsData { _conn: self })
                }

                9 => State::MayEncryptAppData(MayEncryptAppData { _conn: self }),

                10 => State::MustTransmitTlsData(MustTransmitTlsData { _conn: self }),

                11 => State::NeedsMoreTlsData { num_bytes: None },

                12 => {
                    for _ in 0..4 {
                        discard += mock::process(103, "encrypted HS::NewSessionTicket");
                    }

                    discard += 95;

                    State::AppDataAvailable(AppDataAvailable {
                        _conn: self,
                        _incoming_tls,
                    })
                }

                13 => {
                    discard += mock::process(24, "encrypted Alert");

                    State::TrafficTransit(TrafficTransit { _conn: self })
                }

                state => unimplemented!("client state: {state}"),
            }
        } else {
            unimplemented!()
        };

        Ok(Status { discard, state })
    }
}

pub type ServerName = str;

#[derive(Clone, Debug)]
pub struct Certificate<'a>(pub Cow<'a, [u8]>);

#[derive(Clone, Debug)]
pub struct CertificateEntry<'a> {
    pub cert: Certificate<'a>,
    // XXX could be lazier / non-allocating?
    pub exts: Vec<CertificateExtension>,
}

impl CertificateEntry<'_> {
    pub fn into_owned(self) -> CertificateEntry<'static> {
        CertificateEntry {
            cert: Certificate(Cow::Owned(self.cert.0.into_owned())),
            exts: self.exts,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CertificateExtension;

#[derive(Clone, Debug)]
pub struct DigitallySignedStruct<'a> {
    sig: PayloadU16<'a>,
}

impl DigitallySignedStruct<'_> {
    pub fn into_owned(self) -> DigitallySignedStruct<'static> {
        DigitallySignedStruct {
            sig: PayloadU16(Cow::Owned(self.sig.0.into_owned())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PayloadU16<'a>(pub Cow<'a, [u8]>);

pub struct ServerCertVerified;

pub struct HandshakeSignatureValid;

#[derive(Clone, Copy, Debug)]
pub enum ProtocolVersion {
    TLSv1_2,
    TLSv1_3,
}

pub trait ServerCertVerifier: Send + Sync {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        ocsp_response: &[u8],
        // now: SystemTime,
    ) -> TlsResult<ServerCertVerified>;

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> TlsResult<HandshakeSignatureValid>;

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> TlsResult<HandshakeSignatureValid>;

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;
}

pub struct WebPkiServerCertVerifier;

impl ServerCertVerifier for WebPkiServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        server_name: &ServerName,
        _ocsp_response: &[u8],
        // now: SystemTime,
    ) -> TlsResult<ServerCertVerified> {
        #[cfg(test)]
        eprintln!("verified the server certificate of {server_name}");

        Ok(ServerCertVerified)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> TlsResult<HandshakeSignatureValid> {
        #[cfg(test)]
        eprintln!("signed TLS 1.2 message");

        Ok(HandshakeSignatureValid)
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> TlsResult<HandshakeSignatureValid> {
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
    use core::mem::MaybeUninit;
    use std::{
        error::Error,
        io::{self, BorrowedBuf, BorrowedCursor},
    };

    use super::*;

    struct AsyncTcpStream {
        is_client: bool,
    }

    impl AsyncTcpStream {
        async fn connect(_addr: &str) -> io::Result<Self> {
            Ok(Self { is_client: true })
        }

        async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            eprintln!("\nwrote {}B to socket", bytes.len());
            Ok(())
        }

        async fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            let num_bytes = if self.is_client {
                match mock::ClientState.advance() {
                    3 => 1580,

                    11 => 531,

                    state => unimplemented!("client state: {state}"),
                }
            } else {
                unimplemented!()
            };

            eprintln!("\nread {num_bytes}B from socket");
            Ok(num_bytes)
        }
    }

    // async + Vec
    async fn client_async_vec_() -> Result<(), Box<dyn Error>> {
        let server_name = "localhost";
        let port = 1433;

        let cert_verifier = WebPkiServerCertVerifier;
        let mut sock = AsyncTcpStream::connect(&format!("{server_name}:{port}")).await?;
        let mut conn = LlClientConnection::new(server_name)?;

        let mut outgoing_tls = vec![];
        let mut incoming_tls = [0; 2 * 1024];

        let mut outgoing_used = 0;
        let mut incoming_used = 0;
        let mut certificates = vec![];
        let mut dss = None;

        let max_iters = 32;
        for _ in 0..max_iters {
            let Status { discard, state } =
                conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

            eprintln!("state: {}", state.variant_name());

            match state {
                State::NeedsSupportedVerifySchemes(mut conn) => {
                    let schemes = cert_verifier.supported_verify_schemes();
                    conn.add_supported_verify_schemes(schemes);
                }

                State::MustEncryptTlsData(mut encrypter) => {
                    let res = encrypter.encrypt(&mut outgoing_tls[outgoing_used..]);

                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            // example of on-the-fly buffer resizing
                            let new_len = outgoing_used + required_size;
                            outgoing_tls.resize(new_len, 0);
                            eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                            // don't forget to encrypt the handshake record after resizing!
                            encrypter
                                .encrypt(&mut outgoing_tls[outgoing_used..])
                                .expect("should not fail this time");
                        }
                    }
                }

                State::MustTransmitTlsData(conn) => {
                    sock.write_all(&outgoing_tls[..outgoing_used]).await?;

                    outgoing_used = 0;

                    conn.done()
                }

                State::NeedsMoreTlsData { .. } => {
                    // XXX real code needs to handle resizing
                    let read = sock.read(&mut incoming_tls[incoming_used..]).await?;
                    incoming_used += read;
                }

                State::ReceivedCertificate(record) => {
                    let new_certificates = record.decrypt();

                    for certificate in new_certificates {
                        certificates.push(certificate?.into_owned())
                    }
                }

                State::ReceivedSignature(record) => {
                    dss = Some(record.decrypt()?.into_owned());
                }

                State::NeedsSignature(state) => {
                    let message = state.message();

                    let (end_entity, intermediates) =
                        certificates.split_first().ok_or(TlsError::Fatal)?;

                    // normally, this would come from the `ext` field of `end_entity` but it was not mocked
                    let ocsp_response = &[];

                    let intermediates = intermediates
                        .iter()
                        .map(|entry| entry.cert.clone())
                        .collect::<Vec<_>>();

                    let cert_verified = cert_verifier.verify_server_cert(
                        &end_entity.cert,
                        &intermediates,
                        server_name,
                        ocsp_response,
                    )?;

                    let dss = dss.as_ref().ok_or(TlsError::Fatal)?;
                    let sig_verified =
                        cert_verifier.verify_tls13_signature(message, &end_entity.cert, dss)?;

                    let verification_outcome = VerificationOutcome::Valid {
                        cert_verified,
                        sig_verified,
                    };

                    state.done(verification_outcome);
                }

                State::AppDataAvailable(record) => {
                    let _data = record.decrypt()?;
                    // do stuff with `data`
                }

                State::EarlyDataAvailable(record) => {
                    // unreachable since this is a clinet
                    let _early_data = record.decrypt()?;
                    // do stuff with `early_data`
                }

                State::MayEncryptAppData(mut encrypter) => {
                    let app_data = b"Hello, world!";
                    let res = encrypter.encrypt(app_data, &mut outgoing_tls[outgoing_used..]);
                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            let new_len = outgoing_used + required_size;
                            outgoing_tls.resize(new_len, 0);
                            eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                            // don't forget to encrypt `app_data` after resizing!
                            encrypter
                                .encrypt(app_data, &mut outgoing_tls[outgoing_used..])
                                .expect("should not fail this time");
                        }
                    }

                    encrypter.done();
                }

                State::TrafficTransit(_) => {
                    // post-handshake logic
                    return Ok(());
                }

                State::MayEncryptEarlyData(encrypter) => {
                    // not sending any early data in this example
                    encrypter.done();
                }
            }

            // discard TLS record
            if discard != 0 {
                assert!(discard <= incoming_used);

                incoming_tls.copy_within(discard..incoming_used, 0);
                incoming_used -= discard;
            }
        }

        panic!("exceeded the number of max iterations ({max_iters})")
    }

    #[test]
    fn client_async_vec() -> Result<(), Box<dyn Error>> {
        tokio_test::block_on(client_async_vec_())
    }

    struct TcpStream {
        is_client: bool,
    }

    impl TcpStream {
        fn connect(_addr: &str) -> io::Result<Self> {
            Ok(Self { is_client: true })
        }

        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            eprintln!("\nwrote {}B to socket", bytes.len());
            Ok(())
        }

        fn read_buf(&mut self, mut cursor: BorrowedCursor) -> io::Result<usize> {
            let num_bytes = if self.is_client {
                match mock::ClientState.advance() {
                    3 => 1580,

                    11 => 531,

                    state => unimplemented!("client state: {state}"),
                }
            } else {
                unimplemented!()
            };

            unsafe {
                cursor.advance(num_bytes);
            }

            eprintln!("\nread {num_bytes}B from socket");
            Ok(num_bytes)
        }
    }

    // logic-wise quite similar to `client_async_vec` but uses (mocked) blocking IO and
    // the `read_buf` API (`Borrowed{Buf,Cursor}`)
    #[test]
    fn client_blocking_read_buf() -> Result<(), Box<dyn Error>> {
        let server_name = "localhost";
        let port = 1433;

        let cert_verifier = WebPkiServerCertVerifier;
        let mut sock = TcpStream::connect(&format!("{server_name}:{port}"))?;
        let mut conn = LlClientConnection::new(server_name)?;

        let mut outgoing_tls = vec![];
        let mut incoming_tls = [MaybeUninit::uninit(); 2 * 1024];
        let mut incoming_tls = BorrowedBuf::from(&mut incoming_tls[..]);

        let mut outgoing_used = 0;
        let mut incoming_used = 0;
        let mut certificates = vec![];
        let mut dss = None;

        let max_iters = 32;
        for _ in 0..max_iters {
            let Status { discard, state } = conn.process_tls_records(incoming_tls.filled_mut())?;

            eprintln!("state: {}", state.variant_name());

            match state {
                State::NeedsSupportedVerifySchemes(mut conn) => {
                    let schemes = cert_verifier.supported_verify_schemes();
                    conn.add_supported_verify_schemes(schemes);
                }

                State::MustEncryptTlsData(mut encrypter) => {
                    let res = encrypter.encrypt(&mut outgoing_tls[outgoing_used..]);

                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            // example of on-the-fly buffer resizing
                            let new_len = outgoing_used + required_size;
                            outgoing_tls.resize(new_len, 0);
                            eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                            // don't forget to encrypt the handshake record after resizing!
                            encrypter
                                .encrypt(&mut outgoing_tls[outgoing_used..])
                                .expect("should not fail this time");
                        }
                    }
                }

                State::MustTransmitTlsData(conn) => {
                    sock.write_all(&outgoing_tls[..outgoing_used])?;

                    outgoing_used = 0;

                    conn.done()
                }

                State::NeedsMoreTlsData { .. } => {
                    // XXX real code needs to handle resizing
                    let read = sock.read_buf(incoming_tls.unfilled())?;
                    incoming_used += read;
                }

                State::ReceivedCertificate(record) => {
                    let new_certificates = record.decrypt();

                    for certificate in new_certificates {
                        certificates.push(certificate?.into_owned())
                    }
                }

                State::ReceivedSignature(record) => {
                    dss = Some(record.decrypt()?.into_owned());
                }

                State::NeedsSignature(state) => {
                    let message = state.message();

                    let (end_entity, intermediates) =
                        certificates.split_first().ok_or(TlsError::Fatal)?;

                    // normally, this would come from the `ext` field of `end_entity` but it was not mocked
                    let ocsp_response = &[];

                    let intermediates = intermediates
                        .iter()
                        .map(|entry| entry.cert.clone())
                        .collect::<Vec<_>>();

                    let cert_verified = cert_verifier.verify_server_cert(
                        &end_entity.cert,
                        &intermediates,
                        server_name,
                        ocsp_response,
                    )?;

                    let dss = dss.as_ref().ok_or(TlsError::Fatal)?;
                    let sig_verified =
                        cert_verifier.verify_tls13_signature(message, &end_entity.cert, dss)?;

                    let verification_outcome = VerificationOutcome::Valid {
                        cert_verified,
                        sig_verified,
                    };

                    state.done(verification_outcome);
                }

                State::AppDataAvailable(record) => {
                    let _data = record.decrypt()?;
                    // do stuff with `data`
                }

                State::EarlyDataAvailable(record) => {
                    // unreachable since this is a clinet
                    let _early_data = record.decrypt()?;
                    // do stuff with `early_data`
                }

                State::MayEncryptAppData(mut encrypter) => {
                    let app_data = b"Hello, world!";
                    let res = encrypter.encrypt(app_data, &mut outgoing_tls[outgoing_used..]);
                    match res {
                        Ok(written) => {
                            outgoing_used += written;
                        }

                        Err(EncryptError { required_size }) => {
                            let new_len = outgoing_used + required_size;
                            outgoing_tls.resize(new_len, 0);
                            eprintln!("resized `outgoing_tls` buffer to {}B", new_len);

                            // don't forget to encrypt `app_data` after resizing!
                            encrypter
                                .encrypt(app_data, &mut outgoing_tls[outgoing_used..])
                                .expect("should not fail this time");
                        }
                    }

                    encrypter.done();
                }

                State::TrafficTransit(_) => {
                    // post-handshake logic
                    return Ok(());
                }

                State::MayEncryptEarlyData(encrypter) => {
                    // not sending any early data in this example
                    encrypter.done();
                }
            }

            // discard TLS record
            if discard != 0 {
                assert!(discard <= incoming_used);

                incoming_tls
                    .filled_mut()
                    .copy_within(discard..incoming_used, 0);
                incoming_tls.clear();
                unsafe {
                    incoming_tls.unfilled().advance(incoming_used - discard);
                }
                incoming_used -= discard;
            }
        }

        panic!("exceeded the number of max iterations ({max_iters})")
    }
}
