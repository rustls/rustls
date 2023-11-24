#![no_main]
#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::{self, Utf8Error};
use pki_types::{DnsName, InvalidDnsNameError};

use ministd::io::{self, Read, Stream, Write};
use ministd::net::{TcpStream, ToSocketAddrs};
use ministd::{dbg, entry, eprintln};
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{
    AppDataRecord, ClientConfig, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    MayEncryptAppData, RootCertStore, UnbufferedStatus,
};
use rustls_provider_example::PROVIDER as CRYPTO_PROVIDER;

const SERVER_NAME: &str = "www.rust-lang.org";
// const SERVER_NAME: &str = "doc.rust-lang.org";
const PORT: u16 = 443;
const MAX_ITERATIONS: usize = 30;

entry!(main);

fn main() -> Result<(), Error> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let mut config = ClientConfig::builder_with_provider(CRYPTO_PROVIDER)
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        // toggle between TLS versions
        // .with_protocol_versions(&[&TLS12])
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.time_provider = no_std_libc_demo::time_provider();

    let sock_addr = (SERVER_NAME, PORT)
        .to_socket_addrs()?
        .next()
        .ok_or(io::Error::AddressLookup)?;
    dbg!(sock_addr);

    let mut sock = TcpStream::connect(&sock_addr)?;
    let mut conn = UnbufferedClientConnection::new(
        Arc::new(config),
        pki_types::ServerName::DnsName(DnsName::try_from(SERVER_NAME.to_string())?),
    )?;

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = Vec::new();
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut sent_request = false;
    let mut received_response = false;

    let mut iter_count = 0;
    let mut fragment_count = 0;
    while open_connection {
        let UnbufferedStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used])?;
        match state {
            ConnectionState::MustEncodeTlsData(mut state) => {
                try_or_resize_and_retry(
                    |out_buffer| state.encode(out_buffer),
                    |e| {
                        if let EncodeError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    &mut outgoing_tls,
                    &mut outgoing_used,
                )?;
            }

            ConnectionState::MustTransmitTlsData(mut state) => {
                if let Some(mut may_encrypt) = state.may_encrypt_app_data() {
                    make_http_request(
                        &mut sent_request,
                        &mut may_encrypt,
                        &mut outgoing_tls,
                        &mut outgoing_used,
                    )?;
                }

                send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            ConnectionState::NeedsMoreTlsData { .. } => {
                recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
            }

            ConnectionState::AppDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    fragment_count += 1;

                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    let mut stream = Stream::STDOUT;
                    stream.write_all(payload)?;
                    received_response = true;
                }
            }

            ConnectionState::TrafficTransit(mut may_encrypt) => {
                let read = if make_http_request(
                    &mut sent_request,
                    &mut may_encrypt,
                    &mut outgoing_tls,
                    &mut outgoing_used,
                )? {
                    send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                    recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?
                } else {
                    // this happens in the TLS 1.3 case. the app-data was sent in the preceding
                    // `MustTransmitTlsData` state. the server should have already a response which
                    // we can read out from the socket
                    recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?
                };

                if read == 0 && received_response {
                    // end of HTTP response
                    open_connection = false;
                }
            }

            ConnectionState::ConnectionClosed => open_connection = false,

            _ => unreachable!(),
        }

        // discard TLS records
        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }

        iter_count += 1;
        assert!(
            iter_count < MAX_ITERATIONS,
            "did not get a HTTP response within {MAX_ITERATIONS} iterations"
        );
    }

    assert!(sent_request);
    assert!(received_response);
    assert_eq!(0, incoming_used);
    assert_eq!(0, outgoing_used);

    eprintln!("done in {} iterations", iter_count)?;
    eprintln!("HTTP response was split in {} fragments", fragment_count)?;

    Ok(())
}

fn recv_tls(
    sock: &mut TcpStream,
    incoming_tls: &mut [u8],
    incoming_used: &mut usize,
) -> Result<usize, Error> {
    let read = sock.read(&mut incoming_tls[*incoming_used..])?;
    eprintln!("received {}B of data", read)?;
    *incoming_used += read;
    Ok(read)
}

fn send_tls(
    sock: &mut TcpStream,
    outgoing_tls: &[u8],
    outgoing_used: &mut usize,
) -> Result<(), Error> {
    sock.write_all(&outgoing_tls[..*outgoing_used])?;
    eprintln!("sent {}B of data", outgoing_used)?;
    *outgoing_used = 0;
    Ok(())
}

fn make_http_request(
    sent_request: &mut bool,
    may_encrypt: &mut MayEncryptAppData<'_, ClientConnectionData>,
    outgoing_tls: &mut Vec<u8>,
    outgoing_used: &mut usize,
) -> Result<bool, Error> {
    let sent = if !*sent_request {
        let http_request = build_http_request();
        try_or_resize_and_retry(
            |out_buffer| may_encrypt.encrypt(&http_request, out_buffer),
            |e| {
                if let EncryptError::InsufficientSize(is) = &e {
                    Ok(*is)
                } else {
                    Err(e.into())
                }
            },
            outgoing_tls,
            outgoing_used,
        )?;

        *sent_request = true;
        eprintln!("queued HTTP request")?;
        true
    } else {
        false
    };

    Ok(sent)
}

fn try_or_resize_and_retry<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError, Error>,
    outgoing_tls: &mut Vec<u8>,
    outgoing_used: &mut usize,
) -> Result<usize, Error>
where
    Error: From<E>,
{
    let written = match f(&mut outgoing_tls[*outgoing_used..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size } = map_err(e)?;
            let new_len = *outgoing_used + required_size;
            outgoing_tls.resize(new_len, 0);
            eprintln!("resized `outgoing_tls` buffer to {}B", new_len)?;

            f(&mut outgoing_tls[*outgoing_used..])?
        }
    };

    *outgoing_used += written;

    Ok(written)
}

fn build_http_request() -> Vec<u8> {
    const HTTP_SEPARATOR: &str = "\r\n";

    let lines = [
        Cow::Borrowed("GET / HTTP/1.1"),
        format!("Host: {SERVER_NAME}").into(),
        "Connection: close".into(),
        "Accept-Encoding: identity".into(),
        "".into(), // body
    ];

    let mut req = String::new();
    for line in lines {
        req.push_str(&line);
        req.push_str(HTTP_SEPARATOR);
    }

    req.into_bytes()
}

#[derive(Debug)]
enum Error {
    Encode(EncodeError),
    Encrypt(EncryptError),
    InvalidDnsName(InvalidDnsNameError),
    Ministd(io::Error),
    Rustls(rustls::Error),
    Utf8(Utf8Error),
}

impl From<EncryptError> for Error {
    fn from(v: EncryptError) -> Self {
        Self::Encrypt(v)
    }
}

impl From<Utf8Error> for Error {
    fn from(v: Utf8Error) -> Self {
        Self::Utf8(v)
    }
}

impl From<EncodeError> for Error {
    fn from(v: EncodeError) -> Self {
        Self::Encode(v)
    }
}

impl From<InvalidDnsNameError> for Error {
    fn from(v: InvalidDnsNameError) -> Self {
        Self::InvalidDnsName(v)
    }
}

impl From<rustls::Error> for Error {
    fn from(v: rustls::Error) -> Self {
        Self::Rustls(v)
    }
}

impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Self::Ministd(v)
    }
}
