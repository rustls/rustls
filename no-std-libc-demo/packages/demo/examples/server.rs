#![no_main]
#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::str::Utf8Error;

use ministd::io::{Read, Write};
use ministd::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use ministd::{cstr, dbg, entry, eprintln, fs, io, println};
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::UnbufferedServerConnection;
use rustls::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError, ServerConfig,
    UnbufferedStatus,
};
use rustls_pemfile::Item;
use rustls_provider_example::PROVIDER as CRYPTO_PROVIDER;

const KB: usize = 1024;
const INCOMING_TLS_BUFSIZ: usize = 16 * KB;
const OUTGOING_TLS_INITIAL_BUFSIZ: usize = 0;
const MAX_ITERATIONS: usize = 30;

const PORT: u16 = 1443;
// NOTE `CRYPTO_PROVIDER` only supports the `PKCS_ECDSA_P256_SHA256` algorithm so `mkcert`
// (v1.4.4) won't work. Use `rcgen` to produce these PEM files; see `TestPki::new` in
// `/provider_example/examples/server.rs` for details
const CERTFILE: &CStr = cstr!("localhost.pem");
const PRIV_KEY_FILE: &CStr = cstr!("localhost-key.pem");

entry!(main);

fn main() -> Result<(), Error> {
    let mut config = ServerConfig::builder_with_provider(CRYPTO_PROVIDER)
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(load_certs(CERTFILE)?, load_private_key(PRIV_KEY_FILE)?)?;

    config.time_provider = no_std_libc_demo::time_provider();

    let config = Arc::new(config);

    let sock_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), PORT));

    let listener = TcpListener::bind(&sock_addr)?;

    let mut incoming_tls = [0; INCOMING_TLS_BUFSIZ];
    let mut outgoing_tls = vec![0; OUTGOING_TLS_INITIAL_BUFSIZ];
    loop {
        let (sock, peer_addr) = listener.accept()?;
        eprintln!("\n---- new client ----")?;
        eprintln!("peer: {}", peer_addr)?;

        handle(sock, &config, &mut incoming_tls, &mut outgoing_tls)?;
    }
}

fn handle(
    mut sock: TcpStream,
    config: &Arc<ServerConfig>,
    incoming_tls: &mut [u8],
    outgoing_tls: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut conn = UnbufferedServerConnection::new(config.clone())?;

    let mut incoming_used = 0;
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut received_request = false;
    let mut sent_response = false;

    let mut iter_count = 0;
    while open_connection {
        let UnbufferedStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

        match dbg!(state) {
            ConnectionState::AppDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    if payload.starts_with(b"GET") {
                        let response = core::str::from_utf8(payload)?;
                        let header = response
                            .lines()
                            .next()
                            .unwrap_or(response);

                        println!("{}", header)?;
                    } else {
                        println!("(.. continued HTTP request ..)")?;
                    }

                    received_request = true;
                }
            }

            ConnectionState::EarlyDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    println!("early data: {:?}", core::str::from_utf8(payload))?;

                    received_request = true;
                }
            }

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
                    outgoing_tls,
                    &mut outgoing_used,
                )?;
            }

            ConnectionState::MustTransmitTlsData(state) => {
                send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            ConnectionState::NeedsMoreTlsData { .. } => {
                recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
            }

            ConnectionState::TrafficTransit(mut state) => {
                if !received_request {
                    recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
                } else {
                    let map_err = |e| {
                        if let EncryptError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    };

                    let http_response = build_http_response();
                    try_or_resize_and_retry(
                        |out_buffer| state.encrypt(http_response, out_buffer),
                        map_err,
                        outgoing_tls,
                        &mut outgoing_used,
                    )?;
                    sent_response = true;

                    try_or_resize_and_retry(
                        |out_buffer| state.queue_close_notify(out_buffer),
                        map_err,
                        outgoing_tls,
                        &mut outgoing_used,
                    )?;
                    open_connection = false;

                    send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                }
            }

            _ => unreachable!(),
        }

        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;

            eprintln!("discarded {}B from `incoming_tls`", discard)?;
        }

        iter_count += 1;
        assert!(
            iter_count < MAX_ITERATIONS,
            "did not get a HTTP response within {MAX_ITERATIONS} iterations"
        );
    }

    assert!(received_request);
    assert!(sent_response);
    assert_eq!(0, incoming_used);
    assert_eq!(0, outgoing_used);

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

fn build_http_response() -> &'static [u8] {
    b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from no-std rustls server\r\n"
}

fn load_certs(certfile: &CStr) -> Result<Vec<CertificateDer<'static>>, Error> {
    let bytes = fs::read(certfile).map_err(|e| {
        let _ = eprintln!("error reading file {}", certfile.to_str().unwrap());
        e
    })?;
    let mut input = bytes.as_slice();
    let mut certs = vec![];

    while let Some((item, rest)) = rustls_pemfile::read_one_from_slice(input)? {
        input = rest;

        if let Item::X509Certificate(cert) = item {
            certs.push(cert)
        }
    }

    Ok(certs)
}

fn load_private_key(keyfile: &CStr) -> Result<PrivateKeyDer<'static>, Error> {
    let bytes = fs::read(keyfile).map_err(|e| {
        let _ = eprintln!("error reading file {}", keyfile.to_str().unwrap());
        e
    })?;
    let mut input = bytes.as_slice();

    while let Some((item, rest)) = rustls_pemfile::read_one_from_slice(input)? {
        input = rest;

        match item {
            Item::Pkcs1Key(key) => {
                eprintln!("PKCS1 key found")?;
                return Ok(key.into());
            }

            Item::Pkcs8Key(key) => {
                eprintln!("PKCS8 key found")?;

                return Ok(key.into());
            }

            Item::Sec1Key(key) => {
                eprintln!("SEC1 key found")?;

                return Ok(key.into());
            }

            _ => continue,
        }
    }

    panic!("no keys found in file {}", PRIV_KEY_FILE.to_str().unwrap())
}

#[derive(Debug)]
enum Error {
    Encode(EncodeError),
    Encrypt(EncryptError),
    Ministd(io::Error),
    Pemfile(rustls_pemfile::Error),
    Rustls(rustls::Error),
    Utf8(Utf8Error),
}

impl From<EncodeError> for Error {
    fn from(v: EncodeError) -> Self {
        Self::Encode(v)
    }
}

impl From<EncryptError> for Error {
    fn from(v: EncryptError) -> Self {
        Self::Encrypt(v)
    }
}

impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Self::Ministd(v)
    }
}

impl From<rustls_pemfile::Error> for Error {
    fn from(v: rustls_pemfile::Error) -> Self {
        Self::Pemfile(v)
    }
}

impl From<rustls::Error> for Error {
    fn from(v: rustls::Error) -> Self {
        Self::Rustls(v)
    }
}

impl From<Utf8Error> for Error {
    fn from(v: Utf8Error) -> Self {
        Self::Utf8(v)
    }
}
