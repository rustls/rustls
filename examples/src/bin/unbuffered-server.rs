//! This is a simple server using rustls' unbuffered API. Meaning that the application layer must
//! handle the buffers required to receive, process and send TLS data.

use core::error::Error;
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use rustls::crypto::Identity;
use rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, UnbufferedServerConnection};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError,
    UnbufferedStatus,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let mut config = ServerConfig::builder(Arc::new(DEFAULT_PROVIDER))
        .with_no_client_auth()
        .with_single_cert(
            Arc::new(Identity::from_cert_chain(load_certs(cert_file)?)?),
            load_private_key(private_key_file)?,
        )?;

    if let Some(max_early_data_size) = MAX_EARLY_DATA_SIZE {
        config.max_early_data_size = max_early_data_size;
    }

    config.max_fragment_size = MAX_FRAGMENT_SIZE;

    let config = Arc::new(config);

    let listener = TcpListener::bind(format!("[::]:{PORT}"))?;

    let mut incoming_tls = [0; INCOMING_TLS_BUFSIZE];
    let mut outgoing_tls = vec![0; OUTGOING_TLS_INITIAL_BUFSIZE];
    for stream in listener.incoming() {
        handle(stream?, &config, &mut incoming_tls, &mut outgoing_tls)?;
    }

    Ok(())
}

fn handle(
    mut sock: TcpStream,
    config: &Arc<ServerConfig>,
    incoming_tls: &mut [u8],
    outgoing_tls: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    eprintln!("\n---- new client ----");

    dbg!(sock.peer_addr()?);

    let mut conn = UnbufferedServerConnection::new(config.clone())?;

    let mut incoming_used = 0;
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut received_request = false;
    let mut sent_response = false;

    let mut iter_count = 0;
    while open_connection {
        let UnbufferedStatus {
            mut discard, state, ..
        } = conn.process_tls_records(&mut incoming_tls[..incoming_used]);

        match dbg!(state.unwrap()) {
            ConnectionState::ReadTraffic(state) => {
                let record = state.record();
                discard += record.discard;

                if record.payload.starts_with(b"GET") {
                    let response = core::str::from_utf8(record.payload)?;
                    let header = response
                        .lines()
                        .next()
                        .unwrap_or(response);

                    println!("{header}");
                } else {
                    println!("(.. continued HTTP request ..)");
                }

                received_request = true;
            }

            ConnectionState::ReadEarlyData(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                        ..
                    } = res?;
                    discard += new_discard;

                    println!("early data: {:?}", core::str::from_utf8(payload));

                    received_request = true;
                }
            }

            ConnectionState::EncodeTlsData(mut state) => {
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

            ConnectionState::TransmitTlsData(state) => {
                send_tls(&mut sock, outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            ConnectionState::BlockedHandshake { .. } => {
                recv_tls(&mut sock, incoming_tls, &mut incoming_used)?;
            }

            ConnectionState::WriteTraffic(mut state) => {
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

                    let http_response = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls unbuffered server\r\n";
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

            ConnectionState::PeerClosed => {}
            ConnectionState::Closed => {
                open_connection = false;
            }

            _ => unreachable!(),
        }

        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;

            eprintln!("discarded {discard}B from `incoming_tls`");
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

fn try_or_resize_and_retry<E>(
    mut f: impl FnMut(&mut [u8]) -> Result<usize, E>,
    map_err: impl FnOnce(E) -> Result<InsufficientSizeError, Box<dyn Error>>,
    outgoing_tls: &mut Vec<u8>,
    outgoing_used: &mut usize,
) -> Result<usize, Box<dyn Error>>
where
    E: Error + 'static,
{
    let written = match f(&mut outgoing_tls[*outgoing_used..]) {
        Ok(written) => written,

        Err(e) => {
            let InsufficientSizeError { required_size, .. } = map_err(e)?;
            let new_len = *outgoing_used + required_size;
            outgoing_tls.resize(new_len, 0);
            eprintln!("resized `outgoing_tls` buffer to {new_len}B");

            f(&mut outgoing_tls[*outgoing_used..])?
        }
    };

    *outgoing_used += written;

    Ok(written)
}

fn recv_tls(
    sock: &mut TcpStream,
    incoming_tls: &mut [u8],
    incoming_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    let read = sock.read(&mut incoming_tls[*incoming_used..])?;
    eprintln!("received {read}B of data");
    *incoming_used += read;
    Ok(())
}

fn send_tls(
    sock: &mut TcpStream,
    outgoing_tls: &[u8],
    outgoing_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    sock.write_all(&outgoing_tls[..*outgoing_used])?;
    eprintln!("sent {outgoing_used}B of data");
    *outgoing_used = 0;
    Ok(())
}

fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, io::Error> {
    Ok(CertificateDer::pem_file_iter(path)
        .expect("cannot open certificate file")
        .map(|cert| cert.unwrap())
        .collect())
}

fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, io::Error> {
    Ok(PrivateKeyDer::from_pem_file(path).expect("cannot open private key file"))
}

const KB: usize = 1024;
const INCOMING_TLS_BUFSIZE: usize = 16 * KB;
const OUTGOING_TLS_INITIAL_BUFSIZE: usize = 0;
const MAX_EARLY_DATA_SIZE: Option<u32> = Some(128);
const MAX_FRAGMENT_SIZE: Option<usize> = None;

const PORT: u16 = 1443;
const MAX_ITERATIONS: usize = 30;
