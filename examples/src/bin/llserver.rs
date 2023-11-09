use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{
    server::LlServerConnection, AppDataRecord, EncodeError, InsufficientSizeError, LlState,
    LlStatus, ServerConfig,
};
use rustls_pemfile::Item;

const PORT: u16 = 1443;
const MAX_ITERATIONS: usize = 20;
const CERTFILE: &str = "localhost.pem";
const PRIV_KEY_FILE: &str = "localhost-key.pem";

fn main() -> Result<(), Box<dyn Error>> {
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(load_certs()?, load_private_key()?)?,
    );

    let listener = TcpListener::bind(format!("[::]:{PORT}"))?;

    for stream in listener.incoming() {
        handle(stream?, &config)?;
    }

    Ok(())
}

fn handle(mut sock: TcpStream, config: &Arc<ServerConfig>) -> Result<(), Box<dyn Error>> {
    dbg!(sock.peer_addr()?);

    let mut conn = LlServerConnection::new(config.clone())?;

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = Vec::<u8>::new();
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut received_request = false;
    let mut sent_response = false;

    let mut iter_count = 0;
    while open_connection {
        let LlStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

        match dbg!(state) {
            LlState::AppDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    println!("{}", core::str::from_utf8(payload)?);
                    received_request = true;
                }
            }

            LlState::MustEncodeTlsData(mut state) => {
                let written = match state.encode(&mut outgoing_tls[outgoing_used..]) {
                    Ok(written) => written,

                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        let new_len = outgoing_used + required_size;
                        outgoing_tls.resize(new_len, 0);
                        eprintln!("resized `outgoing_tls` buffer to {new_len}B");

                        state
                            .encode(&mut outgoing_tls[outgoing_used..])
                            .expect("should not fail")
                    }

                    Err(e) => return Err(e.into()),
                };

                outgoing_used += written;
            }

            LlState::MustTransmitTlsData(mut state) => {
                dbg!(state.may_encrypt().is_some());

                send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            LlState::NeedsMoreTlsData { .. } => {
                recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
            }

            LlState::TrafficTransit(mut state) => {
                if !received_request {
                    recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
                } else {
                    let written = state
                        .encrypt(build_http_response(), &mut outgoing_tls[outgoing_used..])
                        .expect("encrypted request does not fit in `outgoing_tls`");
                    outgoing_used += written;
                    sent_response = true;

                    let written = state
                        .queue_close_notify(&mut outgoing_tls[outgoing_used..])
                        .expect("encrypted close-notify does not fit in `outgoing_tls`");
                    outgoing_used += written;
                    open_connection = false;

                    send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                }
            }

            _ => unreachable!(),
        }

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

fn build_http_response() -> &'static [u8] {
    b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls llserver\r\n"
}

fn load_certs() -> Result<Vec<CertificateDer<'static>>, io::Error> {
    let mut reader = BufReader::new(File::open(CERTFILE)?);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key() -> Result<PrivateKeyDer<'static>, io::Error> {
    let mut reader = BufReader::new(File::open(PRIV_KEY_FILE)?);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => continue,
        }
    }

    panic!("no keys found in {PRIV_KEY_FILE}")
}
