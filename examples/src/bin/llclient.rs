use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::{ClientConnectionData, LlClientConnection};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{
    AppDataRecord, ClientConfig, EncodeError, InsufficientSizeError, LlState, LlStatus,
    MayEncryptAppData, RootCertStore,
};

const SERVER_NAME: &str = "example.com";
const PORT: u16 = 443;
const MAX_ITERATIONS: usize = 15;

fn main() -> Result<(), Box<dyn Error>> {
    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS12])
        // .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(build_root_store())
        .with_no_client_auth();

    let mut sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}"))?;
    let mut conn = LlClientConnection::new(Arc::new(config), SERVER_NAME.try_into()?)?;

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = Vec::<u8>::new();
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut sent_request = false;
    let mut received_response = false;

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
                    received_response = true;
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
                if let Some(mut may_encrypt) = state.may_encrypt() {
                    make_http_request(
                        &mut sent_request,
                        &mut may_encrypt,
                        &mut outgoing_tls,
                        &mut outgoing_used,
                    );
                }

                send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                state.done();
            }

            LlState::NeedsMoreTlsData { .. } => {
                recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
            }

            LlState::TrafficTransit(mut may_encrypt) => {
                if make_http_request(
                    &mut sent_request,
                    &mut may_encrypt,
                    &mut outgoing_tls,
                    &mut outgoing_used,
                ) {
                    send_tls(&mut sock, &outgoing_tls, &mut outgoing_used)?;
                    recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
                } else if !received_response {
                    // this happens in the TLS 1.3 case. the app-data was sent in the preceding
                    // `MustTransmitTlsData` state. the server should have already a response which
                    // we can read out from the socket
                    recv_tls(&mut sock, &mut incoming_tls, &mut incoming_used)?;
                }
            }

            LlState::ConnectionClosed => {
                open_connection = false;
            }

            // other states are not expected in this example
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

    assert!(sent_request);
    assert!(received_response);
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

fn make_http_request(
    sent_request: &mut bool,
    may_encrypt: &mut MayEncryptAppData<'_, ClientConnectionData>,
    outgoing_tls: &mut [u8],
    outgoing_used: &mut usize,
) -> bool {
    if !*sent_request {
        let written = may_encrypt
            .encrypt(&build_http_request(), &mut outgoing_tls[*outgoing_used..])
            .expect("encrypted request does not fit in `outgoing_tls`");
        *outgoing_used += written;
        *sent_request = true;
        eprintln!("queued HTTP request");
        true
    } else {
        false
    }
}

fn build_root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    root_store
}

fn build_http_request() -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").into_bytes()
}
