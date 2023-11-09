use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::{ClientConnectionData, LlClientConnection};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{
    AppDataRecord, ClientConfig, EarlyDataError, EncodeError, EncryptError, InsufficientSizeError,
    LlState, LlStatus, MayEncryptAppData, RootCertStore,
};

const SERVER_NAME: &str = "example.com";
const PORT: u16 = 443;
const MAX_ITERATIONS: usize = 20;
const SEND_EARLY_DATA: bool = true;
const EARLY_DATA: &[u8] = b"hello";

fn main() -> Result<(), Box<dyn Error>> {
    let mut config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        // .with_protocol_versions(&[&TLS12])
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(build_root_store())
        .with_no_client_auth();
    config.enable_early_data = SEND_EARLY_DATA;

    let config = Arc::new(config);

    converse(&config, false)?;
    if SEND_EARLY_DATA {
        eprintln!("---- second connection ----");
        converse(&config, true)?;
    }

    Ok(())
}

fn converse(config: &Arc<ClientConfig>, send_early_data: bool) -> Result<(), Box<dyn Error>> {
    let mut conn = LlClientConnection::new(Arc::clone(config), SERVER_NAME.try_into()?)?;
    let mut sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}"))?;

    let mut incoming_tls = [0; 16 * 1024];
    let mut incoming_used = 0;

    let mut outgoing_tls = Vec::<u8>::new();
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut sent_request = false;
    let mut received_response = false;
    let mut sent_early_data = false;

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

                    if payload.starts_with(b"HTTP") {
                        let response = core::str::from_utf8(payload)?;
                        let header = response
                            .lines()
                            .next()
                            .unwrap_or(response);

                        println!("{header}");
                    } else {
                        println!("(.. continued HTTP response ..)");
                    }

                    received_response = true;
                }
            }

            LlState::MustEncodeTlsData(mut state) => {
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

            LlState::MustTransmitTlsData(mut state) => {
                if let Some(mut may_encrypt_early_data) = state.may_encrypt_early_data() {
                    let written = try_or_resize_and_retry(
                        |out_buffer| may_encrypt_early_data.encrypt(EARLY_DATA, out_buffer),
                        |e| {
                            if let EarlyDataError::Encrypt(EncryptError::InsufficientSize(is)) = &e
                            {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                        &mut outgoing_tls,
                        &mut outgoing_used,
                    )?;

                    eprintln!("queued {written}B of early data");
                    sent_early_data = true;
                }

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
                } else {
                    try_or_resize_and_retry(
                        |out_buffer| may_encrypt.queue_close_notify(out_buffer),
                        |e| {
                            if let EncryptError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                        &mut outgoing_tls,
                        &mut outgoing_used,
                    )?;
                    send_tls(&mut sock, &mut outgoing_tls, &mut outgoing_used)?;
                    open_connection = false;
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
    assert_eq!(send_early_data, sent_early_data);
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
            let InsufficientSizeError { required_size } = map_err(e)?;
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
