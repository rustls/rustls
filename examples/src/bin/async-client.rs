//! This is a simple client using rustls' state-based API, in conjunction with asynchronous I/O via
//! tokio.  The application manages its own receive buffer.

use core::error::Error;
use std::sync::Arc;

use rustls::client::{ClientState, ClientTraffic};
use rustls::crypto::cipher::OutboundPlain;
use rustls::state::{ReceiveTrafficState, SliceInput, TlsInputBuffer};
use rustls::{ClientConfig, RootCertStore};
use rustls_aws_lc_rs::DEFAULT_PROVIDER;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = ClientConfig::builder(Arc::new(DEFAULT_PROVIDER))
        .with_root_certificates(root_store)
        .with_no_client_auth()?;

    let config = Arc::new(config);

    let mut incoming_tls = vec![0; INCOMING_TLS_BUFSIZE];
    converse(&config, &mut incoming_tls).await?;

    Ok(())
}

async fn converse(
    config: &Arc<ClientConfig>,
    incoming_tls: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let mut state = ClientState::new(config.clone(), SERVER_NAME.try_into()?, None)?;
    let mut sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}")).await?;

    let mut incoming_used = 0;

    // complete handshake
    let traffic = loop {
        state = match state {
            ClientState::SendClientFlight(mut send) => {
                while let Some(data) = send.take_data() {
                    sock.write_all(&data).await?;
                }
                send.into_next()
            }

            ClientState::AwaitServerFlight(recv) => {
                recv_tls(&mut sock, incoming_tls, &mut incoming_used).await?;
                let mut buffer = SliceInput::new(&mut incoming_tls[..incoming_used]);
                let next = match recv.input_data(&mut buffer) {
                    Ok(next) => next,
                    Err((mut err_alert, _outputs)) => {
                        while let Some(data) = err_alert.take_tls_data() {
                            sock.write_all(&data).await?;
                        }
                        return Err(err_alert.error.into());
                    }
                };

                let used = buffer.into_used();
                // note, this is a very inefficient buffer representation.
                incoming_tls.copy_within(used..incoming_used, 0);
                incoming_used -= used;
                next
            }

            ClientState::Traffic(traffic) => break traffic,

            _ => todo!(),
        };
    };

    let ClientTraffic {
        mut send,
        mut receive,
        outputs,
    } = *traffic;

    println!(
        "connected to server with version={:?} cipher suite={:?}",
        outputs.protocol_version(),
        outputs.negotiated_cipher_suite()
    );

    let request = [
        b"GET / HTTP/1.1\r\n\
        Host: ",
        SERVER_NAME.as_bytes(),
        b"\r\n\
        Connection: close\r\n\
        Accept-Encoding: identity\r\n\
        \r\n",
    ];
    let mut tls_data = send.write(OutboundPlain::new(&request))?;
    tls_data.push(send.close());
    for chunk in tls_data {
        sock.write_all(&chunk).await?;
    }

    loop {
        let mut buffer = SliceInput::new(&mut incoming_tls[..incoming_used]);
        let received = match receive.read(&mut buffer) {
            Ok(received) => received,
            Err(mut err_alert) => {
                while let Some(data) = err_alert.take_tls_data() {
                    sock.write_all(&data).await?;
                }
                return Err(err_alert.error.into());
            }
        };

        receive = match received {
            ReceiveTrafficState::Await(receive) => {
                if recv_tls(&mut sock, incoming_tls, &mut incoming_used).await? == 0 {
                    println!("server uncleanly closed connection");
                    break;
                }
                receive
            }

            ReceiveTrafficState::WakeSender(wake) => {
                // sender already closed; nothing to do
                wake.into_next()
            }

            ReceiveTrafficState::Available(data) => {
                println!(
                    "received response: {:?}",
                    String::from_utf8_lossy(data.data)
                );
                let (used, next_state) = data.into_next();
                buffer.discard(used);
                let used = buffer.into_used();
                incoming_tls.copy_within(used..incoming_used, 0);
                incoming_used -= used;
                next_state
            }

            ReceiveTrafficState::CloseNotify => {
                println!("server cleanly closed connection");
                break;
            }
        };
    }

    Ok(())
}

async fn recv_tls(
    sock: &mut TcpStream,
    incoming_tls: &mut [u8],
    incoming_used: &mut usize,
) -> Result<usize, Box<dyn Error>> {
    let read = sock
        .read(&mut incoming_tls[*incoming_used..])
        .await?;
    println!("received {read}B of data");
    *incoming_used += read;
    Ok(read)
}

const SERVER_NAME: &str = "jbp.io";
const PORT: u16 = 443;

const INCOMING_TLS_BUFSIZE: usize = 16 * 1024;
