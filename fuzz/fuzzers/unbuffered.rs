#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::client::UnbufferedClientConnection;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, UnbufferedStatus};
use rustls::{ClientConfig, ServerConfig, SideData};

fuzz_target!(|data: &[u8]| {
    let _ = env_logger::try_init();
    let mut data = data.to_vec();
    match data.split_first_mut() {
        Some((0x00, rest)) => client(rest),
        Some((0x01, rest)) => server(rest),
        Some((_, _)) | None => {}
    }
});

fn client(data: &mut [u8]) {
    let config = ClientConfig::builder(rustls_fuzzing_provider::PROVIDER.into())
        .dangerous()
        .with_custom_certificate_verifier(rustls_fuzzing_provider::server_verifier())
        .with_no_client_auth()
        .unwrap();
    let conn =
        UnbufferedClientConnection::new(config.into(), "localhost".try_into().unwrap()).unwrap();
    fuzz_unbuffered(data, ClientServer::Client(conn));
}

fn server(data: &mut [u8]) {
    let config = ServerConfig::builder(rustls_fuzzing_provider::PROVIDER.into())
        .with_no_client_auth()
        .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
        .unwrap();
    let conn = UnbufferedServerConnection::new(config.into()).unwrap();
    fuzz_unbuffered(data, ClientServer::Server(conn));
}

enum ClientServer {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

fn fuzz_unbuffered(mut data: &mut [u8], mut conn: ClientServer) {
    while !data.is_empty() {
        let consumed = match &mut conn {
            ClientServer::Server(server) => process(server.process_tls_records(data)),
            ClientServer::Client(client) => process(client.process_tls_records(data)),
        };

        match consumed {
            Some(consumed) => {
                data = &mut data[consumed..];
            }
            None => break,
        };
    }
}

fn process<S: SideData>(status: UnbufferedStatus<'_, '_, S>) -> Option<usize> {
    let UnbufferedStatus { discard, state, .. } = status;

    match state {
        Ok(ConnectionState::EncodeTlsData(mut enc)) => {
            let mut buffer = [0u8; 16_384 + 5]; // big enough for largest TLS packet
            enc.encode(&mut buffer).unwrap();
        }
        Ok(ConnectionState::TransmitTlsData(xmit)) => xmit.done(),
        Ok(ConnectionState::WriteTraffic(_)) => return None,
        Ok(ConnectionState::BlockedHandshake) => return None,
        Ok(ConnectionState::ReadTraffic(_)) => {}
        Ok(st) => panic!("unhandled state {st:?}"),
        Err(_) => return None,
    };

    Some(discard)
}
