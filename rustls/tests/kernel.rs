use rustls::client::UnbufferedClientConnection;
use rustls::server::UnbufferedServerConnection;
use rustls::version::{TLS12, TLS13};
use rustls::{ConnectionTrafficSecrets, Error};

use self::common::*;
use super::*;

mod common;

// Tests for the external API.
//
// We don't have anything set up to actually encrypt/decrypt the connection
// content so these tests all just check that the updated traffic secrets are
// equivalent on each side of the connection, if supported by the protocol
// version.

#[test]
fn err_on_secret_extraction_not_enabled() {
    let server_config = make_server_config(KeyType::Rsa2048);
    let server_config = Arc::new(server_config);

    let client_config = make_client_config(KeyType::Rsa2048);
    let client_config = Arc::new(client_config);

    let mut server = UnbufferedServerConnection::new(server_config).unwrap();
    let mut client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();

    do_unbuffered_handshake(&mut client, &mut server);

    assert!(
        client
            .dangerous_into_kernel_connection()
            .is_err()
    );
    assert!(
        server
            .dangerous_into_kernel_connection()
            .is_err()
    );
}

#[test]
fn err_on_handshake_not_complete() {
    let mut server_config = make_server_config(KeyType::Rsa2048);
    server_config.enable_secret_extraction = true;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config(KeyType::Rsa2048);
    client_config.enable_secret_extraction = true;
    let client_config = Arc::new(client_config);

    let server = UnbufferedServerConnection::new(server_config).unwrap();
    let client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();

    assert!(matches!(
        client.dangerous_into_kernel_connection(),
        Err(Error::HandshakeNotComplete)
    ));
    assert!(matches!(
        server.dangerous_into_kernel_connection(),
        Err(Error::HandshakeNotComplete)
    ));
}

#[test]
fn initial_traffic_secrets_match() {
    let mut server_config = make_server_config(KeyType::Rsa2048);
    server_config.enable_secret_extraction = true;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config(KeyType::Rsa2048);
    client_config.enable_secret_extraction = true;
    let client_config = Arc::new(client_config);

    let mut server = UnbufferedServerConnection::new(server_config).unwrap();
    let mut client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();

    do_unbuffered_handshake(&mut client, &mut server);

    let (client_secrets, _) = client
        .dangerous_into_kernel_connection()
        .expect("failed to convert client connection to an KernelConnection");
    let (server_secrets, _) = server
        .dangerous_into_kernel_connection()
        .expect("failed to convert server connection to an KernelConnection");

    assert_secrets_equal(client_secrets.tx, server_secrets.rx);
    assert_secrets_equal(server_secrets.tx, client_secrets.rx);
}

#[test]
fn key_updates_tls13() {
    let mut server_config = make_server_config_with_versions(KeyType::Rsa2048, &[&TLS13]);
    server_config.enable_secret_extraction = true;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config_with_versions(KeyType::Rsa2048, &[&TLS13]);
    client_config.enable_secret_extraction = true;
    let client_config = Arc::new(client_config);

    let mut server = UnbufferedServerConnection::new(server_config).unwrap();
    let mut client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();

    do_unbuffered_handshake(&mut client, &mut server);

    let (_, mut client) = client
        .dangerous_into_kernel_connection()
        .expect("failed to convert client connection to an KernelConnection");
    let (_, mut server) = server
        .dangerous_into_kernel_connection()
        .expect("failed to convert server connection to an KernelConnection");

    let new_client_tx = client.update_tx_secret().unwrap();
    let new_client_rx = client.update_rx_secret().unwrap();

    let new_server_tx = server.update_tx_secret().unwrap();
    let new_server_rx = server.update_rx_secret().unwrap();

    assert_secrets_equal(new_server_tx, new_client_rx);
    assert_secrets_equal(new_server_rx, new_client_tx);
}

#[test]
#[cfg(feature = "tls12")]
fn key_updates_tls12() {
    let _ = env_logger::try_init();

    let mut server_config = make_server_config_with_versions(KeyType::Rsa2048, &[&TLS12]);
    server_config.enable_secret_extraction = true;
    let server_config = Arc::new(server_config);

    let mut client_config = make_client_config_with_versions(KeyType::Rsa2048, &[&TLS12]);
    client_config.enable_secret_extraction = true;
    let client_config = Arc::new(client_config);

    let mut server = UnbufferedServerConnection::new(server_config).unwrap();
    let mut client =
        UnbufferedClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();

    do_unbuffered_handshake(&mut client, &mut server);

    let (_, mut client) = client
        .dangerous_into_kernel_connection()
        .expect("failed to convert client connection to an KernelConnection");
    let (_, mut server) = server
        .dangerous_into_kernel_connection()
        .expect("failed to convert server connection to an KernelConnection");

    // TLS 1.2 does not allow key updates so these should all error
    assert!(client.update_tx_secret().is_err());
    assert!(client.update_rx_secret().is_err());

    assert!(server.update_tx_secret().is_err());
    assert!(server.update_rx_secret().is_err());
}

fn assert_secrets_equal(
    (l_seq, l_sec): (u64, ConnectionTrafficSecrets),
    (r_seq, r_sec): (u64, ConnectionTrafficSecrets),
) {
    assert_eq!(l_seq, r_seq);
    assert_eq!(explode_secrets(&l_sec), explode_secrets(&r_sec));
}

// Comparing secrets for equality is something you should never have to
// do in production code, so ConnectionTrafficSecrets doesn't implement
// PartialEq/Eq on purpose. Instead, we have to get creative.
fn explode_secrets(s: &ConnectionTrafficSecrets) -> (&[u8], &[u8]) {
    match s {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (key.as_ref(), iv.as_ref()),
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (key.as_ref(), iv.as_ref()),
        _ => panic!("unexpected secret type"),
    }
}
