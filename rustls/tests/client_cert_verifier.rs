//! Tests for configuring and using a [`ClientCertVerifier`] for a server.

#![allow(clippy::duplicate_mod)]

use super::*;

mod common;
use std::sync::Arc;

use common::{
    do_handshake_until_both_error, do_handshake_until_error, make_client_config_with_versions,
    make_client_config_with_versions_with_auth, make_pair_for_arc_configs, server_config_builder,
    server_name, ErrorFromPeer, KeyType, MockClientVerifier, ALL_KEY_TYPES,
};
use rustls::server::danger::ClientCertVerified;
use rustls::{
    AlertDescription, ClientConnection, Error, InvalidMessage, ServerConfig, ServerConnection,
};

// Client is authorized!
fn ver_ok() -> Result<ClientCertVerified, Error> {
    Ok(ClientCertVerified::assertion())
}

// Use when we shouldn't even attempt verification
fn ver_unreachable() -> Result<ClientCertVerified, Error> {
    unreachable!()
}

// Verifier that returns an error that we can expect
fn ver_err() -> Result<ClientCertVerified, Error> {
    Err(Error::General("test err".to_string()))
}

fn server_config_with_verifier(
    kt: KeyType,
    client_cert_verifier: MockClientVerifier,
) -> ServerConfig {
    server_config_builder()
        .with_client_cert_verifier(Arc::new(client_cert_verifier))
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

#[test]
// Happy path, we resolve to a root, it is verified OK, should be able to connect
fn client_verifier_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier::new(ver_ok, *kt);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config.clone()), &server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(err, Ok(()));
        }
    }
}

// Server offers no verification schemes
#[test]
fn client_verifier_no_schemes() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_verifier = MockClientVerifier::new(ver_ok, *kt);
        client_verifier.offered_schemes = Some(vec![]);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config.clone()), &server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidMessage(
                    InvalidMessage::NoSignatureSchemes,
                ))),
            );
        }
    }
}

// If we do have a root, we must do auth
#[test]
fn client_verifier_no_auth_yes_root() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier::new(ver_unreachable, *kt);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::NoCertificatesPresented),
                    ErrorFromPeer::Client(Error::AlertReceived(
                        AlertDescription::CertificateRequired
                    ))
                ])
            );
        }
    }
}

#[test]
// Triple checks we propagate the rustls::Error through
fn client_verifier_fails_properly() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier::new(ver_err, *kt);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::General("test err".into())))
            );
        }
    }
}
