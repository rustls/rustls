//! Tests for configuring and using a [`ClientCertVerifier`] for a server.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use rustls::server::danger::ClientCertVerified;
use rustls::{
    AlertDescription, CertificateError, ClientConnection, Error, InvalidMessage, PeerIdentity,
    PeerMisbehaved, ServerConfig, ServerConnection,
};
use rustls_test::{
    do_handshake, make_server_config_with_client_verifier,
    make_server_config_with_mandatory_client_auth, make_server_config_with_optional_client_auth,
    webpki_client_verifier_builder,
};

use super::common::{
    Arc, ErrorFromPeer, KeyType, MockClientVerifier, all_versions, do_handshake_until_both_error,
    do_handshake_until_error, make_client_config, make_client_config_with_auth,
    make_pair_for_arc_configs, server_name,
};
use super::*;

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
    ServerConfig::builder_with_provider(provider::default_provider().into())
        .with_client_cert_verifier(Arc::new(client_cert_verifier))
        .with_single_cert(kt.chain(), kt.key())
        .unwrap()
}

#[test]
// Happy path, we resolve to a root, it is verified OK, should be able to connect
fn client_verifier_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let client_verifier = MockClientVerifier::new(ver_ok, *kt, &provider);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let mut client_verifier = MockClientVerifier::new(ver_ok, *kt, &provider);
        client_verifier.offered_schemes = Some(vec![]);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let client_verifier = MockClientVerifier::new(ver_unreachable, *kt, &provider);

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::PeerMisbehaved(
                        PeerMisbehaved::NoCertificatesPresented
                    )),
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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let client_verifier = MockClientVerifier::new(ver_err, *kt, &provider);
        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
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

/// Test that the server handles combination of `offer_client_auth()` returning true
/// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
/// client's and server's ability to "recover" from the server asking for a client
/// certificate and not being given one.
#[test]
fn server_allow_any_anonymous_or_authenticated_client() {
    let provider = Arc::new(provider::default_provider());
    let kt = KeyType::Rsa2048;
    for client_cert_chain in [None, Some(kt.client_chain())] {
        let client_auth = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .allow_unauthenticated()
            .build()
            .unwrap();

        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_client_cert_verifier(client_auth)
            .with_single_cert(kt.chain(), kt.key())
            .unwrap();
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let client_config = if client_cert_chain.is_some() {
                make_client_config_with_auth(kt, &version_provider)
            } else {
                make_client_config(kt, &version_provider)
            };
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = match server.peer_identity() {
                Some(PeerIdentity::X509(certs)) => Some(certs),
                None => None,
                _ => panic!("expected X509 certs"),
            };

            let (certs, client_chain) = match (certs, &client_cert_chain) {
                (Some(certs), Some(client_chain)) => (certs, client_chain),
                (None, None) => continue,
                _ => panic!("expected both sides to agree on presence of client certs"),
            };

            assert_eq!(certs.end_entity, client_chain[0]);
            assert_eq!(certs.intermediates, &client_chain[1..]);
        }
    }
}

#[test]
fn client_auth_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *kt, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[test]
fn client_mandatory_auth_client_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let relevant_crls = vec![kt.client_crl()];
        // Only check the EE certificate status. See client_mandatory_auth_intermediate_revocation_works
        // for testing revocation status of the whole chain.
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(relevant_crls)
            .only_check_end_entity_revocation();
        let revoked_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // and uses the default behaviour of treating unknown revocation status as an error.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();
        let missing_client_crl_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // but change the builder to allow unknown revocation status.
        let ee_verifier_builder = webpki_client_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let allow_missing_client_crl_server_config = Arc::new(
            make_server_config_with_client_verifier(*kt, ee_verifier_builder, &provider),
        );

        for version_provider in all_versions(&provider) {
            // Connecting to the server with a CRL that indicates the client certificate is revoked
            // should fail with the expected error.
            let client_config = Arc::new(make_client_config_with_auth(*kt, &version_provider));
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &revoked_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // Connecting to the server missing CRL information for the client certificate should
            // fail with the expected unknown revocation status error.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                res,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            );
            // Connecting to the server missing CRL information for the client should not error
            // if the server's verifier allows unknown revocation status.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &allow_missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_mandatory_auth_intermediate_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the intermediate certificate
        // is revoked. We check the full chain for revocation status (default), and allow unknown
        // revocation status so the EE's unknown revocation status isn't an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_client_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();
        let full_chain_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            full_chain_verifier_builder,
            &provider,
        ));

        // Also create a server configuration that uses the same CRL, but that only checks the EE
        // cert revocation status.
        let ee_only_verifier_builder =
            webpki_client_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();
        let ee_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_only_verifier_builder,
            &provider,
        ));

        for version_provider in all_versions(&provider) {
            // When checking the full chain, we expect an error - the intermediate is revoked.
            let client_config = Arc::new(make_client_config_with_auth(*kt, &version_provider));
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &full_chain_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // However, when checking just the EE cert we expect no error - the intermediate's
            // revocation status should not be checked.
            let (mut client, mut server) =
                make_pair_for_arc_configs(&client_config, &ee_server_config);
            assert!(do_handshake_until_error(&mut client, &mut server).is_ok());
        }
    }
}

#[test]
fn client_optional_auth_client_revocation_works() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let crls = vec![kt.client_crl()];
        let server_config = Arc::new(make_server_config_with_optional_client_auth(
            *kt, crls, &provider,
        ));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_auth(*kt, &version_provider);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            // Because the client certificate is revoked, the handshake should fail.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}
