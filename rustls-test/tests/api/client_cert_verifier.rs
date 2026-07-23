//! Tests for configuring and using a [`ClientVerifier`] for a server.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;

use rustls::error::{AlertDescription, CertificateError, Error, InvalidMessage, PeerMisbehaved};
use rustls::server::danger::PeerVerified;
use rustls::{ClientConfig, ServerConnection, VecInput};
use rustls_test::{
    ErrorFromPeer, MockClientVerifier, MultiTest, do_handshake, do_handshake_until_both_error,
    do_handshake_until_error, make_pair_for_arc_configs, make_server_config_with_client_verifier,
    make_server_config_with_optional_client_auth, server_name, webpki_client_verifier_builder,
};

use super::provider;

// Client is authorized!
fn ver_ok() -> Result<PeerVerified, Error> {
    Ok(PeerVerified::assertion())
}

// Use when we shouldn't even attempt verification
fn ver_unreachable() -> Result<PeerVerified, Error> {
    unreachable!()
}

// Verifier that returns an error that we can expect
fn ver_err() -> Result<PeerVerified, Error> {
    Err(Error::General("test err".to_string()))
}

// Happy path, we resolve to a root, it is verified OK, should be able to connect
#[test]
fn client_verifier_works() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER)
        .require_client_auth()
        .with_client_verifier(Box::new(|kt, provider| {
            Arc::new(MockClientVerifier::new(ver_ok, kt, &provider))
        }))
    {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(err, Ok(()));
    }
}

// Server offers no verification schemes
#[test]
fn client_verifier_no_schemes() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER)
        .require_client_auth()
        .with_client_verifier(Box::new(|kt, provider| {
            let mut verifier = MockClientVerifier::new(ver_ok, kt, &provider);
            verifier.offered_schemes = Some(vec![]);
            Arc::new(verifier)
        }))
    {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            err,
            Err(ErrorFromPeer::Client(Error::InvalidMessage(
                InvalidMessage::NoSignatureSchemes,
            ))),
        );
    }
}

// server demands client auth, but client config has no credentials.
#[test]
fn client_verifier_no_auth_yes_root() {
    for (_, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER)
        .require_client_auth()
        .with_client_verifier(Box::new(|kt, provider| {
            Arc::new(MockClientVerifier::new(ver_unreachable, kt, &provider))
        }))
    {
        let mut server = ServerConnection::new(server_config).unwrap();

        let mut client = Arc::new(
            ClientConfig::builder(Arc::new(provider::DEFAULT_PROVIDER))
                .with_root_certificates(expect.key_type.client_root_store())
                .with_no_client_auth()
                .unwrap(),
        )
        .connect(server_name("localhost"))
        .build()
        .unwrap();

        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let errs = do_handshake_until_both_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            errs,
            Err(vec![
                ErrorFromPeer::Server(Error::PeerMisbehaved(
                    PeerMisbehaved::NoCertificatesPresented
                )),
                ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::CertificateRequired))
            ])
        );
    }
}

// Triple checks we propagate the rustls::Error through
#[test]
fn client_verifier_fails_properly() {
    for (client_config, server_config, _) in MultiTest::new(provider::DEFAULT_PROVIDER)
        .require_client_auth()
        .with_client_verifier(Box::new(|kt, provider| {
            Arc::new(MockClientVerifier::new(ver_err, kt, &provider))
        }))
    {
        let mut server = ServerConnection::new(server_config).unwrap();
        let mut client = client_config
            .connect(server_name("localhost"))
            .build()
            .unwrap();
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            err,
            Err(ErrorFromPeer::Server(Error::General("test err".into())))
        );
    }
}

/// Test that the server handles combination of `offer_client_auth()` returning true
/// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
/// client's and server's ability to "recover" from the server asking for a client
/// certificate and not being given one.
#[test]
fn server_allow_any_anonymous_or_authenticated_client() {
    for (client_config, server_config, expect) in MultiTest::new(provider::DEFAULT_PROVIDER)
        .with_client_verifier(Box::new(|kt, provider| {
            Arc::new(
                webpki_client_verifier_builder(kt.client_root_store(), &provider)
                    .allow_unauthenticated()
                    .build()
                    .unwrap(),
            )
        }))
    {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            server.peer_identity(),
            match expect.client_auth {
                true => Some(expect.key_type.client_identity()),
                false => None,
            }
            .as_deref()
        );
    }
}

#[test]
fn client_auth_works() {
    for (client_config, server_config, _) in
        MultiTest::new(provider::DEFAULT_PROVIDER).require_client_auth()
    {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
    }
}

#[test]
fn client_mandatory_auth_client_revocation_works() {
    let provider = provider::DEFAULT_PROVIDER;
    for (client_config, _, expect) in MultiTest::new(provider.clone()).require_client_auth() {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let relevant_crls = vec![expect.key_type.client_crl()];
        // Only check the EE certificate status. See client_mandatory_auth_intermediate_revocation_works
        // for testing revocation status of the whole chain.
        let ee_verifier_builder =
            webpki_client_verifier_builder(expect.key_type.client_root_store(), &provider)
                .with_crls(relevant_crls)
                .only_check_end_entity_revocation();
        let revoked_server_config = Arc::new(make_server_config_with_client_verifier(
            expect.key_type,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // and uses the default behaviour of treating unknown revocation status as an error.
        let unrelated_crls = vec![expect.key_type.intermediate_crl()];
        let ee_verifier_builder =
            webpki_client_verifier_builder(expect.key_type.client_root_store(), &provider)
                .with_crls(unrelated_crls.clone())
                .only_check_end_entity_revocation();
        let missing_client_crl_server_config = Arc::new(make_server_config_with_client_verifier(
            expect.key_type,
            ee_verifier_builder,
            &provider,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // but change the builder to allow unknown revocation status.
        let ee_verifier_builder =
            webpki_client_verifier_builder(expect.key_type.client_root_store(), &provider)
                .with_crls(unrelated_crls.clone())
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();
        let allow_missing_client_crl_server_config =
            Arc::new(make_server_config_with_client_verifier(
                expect.key_type,
                ee_verifier_builder,
                &provider,
            ));

        // Connecting to the server with a CRL that indicates the client certificate is revoked
        // should fail with the expected error.
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &revoked_server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
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
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let res = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
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
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        )
        .unwrap();
    }
}

#[test]
fn client_mandatory_auth_intermediate_revocation_works() {
    let provider = provider::DEFAULT_PROVIDER;
    for (client_config, _, expect) in MultiTest::new(provider.clone()).require_client_auth() {
        // Create a server configuration that includes a CRL that specifies the intermediate certificate
        // is revoked. We check the full chain for revocation status (default), and allow unknown
        // revocation status so the EE's unknown revocation status isn't an error.
        let crls = vec![expect.key_type.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_client_verifier_builder(expect.key_type.client_root_store(), &provider)
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();
        let full_chain_server_config = Arc::new(make_server_config_with_client_verifier(
            expect.key_type,
            full_chain_verifier_builder,
            &provider,
        ));

        // Also create a server configuration that uses the same CRL, but that only checks the EE
        // cert revocation status.
        let ee_only_verifier_builder =
            webpki_client_verifier_builder(expect.key_type.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();
        let ee_server_config = Arc::new(make_server_config_with_client_verifier(
            expect.key_type,
            ee_only_verifier_builder,
            &provider,
        ));

        // When checking the full chain, we expect an error - the intermediate is revoked.
        let (mut client, mut server) =
            make_pair_for_arc_configs(&client_config, &full_chain_server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            err,
            Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                CertificateError::Revoked
            )))
        );
        // However, when checking just the EE cert we expect no error - the intermediate's
        // revocation status should not be checked.
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &ee_server_config);
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        )
        .unwrap();
    }
}

#[test]
fn client_optional_auth_client_revocation_works() {
    let provider = provider::DEFAULT_PROVIDER;
    for (client_config, _, expect) in MultiTest::new(provider.clone()).require_client_auth() {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let crls = vec![expect.key_type.client_crl()];
        let server_config = Arc::new(make_server_config_with_optional_client_auth(
            expect.key_type,
            crls,
            &provider,
        ));

        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        // Because the client certificate is revoked, the handshake should fail.
        let mut client_input = VecInput::default();
        let mut server_input = VecInput::default();
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client,
            &mut server_input,
            &mut server,
        );
        assert_eq!(
            err,
            Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                CertificateError::Revoked
            )))
        );
    }
}
