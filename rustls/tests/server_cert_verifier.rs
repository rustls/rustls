//! Tests for configuring and using a [`ServerCertVerifier`] for a client.

#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]

mod common;
use crate::common::{
    do_handshake, do_handshake_until_both_error, make_client_config_with_versions,
    make_pair_for_arc_configs, make_server_config, ErrorFromPeer, MockServerVerifier,
    ALL_KEY_TYPES,
};
use rustls::{AlertDescription, Error, InvalidMessage};

use std::sync::Arc;

#[test]
fn client_can_override_certificate_verification() {
    for kt in ALL_KEY_TYPES.iter() {
        let verifier = Arc::new(MockServerVerifier::accepts_anything());

        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[test]
fn client_can_override_certificate_verification_and_reject_certificate() {
    for kt in ALL_KEY_TYPES.iter() {
        let verifier = Arc::new(MockServerVerifier::rejects_certificate(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Client(Error::InvalidMessage(
                        InvalidMessage::HandshakePayloadTooLarge,
                    )),
                    ErrorFromPeer::Server(Error::AlertReceived(AlertDescription::HandshakeFailure)),
                ]),
            );
        }
    }
}

#[cfg(feature = "tls12")]
#[test]
fn client_can_override_certificate_verification_and_reject_tls12_signatures() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS12]);
        let verifier = Arc::new(MockServerVerifier::rejects_tls12_signatures(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        let server_config = Arc::new(make_server_config(*kt));

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        let errs = do_handshake_until_both_error(&mut client, &mut server);
        assert_eq!(
            errs,
            Err(vec![
                ErrorFromPeer::Client(Error::InvalidMessage(
                    InvalidMessage::HandshakePayloadTooLarge,
                )),
                ErrorFromPeer::Server(Error::AlertReceived(AlertDescription::HandshakeFailure)),
            ]),
        );
    }
}

#[test]
fn client_can_override_certificate_verification_and_reject_tls13_signatures() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS13]);
        let verifier = Arc::new(MockServerVerifier::rejects_tls13_signatures(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        let server_config = Arc::new(make_server_config(*kt));

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        let errs = do_handshake_until_both_error(&mut client, &mut server);
        assert_eq!(
            errs,
            Err(vec![
                ErrorFromPeer::Client(Error::InvalidMessage(
                    InvalidMessage::HandshakePayloadTooLarge,
                )),
                ErrorFromPeer::Server(Error::AlertReceived(AlertDescription::HandshakeFailure)),
            ]),
        );
    }
}

#[test]
fn client_can_override_certificate_verification_and_offer_no_signature_schemes() {
    for kt in ALL_KEY_TYPES.iter() {
        let verifier = Arc::new(MockServerVerifier::offers_no_signature_schemes());

        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::PeerIncompatible(
                        rustls::PeerIncompatible::NoSignatureSchemesInCommon
                    )),
                    ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::HandshakeFailure)),
                ])
            );
        }
    }
}
