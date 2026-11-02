#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;

use rustls::crypto::{Identity, VerifiedIdentity};
use rustls::enums::CertificateType;
use rustls::error::{Error, PeerIncompatible};
use rustls_test::{
    ErrorFromPeer, KeyType, ServerCheckCertResolve, make_client_config,
    make_client_config_with_raw_key_support, make_pair_for_configs, make_server_config,
    make_server_config_with_raw_key_support,
};

use super::provider;

#[test]
fn successful_raw_key_connection_and_correct_peer_certificates() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config_with_raw_key_support(*kt, &provider);
        let server_config = make_server_config_with_raw_key_support(*kt, &provider);

        let (mut client, mut server, mut buf) = make_pair_for_configs(client_config, server_config);
        buf.handshake(&mut client, &mut server);

        // Test that the client peer certificate is the server's public key
        match client
            .peer_identity()
            .map(VerifiedIdentity::identity)
        {
            Some(Identity::X509(certificates)) => {
                assert!(certificates.intermediates.is_empty());
                assert_eq!(certificates.end_entity.as_ref(), kt.spki().as_ref());
            }
            Some(Identity::RawPublicKey(spki)) => {
                assert_eq!(spki, &kt.spki());
            }
            _ => {
                unreachable!("Client should have received a certificate")
            }
        }

        // Test that the server peer certificate is the client's public key
        match server
            .peer_identity()
            .map(VerifiedIdentity::identity)
        {
            Some(Identity::X509(certificates)) => {
                assert!(certificates.intermediates.is_empty());
                assert_eq!(certificates.end_entity.as_ref(), kt.client_spki().as_ref());
            }
            Some(Identity::RawPublicKey(spki)) => {
                assert_eq!(spki, &kt.client_spki());
            }
            _ => {
                unreachable!("Server should have received a certificate")
            }
        }
    }
}

#[test]
fn correct_certificate_type_extensions_from_client_hello() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config_with_raw_key_support(*kt, &provider);
        let mut server_config = make_server_config_with_raw_key_support(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_client_cert_types: Some(vec![CertificateType::RawPublicKey]),
            expected_server_cert_types: Some(vec![CertificateType::RawPublicKey]),
            ..Default::default()
        });

        let (mut client, mut server, mut buf) = make_pair_for_configs(client_config, server_config);
        let err = buf.handshake_until_error(&mut client, &mut server);
        assert_eq!(
            err.err(),
            Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
        );
    }
}

#[test]
fn only_client_supports_raw_keys() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config_rpk = make_client_config_with_raw_key_support(*kt, &provider);
        let server_config = make_server_config(*kt, &provider);

        let (mut client_rpk, mut server, mut buf) =
            make_pair_for_configs(client_config_rpk, server_config);

        // The client
        match buf.handshake_until_error(&mut client_rpk, &mut server) {
            Err(err) => {
                assert_eq!(
                    err,
                    ErrorFromPeer::Server(Error::PeerIncompatible(
                        PeerIncompatible::IncorrectCertificateTypeExtension
                    ))
                )
            }
            _ => {
                unreachable!("Expected error because client is incorrectly configured")
            }
        }
    }
}

#[test]
fn only_server_supports_raw_keys() {
    let provider = provider::DEFAULT_TLS13_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let server_config_rpk = make_server_config_with_raw_key_support(*kt, &provider);

        let (mut client, mut server_rpk, mut buf) =
            make_pair_for_configs(client_config, server_config_rpk);

        match buf.handshake_until_error(&mut client, &mut server_rpk) {
            Err(err) => {
                assert_eq!(
                    err,
                    ErrorFromPeer::Server(Error::PeerIncompatible(
                        PeerIncompatible::IncorrectCertificateTypeExtension
                    ))
                )
            }
            _ => {
                unreachable!("Expected error because client is incorrectly configured")
            }
        }
    }
}
