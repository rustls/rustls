//! Tests for configuring and using a [`ClientCertVerifier`] for a server.

#![cfg(feature = "dangerous_configuration")]

mod common;

use crate::common::{
    dns_name, do_handshake_until_both_error, do_handshake_until_error, get_client_root_store,
    make_client_config_with_versions, make_client_config_with_versions_with_auth,
    make_pair_for_arc_configs, ErrorFromPeer, KeyType, ALL_KEY_TYPES,
};
use rustls::client::WebPkiVerifier;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::AlertDescription;
use rustls::internal::msgs::enums::ContentType;
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    Certificate, ClientConnection, DistinguishedNames, Error, ServerConfig, ServerConnection,
    SignatureScheme,
};
use std::sync::Arc;

// Client is authorized!
fn ver_ok() -> Result<ClientCertVerified, Error> {
    Ok(rustls::server::ClientCertVerified::assertion())
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
    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(client_cert_verifier))
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

#[test]
// Happy path, we resolve to a root, it is verified OK, should be able to connect
fn client_verifier_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier {
            verified: ver_ok,
            subjects: Some(
                get_client_root_store(*kt)
                    .roots
                    .iter()
                    .map(|r| PayloadU16(r.subject().to_vec()))
                    .collect(),
            ),
            mandatory: Some(true),
            offered_schemes: None,
        };

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
        let client_verifier = MockClientVerifier {
            verified: ver_ok,
            subjects: Some(
                get_client_root_store(*kt)
                    .roots
                    .iter()
                    .map(|r| PayloadU16(r.subject().to_vec()))
                    .collect(),
            ),
            mandatory: Some(true),
            offered_schemes: Some(vec![]),
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config.clone()), &server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::CorruptMessagePayload(
                    ContentType::Handshake
                )))
            );
        }
    }
}

// Common case, we do not find a root store to resolve to
#[test]
fn client_verifier_no_root() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier {
            verified: ver_ok,
            subjects: None,
            mandatory: Some(true),
            offered_schemes: None,
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("notlocalhost")).unwrap();
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::General(
                        "client rejected by client_auth_root_subjects".into()
                    )),
                    ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                ])
            );
        }
    }
}

// If we cannot resolve a root, we cannot decide if auth is mandatory
#[test]
fn client_verifier_no_auth_no_root() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier {
            verified: ver_unreachable,
            subjects: None,
            mandatory: Some(true),
            offered_schemes: None,
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("notlocalhost")).unwrap();
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::General(
                        "client rejected by client_auth_root_subjects".into()
                    )),
                    ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                ])
            );
        }
    }
}

// If we do have a root, we must do auth
#[test]
fn client_verifier_no_auth_yes_root() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier {
            verified: ver_unreachable,
            subjects: Some(
                get_client_root_store(*kt)
                    .roots
                    .iter()
                    .map(|r| PayloadU16(r.subject().to_vec()))
                    .collect(),
            ),
            mandatory: Some(true),
            offered_schemes: None,
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
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
        let client_verifier = MockClientVerifier {
            verified: ver_err,
            subjects: Some(
                get_client_root_store(*kt)
                    .roots
                    .iter()
                    .map(|r| PayloadU16(r.subject().to_vec()))
                    .collect(),
            ),
            mandatory: Some(true),
            offered_schemes: None,
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::General("test err".into())))
            );
        }
    }
}

#[test]
// If a verifier returns a None on Mandatory-ness, then we error out
fn client_verifier_must_determine_client_auth_requirement_to_continue() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_verifier = MockClientVerifier {
            verified: ver_ok,
            subjects: Some(
                get_client_root_store(*kt)
                    .roots
                    .iter()
                    .map(|r| PayloadU16(r.subject().to_vec()))
                    .collect(),
            ),
            mandatory: None,
            offered_schemes: None,
        };

        let server_config = server_config_with_verifier(*kt, client_verifier);
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut client =
                ClientConnection::new(Arc::new(client_config), dns_name("localhost")).unwrap();
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::General(
                        "client rejected by client_auth_mandatory".into()
                    )),
                    ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::AccessDenied))
                ])
            );
        }
    }
}

pub struct MockClientVerifier {
    pub verified: fn() -> Result<ClientCertVerified, Error>,
    pub subjects: Option<DistinguishedNames>,
    pub mandatory: Option<bool>,
    pub offered_schemes: Option<Vec<SignatureScheme>>,
}

impl ClientCertVerifier for MockClientVerifier {
    fn client_auth_mandatory(&self) -> Option<bool> {
        self.mandatory
    }

    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        self.subjects.as_ref().cloned()
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: std::time::SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        (self.verified)()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(schemes) = &self.offered_schemes {
            schemes.clone()
        } else {
            WebPkiVerifier::verification_schemes()
        }
    }
}
