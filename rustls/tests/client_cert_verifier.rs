//! Tests for configuring and using a [`ClientCertVerifier`] for a server.

#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]

mod common;

use crate::common::{
    do_handshake_until_both_error, do_handshake_until_error, get_client_root_store,
    make_client_config_with_versions, make_client_config_with_versions_with_auth,
    make_pair_for_arc_configs, server_config_builder, server_name, webpki_client_verifier_builder,
    ErrorFromPeer, KeyType, ALL_KEY_TYPES,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::internal::msgs::handshake::DistinguishedName;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    AlertDescription, ClientConnection, DigitallySignedStruct, Error, InvalidMessage, ServerConfig,
    ServerConnection, SignatureScheme,
};

use pki_types::{CertificateDer, UnixTime};

use std::sync::Arc;

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

#[derive(Debug)]
pub struct MockClientVerifier {
    parent: Arc<dyn ClientCertVerifier>,
    pub verified: fn() -> Result<ClientCertVerified, Error>,
    pub subjects: Vec<DistinguishedName>,
    pub mandatory: bool,
    pub offered_schemes: Option<Vec<SignatureScheme>>,
}

impl MockClientVerifier {
    pub fn new(verified: fn() -> Result<ClientCertVerified, Error>, kt: KeyType) -> Self {
        Self {
            parent: webpki_client_verifier_builder(get_client_root_store(kt))
                .build()
                .unwrap(),
            verified,
            subjects: get_client_root_store(kt).subjects(),
            mandatory: true,
            offered_schemes: None,
        }
    }
}

impl ClientCertVerifier for MockClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        (self.verified)()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(schemes) = &self.offered_schemes {
            schemes.clone()
        } else {
            self.parent.supported_verify_schemes()
        }
    }
}
