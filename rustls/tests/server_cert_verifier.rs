//! Tests for configuring and using a [`ServerCertVerifier`] for a client.

#![allow(clippy::duplicate_mod)]

use super::*;

mod common;

use common::{
    client_config_builder, client_config_builder_with_versions, do_handshake,
    do_handshake_until_both_error, do_handshake_until_error, make_client_config_with_versions,
    make_pair_for_arc_configs, make_server_config, server_config_builder, transfer_altered,
    Altered, Arc, ErrorFromPeer, KeyType, MockServerVerifier, ALL_KEY_TYPES,
};

use pki_types::{CertificateDer, ServerName};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::internal::msgs::handshake::{ClientExtension, HandshakePayload};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::{
    AlertDescription, CertificateError, DigitallySignedStruct, DistinguishedName, Error,
    InvalidMessage, RootCertStore,
};

use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

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

#[test]
fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa2048));

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store
        .add(KeyType::Rsa2048.ca_cert())
        .unwrap();

    let server_verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_cert_store),
        Arc::new(provider::default_provider()),
    )
    .build()
    .unwrap();
    let cas_sending_server_verifier = Arc::new(ServerCertVerifierWithCasExt {
        verifier: server_verifier.clone(),
        ca_names: vec![KeyType::Rsa2048
            .ca_distinguished_name()
            .to_vec()
            .into()],
    });

    for (protocol_version, cas_extension_expected) in [(&TLS12, false), (&TLS13, true)] {
        let client_config = Arc::new(
            client_config_builder_with_versions(&[protocol_version])
                .dangerous()
                .with_custom_certificate_verifier(cas_sending_server_verifier.clone())
                .with_no_client_auth(),
        );

        let expect_cas_extension = |msg: &mut Message<'_>| -> Altered {
            if let MessagePayload::Handshake { parsed, .. } = &msg.payload {
                if let HandshakePayload::ClientHello(ch) = &parsed.payload {
                    assert_eq!(
                        ch.extensions
                            .iter()
                            .any(|ext| matches!(ext, ClientExtension::AuthorityNames(_))),
                        cas_extension_expected
                    );
                    println!("cas extension expectation met! cas_extension_expected: {cas_extension_expected}");
                }
            }
            Altered::InPlace
        };

        let (client, server) = make_pair_for_arc_configs(&client_config, &server_config);
        let (mut client, mut server) = (client.into(), server.into());
        transfer_altered(&mut client, expect_cas_extension, &mut server);
    }
}

#[test]
fn client_can_request_certain_trusted_cas() {
    // These keys have CAs with different names, which our test needs.
    // They also share the same sigalgs, so the server won't pick one over the other based on sigalgs.
    let key_types = [KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096];
    let cert_resolver = ResolvesCertChainByCaName(
        key_types
            .iter()
            .map(|kt| {
                (
                    kt.ca_distinguished_name()
                        .to_vec()
                        .into(),
                    kt.certified_key_with_cert_chain()
                        .unwrap(),
                )
            })
            .collect(),
    );

    let server_config = Arc::new(
        server_config_builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver.clone())),
    );

    let mut cas_unaware_error_count = 0;

    for key_type in key_types {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(key_type.ca_cert())
            .unwrap();
        let server_verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            Arc::new(provider::default_provider()),
        )
        .build()
        .unwrap();

        let cas_sending_server_verifier = Arc::new(ServerCertVerifierWithCasExt {
            verifier: server_verifier.clone(),
            ca_names: vec![DistinguishedName::from(
                key_type
                    .ca_distinguished_name()
                    .to_vec(),
            )],
        });

        let cas_sending_client_config = client_config_builder()
            .dangerous()
            .with_custom_certificate_verifier(cas_sending_server_verifier)
            .with_no_client_auth();

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(cas_sending_client_config), &server_config);
        do_handshake(&mut client, &mut server);

        let cas_unaware_client_config = client_config_builder()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_no_client_auth();

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(cas_unaware_client_config), &server_config);

        cas_unaware_error_count += do_handshake_until_error(&mut client, &mut server)
            .inspect_err(|e| {
                assert!(matches!(
                    e,
                    ErrorFromPeer::Client(Error::InvalidCertificate(
                        CertificateError::UnknownIssuer
                    ))
                ))
            })
            .is_err() as usize;

        println!("key type {key_type:?} success!");
    }

    // For cas_unaware clients, all of them should fail except one that happens to
    // have the cert the server sends
    assert_eq!(cas_unaware_error_count, key_types.len() - 1);
}

#[derive(Debug, Clone)]
pub struct ResolvesCertChainByCaName(Vec<(DistinguishedName, Arc<CertifiedKey>)>);

impl ResolvesServerCert for ResolvesCertChainByCaName {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(cas_extension) = client_hello.certificate_authorities() else {
            println!("ResolvesCertChainByCaName: no CAs extension in ClientHello, returning default cert");
            return Some(self.0[0].1.clone());
        };
        for (name, certified_key) in self.0.iter() {
            let name = X509Name::from_der(name.as_ref())
                .unwrap()
                .1;
            if cas_extension.iter().any(|ca_name| {
                X509Name::from_der(ca_name.as_ref()).is_ok_and(|(_, ca_name)| ca_name == name)
            }) {
                println!("ResolvesCertChainByCaName: found matching CA name: {name}");
                return Some(certified_key.clone());
            }
        }
        println!("ResolvesCertChainByCaName: no matching CA name found, returning default Cert");
        Some(self.0[0].1.clone())
    }
}

#[derive(Debug)]
struct ServerCertVerifierWithCasExt {
    verifier: Arc<dyn ServerCertVerifier>,
    ca_names: Vec<DistinguishedName>,
}

impl ServerCertVerifier for ServerCertVerifierWithCasExt {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.verifier.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        println!("ServerCertVerifierWithCasExt::root_hint_subjects() called!");
        Some(&self.ca_names)
    }
}
