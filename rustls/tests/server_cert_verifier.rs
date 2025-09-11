//! Tests for configuring and using a [`ServerCertVerifier`] for a client.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use super::*;

mod common;

use common::{
    Arc, ErrorFromPeer, KeyType, MockServerVerifier, all_versions, do_handshake,
    do_handshake_until_both_error, do_handshake_until_error, make_client_config,
    make_pair_for_arc_configs, make_server_config,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerIdentity,
    SignatureVerificationInput,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DistinguishedName, Error, InvalidMessage,
    RootCertStore, ServerConfig,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

#[test]
fn client_can_override_certificate_verification() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let verifier = Arc::new(MockServerVerifier::accepts_anything());

        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let mut client_config = make_client_config(*kt, &version_provider);
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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let verifier = Arc::new(MockServerVerifier::rejects_certificate(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let mut client_config = make_client_config(*kt, &version_provider);
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

#[test]
fn client_can_override_certificate_verification_and_reject_tls12_signatures() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let mut client_config = make_client_config(*kt, &provider.clone().with_only_tls12());
        let verifier = Arc::new(MockServerVerifier::rejects_tls12_signatures(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        let server_config = Arc::new(make_server_config(*kt, &provider));

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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let mut client_config = make_client_config(*kt, &provider.clone().with_only_tls13());
        let verifier = Arc::new(MockServerVerifier::rejects_tls13_signatures(
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
        ));

        client_config
            .dangerous()
            .set_certificate_verifier(verifier);

        let server_config = Arc::new(make_server_config(*kt, &provider));

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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider).iter() {
        let verifier = Arc::new(MockServerVerifier::offers_no_signature_schemes());

        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let mut client_config = make_client_config(*kt, &version_provider);
            client_config
                .dangerous()
                .set_certificate_verifier(verifier.clone());

            let (mut client, mut server) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            let errs = do_handshake_until_both_error(&mut client, &mut server);
            assert_eq!(
                errs,
                Err(vec![
                    ErrorFromPeer::Server(Error::InvalidMessage(
                        rustls::InvalidMessage::NoSignatureSchemes
                    )),
                    ErrorFromPeer::Client(Error::AlertReceived(AlertDescription::DecodeError)),
                ])
            );
        }
    }
}

#[test]
fn client_can_request_certain_trusted_cas() {
    let provider = provider::default_provider();
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
                    kt.certified_key_with_cert_chain(&provider)
                        .unwrap(),
                )
            })
            .collect(),
    );

    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider.clone().into())
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver.clone()))
            .unwrap(),
    );

    let mut cas_unaware_error_count = 0;

    for key_type in key_types {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(key_type.ca_cert())
            .unwrap();
        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), &provider)
                .build()
                .unwrap();

        let cas_sending_server_verifier = Arc::new(ServerCertVerifierWithCasExt {
            verifier: server_verifier.clone(),
            ca_names: Arc::from(vec![DistinguishedName::from(
                key_type
                    .ca_distinguished_name()
                    .to_vec(),
            )]),
        });

        let cas_sending_client_config =
            ClientConfig::builder_with_provider(provider.clone().into())
                .dangerous()
                .with_custom_certificate_verifier(cas_sending_server_verifier)
                .with_no_client_auth()
                .unwrap();

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(cas_sending_client_config), &server_config);
        do_handshake(&mut client, &mut server);

        let cas_unaware_client_config =
            ClientConfig::builder_with_provider(provider.clone().into())
                .dangerous()
                .with_custom_certificate_verifier(server_verifier)
                .with_no_client_auth()
                .unwrap();

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
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(cas_extension) = client_hello.certificate_authorities() else {
            println!(
                "ResolvesCertChainByCaName: no CAs extension in ClientHello, returning default cert"
            );
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
    ca_names: Arc<[DistinguishedName]>,
}

impl ServerCertVerifier for ServerCertVerifierWithCasExt {
    fn verify_server_cert(
        &self,
        identity: &ServerIdentity<'_>,
    ) -> Result<ServerCertVerified, Error> {
        self.verifier
            .verify_server_cert(identity)
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier
            .verify_tls13_signature(input)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        self.verifier.request_ocsp_response()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.verifier.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        println!("ServerCertVerifierWithCasExt::root_hint_subjects() called!");
        Some(self.ca_names.clone())
    }
}
