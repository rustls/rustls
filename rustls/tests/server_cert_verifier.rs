//! Tests for configuring and using a [`ServerCertVerifier`] for a client.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;

use pki_types::UnixTime;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerIdentity,
    SignatureVerificationInput,
};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    AlertDescription, CertificateError, CertificateType, ClientConfig, ClientConnection,
    DistinguishedName, Error, ExtendedKeyPurpose, InvalidMessage, RootCertStore, ServerConfig,
    ServerConnection,
};
use rustls_test::{
    ErrorFromPeer, KeyType, MockServerVerifier, certificate_error_expecting_name, do_handshake,
    do_handshake_until_both_error, do_handshake_until_error, make_client_config,
    make_client_config_with_verifier, make_pair_for_arc_configs, make_pair_for_configs,
    make_server_config, server_name, webpki_server_verifier_builder,
};
use webpki::anchor_from_trusted_cert;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

use super::common::all_versions;
use super::provider;

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
fn test_pinned_ocsp_response_given_to_custom_server_cert_verifier() {
    let ocsp_response = b"hello-ocsp-world!";
    let kt = KeyType::EcdsaP256;
    let provider = provider::default_provider();

    for version_provider in all_versions(&provider) {
        let server_config = ServerConfig::builder_with_provider(provider.clone().into())
            .with_no_client_auth()
            .with_single_cert_with_ocsp(kt.chain(), kt.key(), ocsp_response.to_vec())
            .unwrap();

        let client_config = ClientConfig::builder_with_provider(version_provider.into())
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(MockServerVerifier::expects_ocsp_response(
                ocsp_response,
            )))
            .with_no_client_auth()
            .unwrap();

        let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
        do_handshake(&mut client, &mut server);
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

#[test]
fn client_checks_server_certificate_with_given_ip_address() {
    fn check_server_name(
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        name: &'static str,
    ) -> Result<(), ErrorFromPeer> {
        let mut client = ClientConnection::new(client_config, server_name(name)).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake_until_error(&mut client, &mut server)
    }

    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let client_config = Arc::new(make_client_config(*kt, &version_provider));

            // positive ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.1"),
                Ok(()),
            );

            // negative ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("198.51.100.2")
                )))
            );

            // positive ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::1"),
                Ok(()),
            );

            // negative ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("2001:db8::2")
                )))
            );
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config(*kt, &version_provider);
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                server_name("not-the-right-hostname.com"),
            )
            .unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    certificate_error_expecting_name("not-the-right-hostname.com")
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_revoked() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier that will check the EE certificate's revocation status.
        let crls = vec![kt.end_entity_crl()];
        let builder = webpki_server_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(crls)
            .only_check_end_entity_revocation();

        for version_provider in all_versions(&provider) {
            let client_config =
                make_client_config_with_verifier(builder.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail since the server's EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_unknown_revocation() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier builder that will check the EE certificate's revocation status, but not
        // allow unknown revocation status (the default). We'll provide CRLs that are not relevant
        // to the EE cert to ensure its status is unknown.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let forbid_unknown_verifier =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(unrelated_crls.clone())
                .only_check_end_entity_revocation();

        // Also set up a verifier builder that will allow unknown revocation status.
        let allow_unknown_verifier =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(unrelated_crls)
                .only_check_end_entity_revocation()
                .allow_unknown_revocation_status();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                forbid_unknown_verifier.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect if we use the forbid_unknown_verifier that the handshake will fail since the
            // server's EE certificate's revocation status is unknown given the CRLs we've provided.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            );

            // We expect if we use the allow_unknown_verifier that the handshake will not fail.
            let client_config =
                make_client_config_with_verifier(allow_unknown_verifier.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_check_server_certificate_intermediate_revoked() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier builder that will check the full chain revocation status against a CRL
        // that marks the intermediate certificate as revoked. We allow unknown revocation status
        // so the EE cert's unknown status doesn't cause an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();

        // Also set up a verifier builder that will use the same CRL, but only check the EE certificate
        // revocation status.
        let ee_verifier_builder = webpki_server_verifier_builder(kt.client_root_store(), &provider)
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                full_chain_verifier_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail when using the full chain verifier since the intermediate's
            // EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );

            let client_config =
                make_client_config_with_verifier(ee_verifier_builder.clone(), &version_provider);
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            // We expect the handshake to succeed when we use the verifier that only checks the EE certificate
            // revocation status. The revoked intermediate status should not be checked.
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok())
        }
    }
}

#[test]
fn client_check_server_certificate_ee_crl_expired() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config(*kt, &provider));

        // Setup a server verifier that will check the EE certificate's revocation status, with CRL expiration enforced.
        let crls = vec![kt.end_entity_crl_expired()];
        let enforce_expiration_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration();

        // Also setup a server verifier without CRL expiration enforced.
        let crls = vec![kt.end_entity_crl_expired()];
        let ignore_expiration_builder =
            webpki_server_verifier_builder(kt.client_root_store(), &provider)
                .with_crls(crls)
                .only_check_end_entity_revocation();

        for version_provider in all_versions(&provider) {
            let client_config = make_client_config_with_verifier(
                enforce_expiration_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to fail since the CRL is expired.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert!(matches!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::ExpiredRevocationListContext { .. }
                )))
            ));

            let client_config = make_client_config_with_verifier(
                ignore_expiration_builder.clone(),
                &version_provider,
            );
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            // We expect the handshake to succeed when CRL expiration is ignored.
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok())
        }
    }
}

/// Simple smoke-test of the webpki verify_server_cert_signed_by_trust_anchor helper API.
/// This public API is intended to be used by consumers implementing their own verifier and
/// so isn't used by the other existing verifier tests.
#[test]
fn client_check_server_certificate_helper_api() {
    for kt in KeyType::all_for_provider(&provider::default_provider()) {
        let chain = kt.chain();
        let correct_roots = kt.client_root_store();
        let incorrect_roots = match kt {
            KeyType::Rsa2048 => KeyType::EcdsaP256,
            _ => KeyType::Rsa2048,
        }
        .client_root_store();
        // Using the correct trust anchors, we should verify without error.
        assert!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &correct_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .is_ok()
        );
        // Using the wrong trust anchors, we should get the expected error.
        assert_eq!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &incorrect_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
    }
}

#[test]
fn client_check_server_valid_purpose() {
    let chain = KeyType::EcdsaP256.client_chain();
    let trust_anchor = chain.last().unwrap();
    let roots = RootCertStore {
        roots: vec![
            anchor_from_trusted_cert(trust_anchor)
                .unwrap()
                .to_owned(),
        ],
    };

    let error = verify_server_cert_signed_by_trust_anchor(
        &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
        &roots,
        &[chain.get(1).unwrap().clone()],
        UnixTime::now(),
        webpki::ALL_VERIFICATION_ALGS,
    )
    .unwrap_err();
    assert_eq!(
        error,
        Error::InvalidCertificate(CertificateError::InvalidPurposeContext {
            required: ExtendedKeyPurpose::ServerAuth,
            presented: vec![ExtendedKeyPurpose::ClientAuth],
        })
    );

    assert_eq!(
        format!("{error}"),
        "invalid peer certificate: certificate does not allow extended key usage for \
         server authentication, allows client authentication"
    );
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

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        self.verifier
            .supported_certificate_types()
    }

    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        println!("ServerCertVerifierWithCasExt::root_hint_subjects() called!");
        Some(self.ca_names.clone())
    }
}
