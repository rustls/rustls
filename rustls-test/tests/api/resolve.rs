//! Tests for choosing a certificate/key during the handshake.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use core::hash::Hasher;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pki_types::{CertificateDer, DnsName};
use rustls::client::{ClientCredentialResolver, CredentialRequest};
use rustls::crypto::{CipherSuite, Credentials, Identity, SelectedCredential, SignatureScheme};
use rustls::enums::{ApplicationProtocol, CertificateType, ProtocolVersion};
use rustls::error::{CertificateError, Error, PeerMisbehaved};
use rustls::server::{ClientHello, ServerCredentialResolver, ServerNameResolver};
use rustls::{
    ClientConfig, Connection, DistinguishedName, ServerConfig, ServerConnection,
    SupportedCipherSuite,
};
use rustls_test::{
    ClientConfigExt, ErrorFromPeer, KeyType, ServerCheckCertResolve,
    certificate_error_expecting_name, do_handshake_until_error, make_client_config,
    make_pair_for_arc_configs, make_pair_for_configs, make_server_config,
    make_server_config_with_client_verifier, make_server_config_with_mandatory_client_auth,
    provider_with_one_suite, server_name, transfer, webpki_client_verifier_builder,
};

use super::{ALL_VERSIONS, provider, provider_is_aws_lc_rs};

#[test]
fn server_cert_resolve_with_sni() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = Arc::new(make_client_config(*kt, &provider));
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("the.value.from.sni").unwrap()),
            ..Default::default()
        });

        let mut client = client_config
            .connect(server_name("the.value.from.sni"))
            .build()
            .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            err.err(),
            Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
        );
    }
}

#[test]
fn server_cert_resolve_with_alpn() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_config = make_client_config(*kt, &provider);
        client_config.alpn_protocols = vec![
            ApplicationProtocol::from(b"foo"),
            ApplicationProtocol::from(b"bar"),
        ];

        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client = Arc::new(client_config)
            .connect(server_name("sni-value"))
            .build()
            .unwrap();

        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            err.err(),
            Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
        );
    }
}

#[test]
fn server_cert_resolve_with_named_groups() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);

        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_named_groups: Some(
                provider
                    .kx_groups
                    .iter()
                    .map(|kx| kx.name())
                    .collect(),
            ),
            ..Default::default()
        });

        let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            err.err(),
            Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
        );
    }
}

#[test]
fn client_trims_terminating_dot() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = Arc::new(make_client_config(*kt, &provider));
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("some-host.com").unwrap()),
            ..Default::default()
        });

        let mut client = client_config
            .connect(server_name("some-host.com."))
            .build()
            .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(
            err.err(),
            Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
        );
    }
}

fn check_sigalgs_reduced_by_ciphersuite(
    kt: KeyType,
    suite: CipherSuite,
    expected_sigalgs: Vec<SignatureScheme>,
) {
    let client_config = ClientConfig::builder(
        provider_with_one_suite(&provider::DEFAULT_PROVIDER, find_suite(suite)).into(),
    )
    .finish(kt);

    let mut server_config = make_server_config(kt, &provider::DEFAULT_PROVIDER);

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        expected_cipher_suites: Some(vec![suite, CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
        ..Default::default()
    });

    let mut client = Arc::new(client_config)
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server);
    assert_eq!(
        Some(ErrorFromPeer::Server(Error::NoSuitableCertificate)),
        err.err()
    );
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    if let Some(found) = provider::ALL_TLS12_CIPHER_SUITES
        .iter()
        .find(|cs| cs.common.suite == suite)
    {
        return SupportedCipherSuite::Tls12(found);
    }

    if let Some(found) = provider::ALL_TLS13_CIPHER_SUITES
        .iter()
        .find(|cs| cs.common.suite == suite)
    {
        return SupportedCipherSuite::Tls13(found);
    }

    panic!("find_suite given unsupported suite {suite:?}");
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_rsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Rsa2048,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        vec![
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
    );
}

#[test]
fn server_cert_resolve_reduces_sigalgs_for_ecdsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::EcdsaP256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        if provider_is_aws_lc_rs() {
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED25519,
            ]
        } else {
            vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        },
    );
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {
    let provider = provider::DEFAULT_PROVIDER;
    for kt in KeyType::all_for_provider(&provider) {
        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckNoSni {});
        let server_config = Arc::new(server_config);

        for version_provider in ALL_VERSIONS {
            let mut client_config = make_client_config(*kt, &version_provider);
            client_config.enable_sni = false;

            let mut client = Arc::new(client_config)
                .connect(server_name("value-not-sent"))
                .build()
                .unwrap();

            let mut server = ServerConnection::new(server_config.clone()).unwrap();
            let err = do_handshake_until_error(&mut client, &mut server);
            dbg!(&err);
            assert_eq!(
                err.err(),
                Some(ErrorFromPeer::Server(Error::NoSuitableCertificate))
            );
        }
    }
}

#[derive(Debug)]
struct ServerCheckNoSni {}

impl ServerCredentialResolver for ServerCheckNoSni {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        // We expect the client to not send SNI.
        assert!(client_hello.server_name().is_none());
        Err(Error::NoSuitableCertificate)
    }
}

#[derive(Debug)]
struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
    expect_root_hint_subjects: Vec<DistinguishedName>,
    expect_sigschemes: Vec<SignatureScheme>,
}

impl ClientCheckCertResolve {
    fn new(
        expect_queries: usize,
        expect_root_hint_subjects: Vec<DistinguishedName>,
        expect_sigschemes: Vec<SignatureScheme>,
    ) -> Self {
        Self {
            query_count: AtomicUsize::new(0),
            expect_queries,
            expect_root_hint_subjects,
            expect_sigschemes,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ClientCredentialResolver for ClientCheckCertResolve {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);

        if request.signature_schemes().is_empty() {
            panic!("no signature schemes shared by server");
        }

        assert_eq!(request.signature_schemes(), self.expect_sigschemes);
        assert_eq!(
            request.root_hint_subjects(),
            &self.expect_root_hint_subjects
        );

        None
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

fn test_client_cert_resolve(
    key_type: KeyType,
    server_config: Arc<ServerConfig>,
    expected_root_hint_subjects: Vec<DistinguishedName>,
) {
    for (version, version_provider) in [
        (ProtocolVersion::TLSv1_3, &provider::DEFAULT_TLS13_PROVIDER),
        (ProtocolVersion::TLSv1_2, &provider::DEFAULT_TLS12_PROVIDER),
    ] {
        println!("{version:?} {key_type:?}:");

        let client_config = ClientConfig::builder(version_provider.clone().into())
            .add_root_certs(key_type)
            .with_client_credential_resolver(Arc::new(ClientCheckCertResolve::new(
                1,
                expected_root_hint_subjects.clone(),
                default_signature_schemes(version),
            )))
            .unwrap();

        let (mut client, mut server) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            do_handshake_until_error(&mut client, &mut server),
            Err(ErrorFromPeer::Server(Error::PeerMisbehaved(
                PeerMisbehaved::NoCertificatesPresented
            )))
        );
    }
}

fn default_signature_schemes(version: ProtocolVersion) -> Vec<SignatureScheme> {
    let mut v = vec![];

    v.extend_from_slice(&[
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
    ]);

    if provider_is_aws_lc_rs() {
        v.insert(2, SignatureScheme::ECDSA_NISTP521_SHA512);
    }

    if version == ProtocolVersion::TLSv1_2 {
        v.extend_from_slice(&[
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]);
    }

    v
}

#[test]
fn client_cert_resolve_default() {
    // Test that in the default configuration that a client cert resolver gets the expected
    // CA subject hints, and supported signature algorithms.
    let provider = provider::DEFAULT_PROVIDER;
    for key_type in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *key_type, &provider,
        ));

        // In a default configuration we expect that the verifier's trust anchors are used
        // for the hint subjects.
        let expected_root_hint_subjects = vec![key_type.ca_distinguished_name()];

        test_client_cert_resolve(*key_type, server_config, expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_no_hints() {
    // Test that a server can provide no hints and the client cert resolver gets the expected
    // arguments.
    let provider = provider::DEFAULT_PROVIDER;
    for key_type in KeyType::all_for_provider(&provider) {
        // Build a verifier with no hint subjects.
        let verifier = webpki_client_verifier_builder(key_type.client_root_store(), &provider)
            .clear_root_hint_subjects();
        let server_config = make_server_config_with_client_verifier(*key_type, verifier, &provider);
        let expected_root_hint_subjects = Vec::default(); // no hints expected.
        test_client_cert_resolve(*key_type, server_config.into(), expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_added_hint() {
    // Test that a server can add an extra subject above/beyond those found in its trust store
    // and the client cert resolver gets the expected arguments.
    let provider = provider::DEFAULT_PROVIDER;
    let extra_name = DistinguishedName::from(
        b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponyland IDK CA".to_vec(),
    );
    for key_type in KeyType::all_for_provider(&provider) {
        let expected_hint_subjects = vec![key_type.ca_distinguished_name(), extra_name.clone()];
        // Create a verifier that adds the extra_name as a hint subject in addition to the ones
        // from the root cert store.
        let verifier = webpki_client_verifier_builder(key_type.client_root_store(), &provider)
            .add_root_hint_subjects([extra_name.clone()].into_iter());
        let server_config = make_server_config_with_client_verifier(*key_type, verifier, &provider);
        test_client_cert_resolve(*key_type, server_config.into(), expected_hint_subjects);
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    let resolver = ServerNameResolver::new();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version_provider in ALL_VERSIONS {
        let client_config = Arc::new(make_client_config(kt, &version_provider));
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let mut client = client_config
            .connect(server_name("thisdoesNOTexist.com"))
            .build()
            .unwrap();

        assert_eq!(None, server.server_name());
        transfer(&mut client, &mut server);
        assert_eq!(
            server.process_new_packets(),
            Err(Error::NoSuitableCertificate)
        );
        assert_eq!(
            Some(&DnsName::try_from("thisdoesnotexist.com").unwrap()),
            server.server_name()
        );
    }
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    let mut resolver = ServerNameResolver::new();
    let signing_key = kt.load_key(&provider);
    resolver
        .add(
            DnsName::try_from("localhost").unwrap(),
            Credentials::new(kt.identity(), signing_key).expect("keys match"),
        )
        .unwrap();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = Arc::new(make_client_config(kt, &provider))
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(server_config).unwrap();
    let mut client2 = Arc::new(make_client_config(kt, &provider))
        .connect(server_name("notlocalhost"))
        .build()
        .unwrap();
    let err = do_handshake_until_error(&mut client2, &mut server2);
    assert_eq!(
        err,
        Err(ErrorFromPeer::Server(Error::NoSuitableCertificate))
    );
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::Rsa2048;
    let mut resolver = ServerNameResolver::new();

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            Credentials::new(kt.identity(), kt.load_key(&provider::DEFAULT_PROVIDER))
                .expect("keys match")
        )
    );
    assert_eq!(
        Err(Error::InvalidCertificate(certificate_error_expecting_name(
            "not-localhost"
        ))),
        resolver.add(
            DnsName::try_from("not-localhost").unwrap(),
            Credentials::new(kt.identity(), kt.load_key(&provider::DEFAULT_PROVIDER))
                .expect("keys match")
        )
    );
}

#[test]
fn sni_resolver_lower_cases_configured_names() {
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    let mut resolver = ServerNameResolver::new();
    let signing_key = kt.load_key(&provider);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("LOCALHOST").unwrap(),
            Credentials::new(kt.identity(), signing_key).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config).unwrap();
    let mut client1 = Arc::new(make_client_config(kt, &provider))
        .connect(server_name("localhost"))
        .build()
        .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_lower_cases_queried_names() {
    // actually, the handshake parser does this, but the effect is the same.
    let kt = KeyType::Rsa2048;
    let provider = provider::DEFAULT_PROVIDER;
    let mut resolver = ServerNameResolver::new();
    let signing_key = kt.load_key(&provider);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            Credentials::new(kt.identity(), signing_key).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config).unwrap();
    let mut client1 = Arc::new(make_client_config(kt, &provider))
        .connect(server_name("LOCALHOST"))
        .build()
        .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::Rsa2048;
    let mut resolver = ServerNameResolver::new();

    let bad_chain =
        Arc::from(Identity::from_cert_chain(vec![CertificateDer::from(vec![0xa0])]).unwrap());
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            Credentials::new_unchecked(bad_chain, kt.load_key(&provider::DEFAULT_PROVIDER))
        )
    );
}
