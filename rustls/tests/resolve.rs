//! Tests for choosing a certificate/key during the handshake.

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use pki_types::{CertificateDer, DnsName};
use rustls::client::ResolvesClientCert;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::{CertifiedKey, CertifiedSigner};
use rustls::{
    ApiMisuse, CertificateError, CertificateType, CipherSuite, ClientConfig, ClientConnection,
    DistinguishedName, Error, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection,
    SignatureScheme, SupportedCipherSuite,
};
use rustls_test::{
    ClientConfigExt, ErrorFromPeer, KeyType, ServerCheckCertResolve,
    certificate_error_expecting_name, do_handshake_until_error, make_client_config,
    make_pair_for_arc_configs, make_pair_for_configs, make_server_config,
    make_server_config_with_client_verifier, make_server_config_with_mandatory_client_auth,
    server_name, transfer, webpki_client_verifier_builder,
};

use super::{provider, provider_is_aws_lc_rs};
use crate::common::{all_versions, provider_with_one_suite};

#[test]
fn server_cert_resolve_with_sni() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("the.value.from.sni").unwrap()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("the.value.from.sni"))
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_alpn() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let mut client_config = make_client_config(*kt, &provider);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("sni-value")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_named_groups() {
    let provider = provider::default_provider();
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
        assert!(err.is_err());
    }
}

#[test]
fn client_trims_terminating_dot() {
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let client_config = make_client_config(*kt, &provider);
        let mut server_config = make_server_config(*kt, &provider);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some(DnsName::try_from("some-host.com").unwrap()),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("some-host.com.")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

fn check_sigalgs_reduced_by_ciphersuite(
    kt: KeyType,
    suite: CipherSuite,
    expected_sigalgs: Vec<SignatureScheme>,
) {
    let client_config = ClientConfig::builder_with_provider(
        provider_with_one_suite(&provider::default_provider(), find_suite(suite)).into(),
    )
    .finish(kt);

    let mut server_config = make_server_config(kt, &provider::default_provider());

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        expected_cipher_suites: Some(vec![suite, CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
        ..Default::default()
    });

    let mut client =
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server);
    assert!(err.is_err());
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
    let provider = provider::default_provider();
    for kt in KeyType::all_for_provider(&provider) {
        let mut server_config = make_server_config(*kt, &provider);
        server_config.cert_resolver = Arc::new(ServerCheckNoSni {});
        let server_config = Arc::new(server_config);

        for version_provider in all_versions(&provider) {
            let mut client_config = make_client_config(*kt, &version_provider);
            client_config.enable_sni = false;

            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("value-not-sent"))
                    .unwrap();
            let mut server = ServerConnection::new(server_config.clone()).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            dbg!(&err);
            assert!(err.is_err());
        }
    }
}

#[derive(Debug)]
struct ServerCheckNoSni {}

impl ResolvesServerCert for ServerCheckNoSni {
    fn resolve(&self, client_hello: &ClientHello) -> Result<CertifiedSigner, Error> {
        // We expect the client to not send SNI.
        assert!(client_hello.server_name().is_none());
        Err(Error::NoSuitableCertificate)
    }
}

#[derive(Debug)]
struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
    expect_root_hint_subjects: Vec<Vec<u8>>,
    expect_sigschemes: Vec<SignatureScheme>,
}

impl ClientCheckCertResolve {
    fn new(
        expect_queries: usize,
        expect_root_hint_subjects: Vec<Vec<u8>>,
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

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedSigner> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);

        if sigschemes.is_empty() {
            panic!("no signature schemes shared by server");
        }

        assert_eq!(sigschemes, self.expect_sigschemes);
        assert_eq!(root_hint_subjects, self.expect_root_hint_subjects);

        None
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }
}

fn test_client_cert_resolve(
    key_type: KeyType,
    server_config: Arc<ServerConfig>,
    expected_root_hint_subjects: Vec<Vec<u8>>,
) {
    let provider = provider::default_provider();
    for (version, version_provider) in [
        (
            ProtocolVersion::TLSv1_3,
            &provider.clone().with_only_tls13(),
        ),
        (
            ProtocolVersion::TLSv1_2,
            &provider.clone().with_only_tls12(),
        ),
    ] {
        println!("{version:?} {key_type:?}:");

        let mut client_config = make_client_config(key_type, version_provider);
        client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(
            1,
            expected_root_hint_subjects.clone(),
            default_signature_schemes(version),
        ));

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
    let provider = provider::default_provider();
    for key_type in KeyType::all_for_provider(&provider) {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(
            *key_type, &provider,
        ));

        // In a default configuration we expect that the verifier's trust anchors are used
        // for the hint subjects.
        let expected_root_hint_subjects = vec![
            key_type
                .ca_distinguished_name()
                .to_vec(),
        ];

        test_client_cert_resolve(*key_type, server_config, expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_no_hints() {
    // Test that a server can provide no hints and the client cert resolver gets the expected
    // arguments.
    let provider = provider::default_provider();
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
    let provider = provider::default_provider();
    let extra_name = b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponyland IDK CA".to_vec();
    for key_type in KeyType::all_for_provider(&provider) {
        let expected_hint_subjects = vec![
            key_type
                .ca_distinguished_name()
                .to_vec(),
            extra_name.clone(),
        ];
        // Create a verifier that adds the extra_name as a hint subject in addition to the ones
        // from the root cert store.
        let verifier = webpki_client_verifier_builder(key_type.client_root_store(), &provider)
            .add_root_hint_subjects([DistinguishedName::from(extra_name.clone())].into_iter());
        let server_config = make_server_config_with_client_verifier(*key_type, verifier, &provider);
        test_client_cert_resolve(*key_type, server_config.into(), expected_hint_subjects);
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version_provider in all_versions(&provider) {
        let client_config = make_client_config(kt, &version_provider);
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("thisdoesNOTexist.com"))
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
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = kt.load_key(&provider);
    resolver
        .add(
            DnsName::try_from("localhost").unwrap(),
            CertifiedKey::new(kt.chain(), signing_key).expect("keys match"),
        )
        .unwrap();

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("localhost"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client2 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("notlocalhost"),
    )
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
    let mut resolver = ResolvesServerCertUsingSni::new();

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            CertifiedKey::new(kt.chain(), kt.load_key(&provider::default_provider()))
                .expect("keys match")
        )
    );
    assert_eq!(
        Err(Error::InvalidCertificate(certificate_error_expecting_name(
            "not-localhost"
        ))),
        resolver.add(
            DnsName::try_from("not-localhost").unwrap(),
            CertifiedKey::new(kt.chain(), kt.load_key(&provider::default_provider()))
                .expect("keys match")
        )
    );
}

#[test]
fn sni_resolver_lower_cases_configured_names() {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = kt.load_key(&provider);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("LOCALHOST").unwrap(),
            CertifiedKey::new(kt.chain(), signing_key).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("localhost"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_lower_cases_queried_names() {
    // actually, the handshake parser does this, but the effect is the same.
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = kt.load_key(&provider);

    assert_eq!(
        Ok(()),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            CertifiedKey::new(kt.chain(), signing_key).expect("keys match")
        )
    );

    let mut server_config = make_server_config(kt, &provider);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
    let mut client1 = ClientConnection::new(
        Arc::new(make_client_config(kt, &provider)),
        server_name("LOCALHOST"),
    )
    .unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::Rsa2048;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();

    assert_eq!(
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            CertifiedKey::new_unchecked(Arc::from([]), kt.load_key(&provider::default_provider()))
        ),
        Err(ApiMisuse::EmptyCertificateChain.into()),
    );

    let bad_chain = Arc::from([CertificateDer::from(vec![0xa0])]);
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        resolver.add(
            DnsName::try_from("localhost").unwrap(),
            CertifiedKey::new_unchecked(bad_chain, kt.load_key(&provider::default_provider()))
        )
    );
}
