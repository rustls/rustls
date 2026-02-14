use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hash::Hasher;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::OnceLock;
use std::vec;

use pki_types::{CertificateDer, FipsStatus, ServerName, UnixTime};

use super::{Tls12Session, Tls13ClientSessionInput, Tls13Session};
use crate::client::{ClientConfig, Resumption, Tls12Resumption};
use crate::crypto::cipher::{EncodedMessage, MessageEncrypter, Payload};
use crate::crypto::kx::{self, NamedGroup, SharedSecret, StartedKeyExchange, SupportedKxGroup};
use crate::crypto::test_provider::FakeKeyExchangeGroup;
use crate::crypto::tls13::OkmBlock;
use crate::crypto::{
    CipherSuite, Credentials, CryptoProvider, Identity, SignatureScheme, SingleCredential,
    TEST_PROVIDER, tls12_only, tls13_only, tls13_suite,
};
use crate::enums::{CertificateType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::msgs::{
    CertificateChain, ClientHelloPayload, Codec, Compression, ECCurveType, EcParameters,
    HandshakeMessagePayload, HandshakePayload, HelloRetryRequest, HelloRetryRequestExtensions,
    KeyShareEntry, MaybeEmpty, Message, MessagePayload, Random, Reader, ServerEcdhParams,
    ServerExtensions, ServerHelloPayload, ServerKeyExchange, ServerKeyExchangeParams,
    ServerKeyExchangePayload, SessionId, SizedPayload,
};
use crate::pki_types::PrivateKeyDer;
use crate::pki_types::pem::PemObject;
use crate::sync::Arc;
use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key};
use crate::verify::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
    SignatureVerificationInput,
};
use crate::{Connection, DigitallySignedStruct, DistinguishedName, KeyLog, RootCertStore};

#[test]
fn tls12_client_session_value_roundtrip() {
    let session_id = SessionId::read(&mut Reader::new(&[
        32, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20,
    ]))
    .unwrap();

    let peer_identity = Identity::X509(crate::crypto::CertificateIdentity {
        end_entity: CertificateDer::from(&b"test cert"[..]),
        intermediates: vec![],
    });

    let session = Tls12Session::new(
        TEST_PROVIDER.tls12_cipher_suites[0],
        session_id,
        Arc::new(SizedPayload::from(vec![0xde, 0xad, 0xbe, 0xef])),
        &[0xab; 48],
        peer_identity.clone(),
        UnixTime::since_unix_epoch(Duration::from_secs(1234567890)),
        Duration::from_secs(3600),
        true, // extended_ms
    );

    let mut encoded = Vec::new();
    session.encode(&mut encoded);
    let decoded = Tls12Session::from_slice(&encoded, &TEST_PROVIDER).unwrap();

    assert_eq!(decoded.suite.common.suite, session.suite.common.suite);
    assert_eq!(decoded.session_id, session_id);
    assert_eq!(&*decoded.master_secret, &*session.master_secret);
    assert_eq!(decoded.extended_ms, session.extended_ms);
    assert_eq!(decoded.common.ticket(), session.common.ticket());
    assert_eq!(decoded.common.epoch, session.common.epoch);
    assert_eq!(*decoded.common.peer_identity(), peer_identity);
}

#[test]
fn tls13_client_session_value_roundtrip() {
    let age_add = 0x12345678_u32;
    let peer_identity = Identity::RawPublicKey(pki_types::SubjectPublicKeyInfoDer::from(
        &b"raw public key"[..],
    ));

    let session = Tls13Session::new(
        Tls13ClientSessionInput {
            suite: TEST_PROVIDER.tls13_cipher_suites[0],
            peer_identity: peer_identity.clone(),
            quic_params: Some(SizedPayload::<u16, MaybeEmpty>::from(vec![
                0xaa, 0xbb, 0xcc, 0xdd,
            ])),
        },
        Arc::new(SizedPayload::from(vec![0x11, 0x22, 0x33])),
        &[0x55; 48],
        UnixTime::since_unix_epoch(Duration::from_secs(9999999)),
        Duration::from_secs(1800),
        age_add,
        8192_u32,
    );

    let mut encoded = Vec::new();
    session.encode(&mut encoded);
    let decoded = Tls13Session::from_slice(&encoded, &TEST_PROVIDER).unwrap();

    assert_eq!(decoded.suite.common.suite, session.suite.common.suite);
    assert_eq!(decoded.secret.bytes(), session.secret.bytes());
    assert_eq!(decoded.age_add, age_add);
    assert_eq!(decoded.max_early_data_size, session.max_early_data_size);
    assert_eq!(decoded.quic_params.bytes(), session.quic_params.bytes());
    assert_eq!(decoded.common.ticket(), session.common.ticket());
    assert_eq!(decoded.common.epoch, session.common.epoch);
    assert_eq!(*decoded.common.peer_identity(), peer_identity);
}

/// Tests that session_ticket(35) extension
/// is not sent if the client does not support TLS 1.2.
#[test]
fn test_no_session_ticket_request_on_tls_1_3() {
    let mut config = ClientConfig::builder(Arc::new(tls13_only(TEST_PROVIDER.clone())))
        .with_root_certificates(roots())
        .with_no_client_auth()
        .unwrap();
    config.resumption =
        Resumption::in_memory_sessions(128).tls12_resumption(Tls12Resumption::SessionIdOrTickets);
    let ch = client_hello_sent_for_config(config).unwrap();
    assert!(ch.extensions.session_ticket.is_none());
}

#[test]
fn test_no_renegotiation_scsv_on_tls_1_3() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder(Arc::new(tls13_only(TEST_PROVIDER.clone())))
            .with_root_certificates(roots())
            .with_no_client_auth()
            .unwrap(),
    )
    .unwrap();
    assert!(
        !ch.cipher_suites
            .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    );
}

#[test]
fn test_client_does_not_offer_sha1() {
    for provider in [
        tls12_only(TEST_PROVIDER.clone()),
        tls13_only(TEST_PROVIDER.clone()),
    ] {
        let config = ClientConfig::builder(Arc::new(provider))
            .with_root_certificates(roots())
            .with_no_client_auth()
            .unwrap();
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(
            !ch.extensions
                .signature_schemes
                .as_ref()
                .unwrap()
                .contains(&SignatureScheme::RSA_PKCS1_SHA1),
            "sha1 unexpectedly offered"
        );
    }
}

#[test]
fn test_client_rejects_hrr_with_varied_session_id() {
    let config = ClientConfig::builder(Arc::new(TEST_PROVIDER.clone()))
        .with_root_certificates(roots())
        .with_no_client_auth()
        .unwrap();
    let mut conn = Arc::new(config)
        .connect(ServerName::try_from("localhost").unwrap())
        .build()
        .unwrap();
    let mut sent = Vec::new();
    conn.write_tls(&mut sent).unwrap();

    // server replies with HRR, but does not echo `session_id` as required.
    let hrr = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                legacy_version: ProtocolVersion::TLSv1_2,
                session_id: SessionId::empty(),
                extensions: HelloRetryRequestExtensions {
                    cookie: Some(SizedPayload::from(vec![1, 2, 3, 4])),
                    ..HelloRetryRequestExtensions::default()
                },
            }),
        )),
    };

    conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
        .unwrap();
    assert_eq!(
        conn.process_new_packets().unwrap_err(),
        PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
    );
}

#[test]
fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
    let mut config = ClientConfig::builder(Arc::new(TEST_PROVIDER.clone()))
        .with_root_certificates(roots())
        .with_no_client_auth()
        .unwrap();
    if !matches!(config.provider().fips(), FipsStatus::Unvalidated) {
        assert!(config.require_ems);
    } else {
        config.require_ems = true;
    }

    let config = Arc::new(config);
    let mut conn = config
        .connect(ServerName::try_from("localhost").unwrap())
        .build()
        .unwrap();
    let mut sent = Vec::new();
    conn.write_tls(&mut sent).unwrap();

    let sh = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ServerHello(
            ServerHelloPayload {
                random: Random::new(config.provider().secure_random).unwrap(),
                compression_method: Compression::Null,
                cipher_suite: CipherSuite::Unknown(0xff12),
                legacy_version: ProtocolVersion::TLSv1_2,
                session_id: SessionId::empty(),
                extensions: Box::new(ServerExtensions::default()),
            },
        ))),
    };
    conn.read_tls(&mut sh.into_wire_bytes().as_slice())
        .unwrap();

    assert_eq!(
        conn.process_new_packets(),
        Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
    );
}

#[test]
fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
    let cas_sending_server_verifier =
        ServerVerifierWithAuthorityNames(Arc::from(vec![DistinguishedName::from(
            b"hello".to_vec(),
        )]));

    let tls12_provider = tls12_only(TEST_PROVIDER.clone());
    let tls13_provider = tls13_only(TEST_PROVIDER.clone());
    for (provider, cas_extension_expected) in [(tls12_provider, false), (tls13_provider, true)] {
        let client_hello = client_hello_sent_for_config(
            ClientConfig::builder(provider.into())
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                .with_no_client_auth()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            client_hello
                .extensions
                .certificate_authority_names
                .is_some(),
            cas_extension_expected
        );
    }
}

/// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
#[test]
fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
    let Some(provider) = x25519_provider(TEST_PROVIDER.clone()) else {
        return;
    };

    let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
    let config = ClientConfig::builder(Arc::new(provider))
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth()
        .unwrap();

    let mut conn = Arc::new(config)
        .connect(ServerName::try_from("localhost").unwrap())
        .build()
        .unwrap();
    let mut sent = Vec::new();
    conn.write_tls(&mut sent).unwrap();

    let sh = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ServerHello(
            ServerHelloPayload {
                random: Random([0u8; 32]),
                compression_method: Compression::Null,
                cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                legacy_version: ProtocolVersion::TLSv1_2,
                session_id: SessionId::empty(),
                extensions: Box::new(ServerExtensions {
                    extended_master_secret_ack: Some(()),
                    ..ServerExtensions::default()
                }),
            },
        ))),
    };
    conn.read_tls(&mut sh.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Certificate(
            CertificateChain(vec![CertificateDer::from(&b"does not matter"[..])]),
        ))),
    };
    conn.read_tls(&mut cert.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    let server_kx = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                ServerKeyExchange {
                    dss: DigitallySignedStruct::new(
                        SignatureScheme::ECDSA_SHA1_Legacy,
                        b"also does not matter".to_vec(),
                    ),
                    params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                        curve_params: EcParameters {
                            curve_type: ECCurveType::NamedCurve,
                            named_group: NamedGroup::X25519,
                        },
                        public: SizedPayload::from(vec![0xab; 32]),
                    }),
                },
            )),
        )),
    };
    conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    let server_done = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ServerHelloDone,
        )),
    };
    conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    assert!(
        verifier
            .seen_sha1_signature
            .load(Ordering::SeqCst)
    );
}

#[derive(Debug, Default)]
struct ExpectSha1EcdsaVerifier {
    seen_sha1_signature: AtomicBool,
}

impl ServerVerifier for ExpectSha1EcdsaVerifier {
    fn verify_identity(&self, _identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        assert_eq!(input.signature.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
        self.seen_sha1_signature
            .store(true, Ordering::SeqCst);
        Ok(HandshakeSignatureValid::assertion())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        todo!()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_SHA1_Legacy]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[test]
fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
    client_requiring_rpk_receives_server_ee(
        Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
        ServerExtensions::default(),
        &TEST_PROVIDER,
    );
}

#[test]
fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
    client_requiring_rpk_receives_server_ee(
        Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
        ServerExtensions {
            server_certificate_type: Some(CertificateType::X509),
            ..ServerExtensions::default()
        },
        &TEST_PROVIDER,
    );
}

#[test]
fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
    client_requiring_rpk_receives_server_ee(
        Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
        ServerExtensions {
            server_certificate_type: Some(CertificateType::RawPublicKey),
            ..ServerExtensions::default()
        },
        &TEST_PROVIDER,
    );
}

#[test]
fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
    client_requiring_rpk_receives_server_ee(
        Err(PeerIncompatible::IncorrectCertificateTypeExtension.into()),
        ServerExtensions {
            client_certificate_type: Some(CertificateType::X509),
            server_certificate_type: Some(CertificateType::RawPublicKey),
            ..ServerExtensions::default()
        },
        &TEST_PROVIDER,
    );
}

#[test]
fn test_client_requiring_rpk_accepts_rpk_server() {
    client_requiring_rpk_receives_server_ee(
        Ok(()),
        ServerExtensions {
            client_certificate_type: Some(CertificateType::RawPublicKey),
            server_certificate_type: Some(CertificateType::RawPublicKey),
            ..ServerExtensions::default()
        },
        &TEST_PROVIDER,
    );
}

#[track_caller]
fn client_requiring_rpk_receives_server_ee(
    expected: Result<(), Error>,
    encrypted_extensions: ServerExtensions<'_>,
    provider: &CryptoProvider,
) {
    let Some(provider) = x25519_provider(provider.clone()) else {
        return;
    };

    let provider = Arc::new(CryptoProvider {
        tls12_cipher_suites: Cow::default(),
        ..provider
    });

    let fake_server_crypto = Arc::new(FakeServerCrypto::new(provider.clone()));
    let credentials = client_credentials(&provider);
    let mut config = ClientConfig::builder(provider)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
        .with_client_credential_resolver(Arc::new(SingleCredential::from(credentials)))
        .unwrap();
    config.key_log = fake_server_crypto.clone();

    let mut conn = Arc::new(config)
        .connect(ServerName::try_from("localhost").unwrap())
        .build()
        .unwrap();
    let mut sent = Vec::new();
    conn.write_tls(&mut sent).unwrap();

    let sh = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ServerHello(
            ServerHelloPayload {
                random: Random([0; 32]),
                compression_method: Compression::Null,
                cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                legacy_version: ProtocolVersion::TLSv1_3,
                session_id: SessionId::empty(),
                extensions: Box::new(ServerExtensions {
                    key_share: Some(KeyShareEntry {
                        group: NamedGroup::X25519,
                        payload: SizedPayload::from(vec![0xaa; 32]),
                    }),
                    ..ServerExtensions::default()
                }),
            },
        ))),
    };
    conn.read_tls(&mut sh.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    let ee = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
        )),
    };

    let mut encrypter = fake_server_crypto.server_handshake_encrypter();
    let enc_ee = encrypter
        .encrypt(EncodedMessage::<Payload<'_>>::from(ee).borrow_outbound(), 0)
        .unwrap();
    conn.read_tls(&mut enc_ee.encode().as_slice())
        .unwrap();

    assert_eq!(conn.process_new_packets().map(|_| ()), expected);
}

fn client_credentials(provider: &CryptoProvider) -> Credentials {
    let key = provider
        .key_provider
        .load_private_key(client_key())
        .unwrap();
    let identity = Arc::from(Identity::RawPublicKey(
        key.public_key().unwrap().into_owned(),
    ));
    Credentials::new_unchecked(identity, key)
}

fn client_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_reader(
        &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
    )
    .unwrap()
}

fn x25519_provider(provider: CryptoProvider) -> Option<CryptoProvider> {
    // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
    // creation of fake server messages.
    let x25519 = provider.find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_3)?;
    Some(CryptoProvider {
        kx_groups: Cow::Owned(vec![x25519]),
        ..provider
    })
}

#[derive(Clone, Debug)]
struct ServerVerifierWithAuthorityNames(Arc<[DistinguishedName]>);

impl ServerVerifier for ServerVerifierWithAuthorityNames {
    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        Some(self.0.clone())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_identity(&self, _identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        unreachable!()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        unreachable!()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        unreachable!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PKCS1_SHA1]
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[derive(Debug)]
struct ServerVerifierRequiringRpk;

impl ServerVerifier for ServerVerifierRequiringRpk {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_identity(&self, _identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        todo!()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        todo!()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PKCS1_SHA1]
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::RawPublicKey]
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[derive(Debug)]
struct FakeServerCrypto {
    server_handshake_secret: OnceLock<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl FakeServerCrypto {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            server_handshake_secret: OnceLock::new(),
            provider,
        }
    }

    fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
        let secret = self
            .server_handshake_secret
            .get()
            .unwrap();

        let cipher_suite = tls13_suite(CipherSuite::TLS13_AES_128_GCM_SHA256, &self.provider);
        let expander = cipher_suite
            .hkdf_provider
            .expander_for_okm(&OkmBlock::new(secret));

        // Derive Encrypter
        let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
        let iv = derive_traffic_iv(expander.as_ref(), cipher_suite.aead_alg.iv_len());
        cipher_suite.aead_alg.encrypter(key, iv)
    }
}

impl KeyLog for FakeServerCrypto {
    fn will_log(&self, _label: &str) -> bool {
        true
    }

    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            self.server_handshake_secret
                .set(secret.to_vec())
                .unwrap();
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder(Arc::new(HYBRID_PROVIDER.clone()))
            .with_root_certificates(roots())
            .with_no_client_auth()
            .unwrap(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::Unknown(0xfe00));
    assert_eq!(key_shares[1].group, NamedGroup::Unknown(0xfe01));
}

#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    let provider = CryptoProvider {
        kx_groups: Cow::Owned(vec![FAKE_HYBRID as _]),
        ..HYBRID_PROVIDER
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder(provider.into())
            .with_root_certificates(roots())
            .with_no_client_auth()
            .unwrap(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::Unknown(0xfe00));
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn = Arc::new(config)
        .connect(ServerName::try_from("localhost").unwrap())
        .build()?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = EncodedMessage::<Payload<'_>>::read(&mut Reader::new(&bytes))
        .unwrap()
        .into_owned();
    match Message::try_from(&message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

const HYBRID_PROVIDER: CryptoProvider = CryptoProvider {
    kx_groups: Cow::Borrowed(&[FAKE_HYBRID, FAKE_KX_GROUP]),
    ..TEST_PROVIDER
};

const FAKE_HYBRID: &FakeHybrid = &FakeHybrid {
    name: NamedGroup::Unknown(0xfe00),
    classical: NamedGroup::Unknown(0xfe01),
};
const FAKE_KX_GROUP: &dyn SupportedKxGroup = &FakeKeyExchangeGroup(NamedGroup::Unknown(0xfe01));

#[derive(Clone, Copy, Debug)]
pub(crate) struct FakeHybrid {
    name: NamedGroup,
    classical: NamedGroup,
}

impl SupportedKxGroup for FakeHybrid {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        Ok(StartedKeyExchange::Hybrid(Box::new(*self)))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

impl kx::HybridKeyExchange for FakeHybrid {
    fn component(&self) -> (NamedGroup, &[u8]) {
        (self.classical, KX_PEER_SHARE)
    }

    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        match peer_pub_key {
            KX_PEER_SHARE => Ok(SharedSecret::from(KX_SHARED_SECRET)),
            _ => Err(Error::from(PeerMisbehaved::InvalidKeyShare)),
        }
    }

    fn as_key_exchange(&self) -> &(dyn kx::ActiveKeyExchange + 'static) {
        FAKE_HYBRID
    }

    fn into_key_exchange(self: Box<Self>) -> Box<dyn kx::ActiveKeyExchange> {
        self
    }
}

impl kx::ActiveKeyExchange for FakeHybrid {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        match peer {
            KX_PEER_SHARE => Ok(SharedSecret::from(KX_SHARED_SECRET)),
            _ => Err(Error::from(PeerMisbehaved::InvalidKeyShare)),
        }
    }

    fn pub_key(&self) -> &[u8] {
        KX_PEER_SHARE
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

const KX_PEER_SHARE: &[u8] = b"KxPeerShareKxPeerShareKxPeerShare";
const KX_SHARED_SECRET: &[u8] = b"KxSharedSecretKxSharedSecret";

fn roots() -> RootCertStore {
    let mut r = RootCertStore::with_capacity(1);
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
