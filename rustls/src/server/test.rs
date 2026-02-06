use alloc::borrow::Cow;
use alloc::boxed::Box;
use std::vec;

use pki_types::UnixTime;

use super::hs::ClientHelloInput;
use super::{
    CommonServerSessionValue, ServerConfig, ServerConnection, ServerSessionValue,
    Tls13ServerSessionValue,
};
use crate::common_state::Input;
use crate::crypto::cipher::FakeAead;
use crate::crypto::kx::ffdhe::{FFDHE2048, FfdheGroup};
use crate::crypto::kx::{
    ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup, SharedSecret, StartedKeyExchange,
    SupportedKxGroup,
};
use crate::crypto::test_provider::{FAKE_HASH, FAKE_HMAC};
use crate::crypto::{
    CertificateIdentity, CipherSuite, Credentials, CryptoProvider, Identity, SignatureScheme,
    SingleCredential, TEST_PROVIDER, tls12, tls12_only,
};
use crate::enums::{CertificateType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible};
use crate::msgs::{
    ClientExtensions, ClientHelloPayload, Codec, Compression, HEADER_SIZE, HandshakeMessagePayload,
    HandshakePayload, KeyShareEntry, Message, MessagePayload, Random, Reader, SessionId,
    SizedPayload, SupportedProtocolVersions,
};
use crate::pki_types::pem::PemObject;
use crate::pki_types::{CertificateDer, FipsStatus, PrivateKeyDer};
use crate::suites::CipherSuiteCommon;
use crate::sync::Arc;
use crate::tls12::Tls12CipherSuite;
use crate::version::TLS12_VERSION;

#[test]
fn serversessionvalue_is_debug() {
    use std::{println, vec};
    let ssv = ServerSessionValue::Tls13(Tls13ServerSessionValue::new(
        CommonServerSessionValue::new(
            None,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            None,
            None,
            vec![4, 5, 6],
            UnixTime::now(),
        ),
        &[1, 2, 3],
        0x12345678,
    ));
    println!("{ssv:?}");
    println!("{:#04x?}", ssv.get_encoding());
}

#[test]
fn serversessionvalue_no_sni() {
    let bytes = [
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x69, 0x7a, 0x4a, 0xdf, 0x00, 0x13, 0x01, 0x00, 0x00,
        0x00, 0x03, 0x04, 0x05, 0x06, 0x03, 0x01, 0x02, 0x03, 0x12, 0x34, 0x56, 0x78,
    ];
    let mut rd = Reader::new(&bytes);
    let ssv = ServerSessionValue::read(&mut rd).unwrap();
    assert_eq!(ssv.get_encoding(), bytes);
}

#[test]
fn serversessionvalue_with_cert() {
    std::eprintln!(
        "{:#04x?}",
        ServerSessionValue::Tls13(Tls13ServerSessionValue::new(
            CommonServerSessionValue::new(
                None,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                Some(Identity::X509(CertificateIdentity {
                    end_entity: CertificateDer::from(&[10, 11, 12][..]),
                    intermediates: alloc::vec![],
                })),
                None,
                alloc::vec![4, 5, 6],
                UnixTime::now(),
            ),
            &[1, 2, 3],
            0x12345678,
        ))
        .get_encoding()
    );

    let bytes = [
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x69, 0x7a, 0x4b, 0x06, 0x00, 0x13, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06,
        0x03, 0x01, 0x02, 0x03, 0x12, 0x34, 0x56, 0x78,
    ];
    let mut rd = Reader::new(&bytes);
    let ssv = ServerSessionValue::read(&mut rd).unwrap();
    assert_eq!(ssv.get_encoding(), bytes);
}

#[test]
fn null_compression_required() {
    assert_eq!(
        test_process_client_hello(ClientHelloPayload {
            compression_methods: vec![],
            ..minimal_client_hello()
        }),
        Err(PeerIncompatible::NullCompressionRequired.into()),
    );
}

fn test_process_client_hello(hello: ClientHelloPayload) -> Result<(), Error> {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            hello,
        ))),
    };

    ClientHelloInput::from_input(&Input {
        message: m,
        aligned_handshake: None,
    })
    .map(|_| ())
}

#[test]
fn test_server_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
    let provider = tls12_only(TEST_PROVIDER.clone());
    let mut config = ServerConfig::builder(provider.into())
        .with_no_client_auth()
        .with_single_cert(server_identity(), server_key())
        .unwrap();

    if !matches!(config.provider.fips(), FipsStatus::Unvalidated) {
        assert!(config.require_ems);
    } else {
        config.require_ems = true;
    }
    let mut conn = ServerConnection::new(config.into()).unwrap();

    let mut ch = minimal_client_hello();
    ch.extensions
        .extended_master_secret_request
        .take();
    let ch = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ch,
        ))),
    };
    conn.read_tls(&mut ch.into_wire_bytes().as_slice())
        .unwrap();

    assert_eq!(
        conn.process_new_packets(),
        Err(Error::PeerIncompatible(
            PeerIncompatible::ExtendedMasterSecretExtensionRequired
        ))
    );
}

#[test]
fn server_picks_ffdhe_group_when_clienthello_has_no_ffdhe_group_in_groups_ext() {
    let config = ServerConfig::builder(Arc::new(CryptoProvider {
        tls13_cipher_suites: Cow::default(),
        ..ffdhe_provider(TEST_PROVIDER.clone())
    }))
    .with_no_client_auth()
    .with_single_cert(server_identity(), server_key())
    .unwrap();

    let mut ch = minimal_client_hello();
    ch.cipher_suites.push(
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .suite,
    );

    server_chooses_ffdhe_group_for_client_hello(ServerConnection::new(config.into()).unwrap(), ch);
}

#[test]
fn server_picks_ffdhe_group_when_clienthello_has_no_groups_ext() {
    let config = ServerConfig::builder(Arc::new(CryptoProvider {
        tls13_cipher_suites: Cow::default(),
        ..ffdhe_provider(TEST_PROVIDER.clone())
    }))
    .with_no_client_auth()
    .with_single_cert(server_identity(), server_key())
    .unwrap();

    let mut ch = minimal_client_hello();
    ch.cipher_suites.push(
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .suite,
    );
    ch.extensions.named_groups.take();

    server_chooses_ffdhe_group_for_client_hello(ServerConnection::new(config.into()).unwrap(), ch);
}

#[test]
fn server_accepts_client_with_no_ecpoints_extension_and_only_ffdhe_cipher_suites() {
    let config = ServerConfig::builder(Arc::new(CryptoProvider {
        tls13_cipher_suites: Cow::default(),
        ..ffdhe_provider(TEST_PROVIDER.clone())
    }))
    .with_no_client_auth()
    .with_single_cert(server_identity(), server_key())
    .unwrap();

    let mut ch = minimal_client_hello();
    ch.cipher_suites.push(
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            .common
            .suite,
    );
    ch.extensions.ec_point_formats.take();

    server_chooses_ffdhe_group_for_client_hello(ServerConnection::new(config.into()).unwrap(), ch);
}

fn server_chooses_ffdhe_group_for_client_hello(
    mut conn: ServerConnection,
    client_hello: ClientHelloPayload,
) {
    let ch = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            client_hello,
        ))),
    };
    conn.read_tls(&mut ch.into_wire_bytes().as_slice())
        .unwrap();
    conn.process_new_packets().unwrap();

    let mut flight = vec![];
    conn.write_tls(&mut &mut flight)
        .unwrap();

    let mut r = Reader::new(&flight[HEADER_SIZE..]);
    assert!(matches!(
        HandshakeMessagePayload::read(&mut r).unwrap(),
        HandshakeMessagePayload(HandshakePayload::ServerHello(_))
    ));
    assert!(matches!(
        HandshakeMessagePayload::read(&mut r).unwrap(),
        HandshakeMessagePayload(HandshakePayload::Certificate(_))
    ));

    let HandshakeMessagePayload(HandshakePayload::ServerKeyExchange(skx)) =
        HandshakeMessagePayload::read(&mut r).unwrap()
    else {
        panic!("unexpected third message");
    };

    skx.unwrap_given_kxa(KeyExchangeAlgorithm::DHE)
        .expect("DHE not used");
}

#[test]
fn test_server_requiring_rpk_client_rejects_x509_client() {
    let Some(server_config) = server_config_for_rpk(TEST_PROVIDER.clone()) else {
        return;
    };

    let mut ch = minimal_client_hello();
    ch.extensions.client_certificate_types = Some(vec![CertificateType::X509]);
    let ch = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ch,
        ))),
    };

    let mut conn = ServerConnection::new(Arc::new(server_config)).unwrap();
    conn.read_tls(&mut ch.into_wire_bytes().as_slice())
        .unwrap();
    assert_eq!(
        conn.process_new_packets().unwrap_err(),
        PeerIncompatible::IncorrectCertificateTypeExtension.into(),
    );
}

#[test]
fn test_rpk_only_server_rejects_x509_only_client() {
    let Some(server_config) = server_config_for_rpk(TEST_PROVIDER.clone()) else {
        return;
    };

    let mut ch = minimal_client_hello();
    ch.extensions.server_certificate_types = Some(vec![CertificateType::X509]);
    let ch = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ch,
        ))),
    };

    let mut conn = ServerConnection::new(Arc::new(server_config)).unwrap();
    conn.read_tls(&mut ch.into_wire_bytes().as_slice())
        .unwrap();

    assert_eq!(
        conn.process_new_packets().unwrap_err(),
        PeerIncompatible::IncorrectCertificateTypeExtension.into(),
    );
}

fn server_config_for_rpk(provider: CryptoProvider) -> Option<ServerConfig> {
    let provider = CryptoProvider {
        kx_groups: Cow::Owned(vec![
            provider.find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_2)?,
        ]),
        ..provider
    };

    let credentials = SingleCredential::from(server_credentials(&provider));
    Some(
        ServerConfig::builder(Arc::new(provider))
            .with_no_client_auth()
            .with_server_credential_resolver(Arc::new(credentials))
            .unwrap(),
    )
}

fn server_credentials(provider: &CryptoProvider) -> Credentials {
    let key = provider
        .key_provider
        .load_private_key(server_key())
        .unwrap();
    let identity = Arc::from(Identity::RawPublicKey(
        key.public_key().unwrap().into_owned(),
    ));
    Credentials::new_unchecked(identity, key)
}

fn server_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_reader(
        &mut include_bytes!("../../../test-ca/ecdsa-p256/end.key").as_slice(),
    )
    .unwrap()
}

fn server_identity() -> Arc<Identity<'static>> {
    Arc::new(
        Identity::from_cert_chain(vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/inter.der")[..]),
        ])
        .unwrap(),
    )
}

fn ffdhe_provider(provider: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        kx_groups: Cow::Owned(vec![FAKE_FFDHE_GROUP]),
        tls12_cipher_suites: Cow::Owned(vec![&TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]),
        ..provider
    }
}

static FAKE_FFDHE_GROUP: &'static dyn SupportedKxGroup = &FakeFfdheGroup;

#[derive(Debug)]
struct FakeFfdheGroup;

impl SupportedKxGroup for FakeFfdheGroup {
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(FFDHE2048)
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::FFDHE2048
    }

    fn start(&self) -> Result<StartedKeyExchange, Error> {
        Ok(StartedKeyExchange::Single(Box::new(ActiveFakeFfdhe)))
    }
}

#[derive(Debug)]
struct ActiveFakeFfdhe;

impl ActiveKeyExchange for ActiveFakeFfdhe {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        todo!()
    }

    fn pub_key(&self) -> &[u8] {
        b"ActiveFakeFfdhe pub key"
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(FFDHE2048)
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::FFDHE2048
    }
}

static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: FAKE_HASH,
        confidentiality_limit: 1,
    },
    kx: KeyExchangeAlgorithm::DHE,
    protocol_version: TLS12_VERSION,
    prf_provider: &tls12::PrfUsingHmac(FAKE_HMAC),
    sign: &[SignatureScheme::ECDSA_NISTP256_SHA256],
    aead_alg: &FakeAead,
};

fn minimal_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::Unknown(0xff13), CipherSuite::Unknown(0xff12)],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions {
            signature_schemes: Some(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            named_groups: Some(vec![NamedGroup::from(0xfe00)]),
            supported_versions: Some(SupportedProtocolVersions {
                tls12: true,
                tls13: true,
            }),
            key_shares: Some(vec![KeyShareEntry {
                group: NamedGroup::from(0xfe00),
                payload: SizedPayload::from(vec![0xab; 32]),
            }]),
            extended_master_secret_request: Some(()),
            ..ClientExtensions::default()
        }),
    }
}
