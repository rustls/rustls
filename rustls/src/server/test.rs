#![cfg(feature = "aws-lc-rs")]

use alloc::borrow::Cow;
use alloc::boxed::Box;
use std::vec;

use super::ServerConnectionData;
use super::hs::ClientHelloInput;
use crate::common_state::{CommonState, Context, KxState, Side};
use crate::crypto::cipher::FakeAead;
use crate::crypto::hash::FakeHash;
use crate::crypto::tls12::FakePrf;
use crate::crypto::{
    ActiveKeyExchange, Credentials, CryptoProvider, Identity, KeyExchangeAlgorithm, SharedSecret,
    SingleCredential, StartedKeyExchange, SupportedKxGroup, tls12_only,
};
use crate::enums::{CertificateType, CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerIncompatible};
use crate::ffdhe_groups::FfdheGroup;
use crate::msgs::base::PayloadU16;
use crate::msgs::deframer::buffers::Locator;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, KeyShareEntry,
    Random, SessionId, SupportedProtocolVersions,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::pki_types::pem::PemObject;
use crate::pki_types::{CertificateDer, PrivateKeyDer};
use crate::server::{ServerConfig, ServerConnection};
use crate::suites::CipherSuiteCommon;
use crate::sync::Arc;
use crate::tls12::Tls12CipherSuite;
use crate::version::TLS12_VERSION;
use crate::{TEST_PROVIDERS, ffdhe_groups};

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

    ClientHelloInput::from_message(
        &m,
        false,
        &mut Context {
            common: &mut CommonState::new(Side::Server),
            data: &mut ServerConnectionData::default(),
            plaintext_locator: &Locator::new(&[]),
            received_plaintext: &mut None,
            sendable_plaintext: None,
        },
    )
    .map(|_| ())
}

#[test]
fn test_server_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
    for &provider in TEST_PROVIDERS {
        let provider = tls12_only(provider.clone());
        let mut config = ServerConfig::builder(provider.into())
            .with_no_client_auth()
            .with_single_cert(server_identity(), server_key())
            .unwrap();

        if config.provider.fips() {
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
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
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
}

#[test]
fn server_picks_ffdhe_group_when_clienthello_has_no_ffdhe_group_in_groups_ext() {
    for &provider in TEST_PROVIDERS {
        let config = ServerConfig::builder(Arc::new(CryptoProvider {
            tls13_cipher_suites: Cow::default(),
            ..ffdhe_provider(provider.clone())
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

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }
}

#[test]
fn server_picks_ffdhe_group_when_clienthello_has_no_groups_ext() {
    for &provider in TEST_PROVIDERS {
        let config = ServerConfig::builder(Arc::new(CryptoProvider {
            tls13_cipher_suites: Cow::default(),
            ..ffdhe_provider(provider.clone())
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

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }
}

#[test]
fn server_accepts_client_with_no_ecpoints_extension_and_only_ffdhe_cipher_suites() {
    for &provider in TEST_PROVIDERS {
        let config = ServerConfig::builder(Arc::new(CryptoProvider {
            tls13_cipher_suites: Cow::default(),
            ..ffdhe_provider(provider.clone())
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

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }
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

    let KxState::Start(skxg) = &conn.kx_state else {
        panic!("unexpected kx_state");
    };
    assert_eq!(skxg.name(), FAKE_FFDHE_GROUP.name());
}

#[test]
fn test_server_requiring_rpk_client_rejects_x509_client() {
    for &provider in TEST_PROVIDERS {
        let Some(server_config) = server_config_for_rpk(provider.clone()) else {
            continue;
        };

        let mut ch = minimal_client_hello();
        ch.extensions.client_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn = ServerConnection::new(Arc::new(server_config)).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }
}

#[test]
fn test_rpk_only_server_rejects_x509_only_client() {
    for &provider in TEST_PROVIDERS {
        let Some(server_config) = server_config_for_rpk(provider.clone()) else {
            continue;
        };

        let mut ch = minimal_client_hello();
        ch.extensions.server_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn = ServerConnection::new(Arc::new(server_config)).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }
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
        &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
    )
    .unwrap()
}

fn server_identity() -> Arc<Identity<'static>> {
    Arc::new(
        Identity::from_cert_chain(vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/inter.der")[..]),
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
        Some(ffdhe_groups::FFDHE2048)
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
        Some(ffdhe_groups::FFDHE2048)
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::FFDHE2048
    }
}

static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &FakeHash,
        confidentiality_limit: 1,
    },
    kx: KeyExchangeAlgorithm::DHE,
    protocol_version: TLS12_VERSION,
    prf_provider: &FakePrf,
    sign: &[SignatureScheme::RSA_PKCS1_SHA256],
    aead_alg: &FakeAead,
};

fn minimal_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions {
            signature_schemes: Some(vec![SignatureScheme::RSA_PSS_SHA256]),
            named_groups: Some(vec![NamedGroup::X25519, NamedGroup::secp256r1]),
            supported_versions: Some(SupportedProtocolVersions {
                tls12: true,
                tls13: true,
            }),
            key_shares: Some(vec![KeyShareEntry {
                group: NamedGroup::X25519,
                payload: PayloadU16::new(vec![0xab; 32]),
            }]),
            extended_master_secret_request: Some(()),
            ..ClientExtensions::default()
        }),
    }
}
