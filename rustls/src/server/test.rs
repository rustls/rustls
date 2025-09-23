use std::prelude::v1::*;
use std::vec;

use super::ServerConnectionData;
use super::hs::ClientHelloInput;
use crate::common_state::Context;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, KeyShareEntry,
    Random, SessionId, SupportedProtocolVersions,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{CommonState, Error, PeerIncompatible, ProtocolVersion, Side};

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
            sendable_plaintext: None,
        },
    )
    .map(|_| ())
}

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use super::super::*;
    use crate::common_state::KxState;
    use crate::crypto::{
        ActiveKeyExchange, CryptoProvider, KeyExchangeAlgorithm, SupportedKxGroup,
    };
    use crate::enums::CertificateType;
    use crate::ffdhe_groups::FfdheGroup;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{CertificateDer, PrivateKeyDer};
    use crate::server::{AlwaysResolvesServerRawPublicKeys, ServerConfig};
    use crate::sign::CertifiedKey;
    use crate::sync::Arc;
    use crate::{CipherSuiteCommon, ConnectionCommon, Tls12CipherSuite};

    #[test]
    fn test_server_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let provider = super::provider::default_provider().with_only_tls12();
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }
        let mut conn = ConnectionCommon::<ServerConnectionData>::new(config.into()).unwrap();

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

    #[test]
    fn server_picks_ffdhe_group_when_clienthello_has_no_ffdhe_group_in_groups_ext() {
        let config = ServerConfig::builder_with_provider(
            ffdhe_provider()
                .with_only_tls12()
                .into(),
        )
        .with_no_client_auth()
        .with_single_cert(server_cert(), server_key())
        .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites.push(
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                .common
                .suite,
        );

        server_chooses_ffdhe_group_for_client_hello(
            ConnectionCommon::<ServerConnectionData>::new(config.into()).unwrap(),
            ch,
        );
    }

    #[test]
    fn server_picks_ffdhe_group_when_clienthello_has_no_groups_ext() {
        let config = ServerConfig::builder_with_provider(
            ffdhe_provider()
                .with_only_tls12()
                .into(),
        )
        .with_no_client_auth()
        .with_single_cert(server_cert(), server_key())
        .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites.push(
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                .common
                .suite,
        );
        ch.extensions.named_groups.take();

        server_chooses_ffdhe_group_for_client_hello(
            ConnectionCommon::<ServerConnectionData>::new(config.into()).unwrap(),
            ch,
        );
    }

    #[test]
    fn server_accepts_client_with_no_ecpoints_extension_and_only_ffdhe_cipher_suites() {
        let config = ServerConfig::builder_with_provider(
            ffdhe_provider()
                .with_only_tls12()
                .into(),
        )
        .with_no_client_auth()
        .with_single_cert(server_cert(), server_key())
        .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites.push(
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                .common
                .suite,
        );
        ch.extensions.ec_point_formats.take();

        server_chooses_ffdhe_group_for_client_hello(
            ConnectionCommon::<ServerConnectionData>::new(config.into()).unwrap(),
            ch,
        );
    }

    fn server_chooses_ffdhe_group_for_client_hello(
        mut conn: ConnectionCommon<ServerConnectionData>,
        client_hello: ClientHelloPayload,
    ) {
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(client_hello),
            )),
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
        let mut ch = minimal_client_hello();
        ch.extensions.client_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn =
            ConnectionCommon::<ServerConnectionData>::new(server_config_for_rpk().into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }

    #[test]
    fn test_rpk_only_server_rejects_x509_only_client() {
        let mut ch = minimal_client_hello();
        ch.extensions.server_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn =
            ConnectionCommon::<ServerConnectionData>::new(server_config_for_rpk().into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }

    fn server_config_for_rpk() -> ServerConfig {
        let x25519_provider = CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        };
        ServerConfig::builder_with_provider(x25519_provider.with_only_tls12().into())
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
                server_certified_key(),
            ))))
            .unwrap()
    }

    fn server_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(server_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new_unchecked(public_key_as_cert, key)
    }

    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
        )
        .unwrap()
    }

    fn server_cert() -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/inter.der")[..]),
        ]
    }

    fn ffdhe_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![FAKE_FFDHE_GROUP],
            tls12_cipher_suites: vec![&TLS_DHE_RSA_WITH_AES_128_GCM_SHA256],
            ..super::provider::default_provider()
        }
    }

    static FAKE_FFDHE_GROUP: &'static dyn SupportedKxGroup = &FakeFfdheGroup;

    #[derive(Debug)]
    struct FakeFfdheGroup;

    impl SupportedKxGroup for FakeFfdheGroup {
        fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
            Some(crate::ffdhe_groups::FFDHE2048)
        }

        fn name(&self) -> NamedGroup {
            NamedGroup::FFDHE2048
        }

        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
            Ok(Box::new(ActiveFakeFfdhe))
        }
    }

    #[derive(Debug)]
    struct ActiveFakeFfdhe;

    impl ActiveKeyExchange for ActiveFakeFfdhe {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn complete(
            self: Box<Self>,
            _peer_pub_key: &[u8],
        ) -> Result<crate::crypto::SharedSecret, Error> {
            todo!()
        }

        fn pub_key(&self) -> &[u8] {
            b"ActiveFakeFfdhe pub key"
        }

        fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
            Some(crate::ffdhe_groups::FFDHE2048)
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::FFDHE2048
        }
    }

    static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            ..super::provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.common
        },
        kx: KeyExchangeAlgorithm::DHE,
        ..*super::provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    };
}

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
