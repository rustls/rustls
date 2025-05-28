use std::prelude::v1::*;
use std::vec;

use super::ServerConnectionData;
use crate::common_state::Context;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::codec::{Codec, LengthPrefixedBuffer, ListLength};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random,
    SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{
    CommonState, Error, HandshakeType, PeerIncompatible, PeerMisbehaved, ProtocolVersion, Side,
};

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

#[test]
fn server_ignores_sni_with_ip_address() {
    let mut ch = minimal_client_hello();
    ch.extensions
        .push(ClientExtension::read_bytes(&sni_extension(&[b"1.1.1.1"])).unwrap());
    std::println!("{:?}", ch.extensions);
    assert_eq!(test_process_client_hello(ch), Ok(()));
}

#[test]
fn server_rejects_sni_with_illegal_dns_name() {
    let mut ch = minimal_client_hello();
    ch.extensions
        .push(ClientExtension::read_bytes(&sni_extension(&[b"ab@cd.com"])).unwrap());
    std::println!("{:?}", ch.extensions);
    assert_eq!(
        test_process_client_hello(ch),
        Err(PeerMisbehaved::ServerNameMustContainOneHostName.into())
    );
}

fn test_process_client_hello(hello: ClientHelloPayload) -> Result<(), Error> {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(hello),
        }),
    };
    super::hs::process_client_hello(
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
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{CertificateDer, PrivateKeyDer};
    use crate::server::{ServerConfig, ServerConnection};
    use crate::sync::Arc;
    use crate::{CipherSuiteCommon, SupportedCipherSuite, Tls12CipherSuite, version};

    #[cfg(feature = "tls12")]
    #[test]
    fn test_server_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let provider = super::provider::default_provider();
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }
        let mut conn = ServerConnection::new(config.into()).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(minimal_client_hello()),
            }),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(Error::PeerIncompatible(
                PeerIncompatible::ExtendedMasterSecretExtensionRequired
            ))
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn server_picks_ffdhe_group_when_clienthello_has_no_ffdhe_group_in_groups_ext() {
        let provider = CryptoProvider {
            kx_groups: vec![FAKE_FFDHE_GROUP],
            cipher_suites: vec![TLS_DHE_RSA_WITH_AES_128_GCM_SHA256],
            ..super::provider::default_provider()
        };
        let config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        let mut conn = ServerConnection::new(config.into()).unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites
            .push(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.suite());
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ch),
            }),
        };
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let KxState::Start(skxg) = &conn.kx_state else {
            panic!("unexpected kx_state");
        };
        assert_eq!(skxg.name(), FAKE_FFDHE_GROUP.name());
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

    static FAKE_FFDHE_GROUP: &'static dyn SupportedKxGroup = &FakeFfdheGroup;

    #[derive(Debug)]
    struct FakeFfdheGroup;

    impl SupportedKxGroup for FakeFfdheGroup {
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

        fn group(&self) -> NamedGroup {
            NamedGroup::FFDHE2048
        }
    }

    static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256);

    static TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite =
        match &super::provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
            SupportedCipherSuite::Tls12(provider) => Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                    ..provider.common
                },
                kx: KeyExchangeAlgorithm::DHE,
                ..**provider
            },
            _ => unreachable!(),
        };
}

fn minimal_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        compression_methods: vec![Compression::Null],
        extensions: vec![
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PSS_SHA256]),
            ClientExtension::NamedGroups(vec![NamedGroup::X25519, NamedGroup::secp256r1]),
        ],
    }
}

fn sni_extension(names: &[&[u8]]) -> Vec<u8> {
    let mut r = Vec::new();
    ExtensionType::ServerName.encode(&mut r);
    let outer = LengthPrefixedBuffer::new(ListLength::U16, &mut r);
    let name_items = LengthPrefixedBuffer::new(ListLength::U16, outer.buf);
    for name in names {
        name_items.buf.push(0);
        let host_name = LengthPrefixedBuffer::new(ListLength::U16, name_items.buf);
        host_name.buf.extend_from_slice(name);
        drop(host_name);
    }
    drop(name_items);
    drop(outer);
    r
}
