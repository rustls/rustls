#![allow(dead_code)]
#![allow(clippy::duplicate_mod)]

use std::io;
use std::ops::DerefMut;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use rustls::crypto::CryptoProvider;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, Connection, ConnectionCommon, ContentType,
    DigitallySignedStruct, Error, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    SideData, SignatureScheme, SupportedCipherSuite,
};
use webpki::anchor_from_trusted_cert;

use super::provider;

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }
    }
}

embed_files! {
    (ECDSA_P256_CA_CERT, "ecdsa-p256", "ca.cert");
    (ECDSA_P256_CA_DER, "ecdsa-p256", "ca.der");
    (ECDSA_P256_CA_KEY, "ecdsa-p256", "ca.key");
    (ECDSA_P256_CLIENT_CERT, "ecdsa-p256", "client.cert");
    (ECDSA_P256_CLIENT_CHAIN, "ecdsa-p256", "client.chain");
    (ECDSA_P256_CLIENT_FULLCHAIN, "ecdsa-p256", "client.fullchain");
    (ECDSA_P256_CLIENT_KEY, "ecdsa-p256", "client.key");
    (ECDSA_P256_END_CRL_PEM, "ecdsa-p256", "end.revoked.crl.pem");
    (ECDSA_P256_CLIENT_CRL_PEM, "ecdsa-p256", "client.revoked.crl.pem");
    (ECDSA_P256_INTERMEDIATE_CRL_PEM, "ecdsa-p256", "inter.revoked.crl.pem");
    (ECDSA_P256_EXPIRED_CRL_PEM, "ecdsa-p256", "end.expired.crl.pem");
    (ECDSA_P256_END_CERT, "ecdsa-p256", "end.cert");
    (ECDSA_P256_END_CHAIN, "ecdsa-p256", "end.chain");
    (ECDSA_P256_END_FULLCHAIN, "ecdsa-p256", "end.fullchain");
    (ECDSA_P256_END_KEY, "ecdsa-p256", "end.key");
    (ECDSA_P256_INTER_CERT, "ecdsa-p256", "inter.cert");
    (ECDSA_P256_INTER_KEY, "ecdsa-p256", "inter.key");

    (ECDSA_P384_CA_CERT, "ecdsa-p384", "ca.cert");
    (ECDSA_P384_CA_DER, "ecdsa-p384", "ca.der");
    (ECDSA_P384_CA_KEY, "ecdsa-p384", "ca.key");
    (ECDSA_P384_CLIENT_CERT, "ecdsa-p384", "client.cert");
    (ECDSA_P384_CLIENT_CHAIN, "ecdsa-p384", "client.chain");
    (ECDSA_P384_CLIENT_FULLCHAIN, "ecdsa-p384", "client.fullchain");
    (ECDSA_P384_CLIENT_KEY, "ecdsa-p384", "client.key");
    (ECDSA_P384_END_CRL_PEM, "ecdsa-p384", "end.revoked.crl.pem");
    (ECDSA_P384_CLIENT_CRL_PEM, "ecdsa-p384", "client.revoked.crl.pem");
    (ECDSA_P384_INTERMEDIATE_CRL_PEM, "ecdsa-p384", "inter.revoked.crl.pem");
    (ECDSA_P384_EXPIRED_CRL_PEM, "ecdsa-p384", "end.expired.crl.pem");
    (ECDSA_P384_END_CERT, "ecdsa-p384", "end.cert");
    (ECDSA_P384_END_CHAIN, "ecdsa-p384", "end.chain");
    (ECDSA_P384_END_FULLCHAIN, "ecdsa-p384", "end.fullchain");
    (ECDSA_P384_END_KEY, "ecdsa-p384", "end.key");
    (ECDSA_P384_INTER_CERT, "ecdsa-p384", "inter.cert");
    (ECDSA_P384_INTER_KEY, "ecdsa-p384", "inter.key");

    (ECDSA_P521_CA_CERT, "ecdsa-p521", "ca.cert");
    (ECDSA_P521_CA_DER, "ecdsa-p521", "ca.der");
    (ECDSA_P521_CA_KEY, "ecdsa-p521", "ca.key");
    (ECDSA_P521_CLIENT_CERT, "ecdsa-p521", "client.cert");
    (ECDSA_P521_CLIENT_CHAIN, "ecdsa-p521", "client.chain");
    (ECDSA_P521_CLIENT_FULLCHAIN, "ecdsa-p521", "client.fullchain");
    (ECDSA_P521_CLIENT_KEY, "ecdsa-p521", "client.key");
    (ECDSA_P521_END_CRL_PEM, "ecdsa-p521", "end.revoked.crl.pem");
    (ECDSA_P521_CLIENT_CRL_PEM, "ecdsa-p521", "client.revoked.crl.pem");
    (ECDSA_P521_INTERMEDIATE_CRL_PEM, "ecdsa-p521", "inter.revoked.crl.pem");
    (ECDSA_P521_EXPIRED_CRL_PEM, "ecdsa-p521", "end.expired.crl.pem");
    (ECDSA_P521_END_CERT, "ecdsa-p521", "end.cert");
    (ECDSA_P521_END_CHAIN, "ecdsa-p521", "end.chain");
    (ECDSA_P521_END_FULLCHAIN, "ecdsa-p521", "end.fullchain");
    (ECDSA_P521_END_KEY, "ecdsa-p521", "end.key");
    (ECDSA_P521_INTER_CERT, "ecdsa-p521", "inter.cert");
    (ECDSA_P521_INTER_KEY, "ecdsa-p521", "inter.key");

    (EDDSA_CA_CERT, "eddsa", "ca.cert");
    (EDDSA_CA_DER, "eddsa", "ca.der");
    (EDDSA_CA_KEY, "eddsa", "ca.key");
    (EDDSA_CLIENT_CERT, "eddsa", "client.cert");
    (EDDSA_CLIENT_CHAIN, "eddsa", "client.chain");
    (EDDSA_CLIENT_FULLCHAIN, "eddsa", "client.fullchain");
    (EDDSA_CLIENT_KEY, "eddsa", "client.key");
    (EDDSA_END_CRL_PEM, "eddsa", "end.revoked.crl.pem");
    (EDDSA_CLIENT_CRL_PEM, "eddsa", "client.revoked.crl.pem");
    (EDDSA_INTERMEDIATE_CRL_PEM, "eddsa", "inter.revoked.crl.pem");
    (EDDSA_EXPIRED_CRL_PEM, "eddsa", "end.expired.crl.pem");
    (EDDSA_END_CERT, "eddsa", "end.cert");
    (EDDSA_END_CHAIN, "eddsa", "end.chain");
    (EDDSA_END_FULLCHAIN, "eddsa", "end.fullchain");
    (EDDSA_END_KEY, "eddsa", "end.key");
    (EDDSA_INTER_CERT, "eddsa", "inter.cert");
    (EDDSA_INTER_KEY, "eddsa", "inter.key");

    (RSA_2048_CA_CERT, "rsa-2048", "ca.cert");
    (RSA_2048_CA_DER, "rsa-2048", "ca.der");
    (RSA_2048_CA_KEY, "rsa-2048", "ca.key");
    (RSA_2048_CLIENT_CERT, "rsa-2048", "client.cert");
    (RSA_2048_CLIENT_CHAIN, "rsa-2048", "client.chain");
    (RSA_2048_CLIENT_FULLCHAIN, "rsa-2048", "client.fullchain");
    (RSA_2048_CLIENT_KEY, "rsa-2048", "client.key");
    (RSA_2048_END_CRL_PEM, "rsa-2048", "end.revoked.crl.pem");
    (RSA_2048_CLIENT_CRL_PEM, "rsa-2048", "client.revoked.crl.pem");
    (RSA_2048_INTERMEDIATE_CRL_PEM, "rsa-2048", "inter.revoked.crl.pem");
    (RSA_2048_EXPIRED_CRL_PEM, "rsa-2048", "end.expired.crl.pem");
    (RSA_2048_END_CERT, "rsa-2048", "end.cert");
    (RSA_2048_END_CHAIN, "rsa-2048", "end.chain");
    (RSA_2048_END_FULLCHAIN, "rsa-2048", "end.fullchain");
    (RSA_2048_END_KEY, "rsa-2048", "end.key");
    (RSA_2048_INTER_CERT, "rsa-2048", "inter.cert");
    (RSA_2048_INTER_KEY, "rsa-2048", "inter.key");

    (RSA_3072_CA_CERT, "rsa-3072", "ca.cert");
    (RSA_3072_CA_DER, "rsa-3072", "ca.der");
    (RSA_3072_CA_KEY, "rsa-3072", "ca.key");
    (RSA_3072_CLIENT_CERT, "rsa-3072", "client.cert");
    (RSA_3072_CLIENT_CHAIN, "rsa-3072", "client.chain");
    (RSA_3072_CLIENT_FULLCHAIN, "rsa-3072", "client.fullchain");
    (RSA_3072_CLIENT_KEY, "rsa-3072", "client.key");
    (RSA_3072_END_CRL_PEM, "rsa-3072", "end.revoked.crl.pem");
    (RSA_3072_CLIENT_CRL_PEM, "rsa-3072", "client.revoked.crl.pem");
    (RSA_3072_INTERMEDIATE_CRL_PEM, "rsa-3072", "inter.revoked.crl.pem");
    (RSA_3072_EXPIRED_CRL_PEM, "rsa-3072", "end.expired.crl.pem");
    (RSA_3072_END_CERT, "rsa-3072", "end.cert");
    (RSA_3072_END_CHAIN, "rsa-3072", "end.chain");
    (RSA_3072_END_FULLCHAIN, "rsa-3072", "end.fullchain");
    (RSA_3072_END_KEY, "rsa-3072", "end.key");
    (RSA_3072_INTER_CERT, "rsa-3072", "inter.cert");
    (RSA_3072_INTER_KEY, "rsa-3072", "inter.key");

    (RSA_4096_CA_CERT, "rsa-4096", "ca.cert");
    (RSA_4096_CA_DER, "rsa-4096", "ca.der");
    (RSA_4096_CA_KEY, "rsa-4096", "ca.key");
    (RSA_4096_CLIENT_CERT, "rsa-4096", "client.cert");
    (RSA_4096_CLIENT_CHAIN, "rsa-4096", "client.chain");
    (RSA_4096_CLIENT_FULLCHAIN, "rsa-4096", "client.fullchain");
    (RSA_4096_CLIENT_KEY, "rsa-4096", "client.key");
    (RSA_4096_END_CRL_PEM, "rsa-4096", "end.revoked.crl.pem");
    (RSA_4096_CLIENT_CRL_PEM, "rsa-4096", "client.revoked.crl.pem");
    (RSA_4096_INTERMEDIATE_CRL_PEM, "rsa-4096", "inter.revoked.crl.pem");
    (RSA_4096_EXPIRED_CRL_PEM, "rsa-4096", "end.expired.crl.pem");
    (RSA_4096_END_CERT, "rsa-4096", "end.cert");
    (RSA_4096_END_CHAIN, "rsa-4096", "end.chain");
    (RSA_4096_END_FULLCHAIN, "rsa-4096", "end.fullchain");
    (RSA_4096_END_KEY, "rsa-4096", "end.key");
    (RSA_4096_INTER_CERT, "rsa-4096", "inter.cert");
    (RSA_4096_INTER_KEY, "rsa-4096", "inter.key");
}

pub fn transfer(
    left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    right: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
) -> usize {
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}

pub fn transfer_eof(conn: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>) {
    let empty_buf = [0u8; 0];
    let empty_cursor: &mut dyn io::Read = &mut &empty_buf[..];
    let sz = conn.read_tls(empty_cursor).unwrap();
    assert_eq!(sz, 0);
}

pub enum Altered {
    /// message has been edited in-place (or is unchanged)
    InPlace,
    /// send these raw bytes instead of the message.
    Raw(Vec<u8>),
}

pub fn transfer_altered<F>(left: &mut Connection, filter: F, right: &mut Connection) -> usize
where
    F: Fn(&mut Message) -> Altered,
{
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut reader = Reader::init(&buf[..sz]);
        while reader.any_left() {
            let message = OutboundOpaqueMessage::read(&mut reader).unwrap();

            // this is a bit of a falsehood: we don't know whether message
            // is encrypted.  it is quite unlikely that a genuine encrypted
            // message can be decoded by `Message::try_from`.
            let plain = message.into_plain_message();

            let message_enc = match Message::try_from(plain.clone()) {
                Ok(mut message) => match filter(&mut message) {
                    Altered::InPlace => PlainMessage::from(message)
                        .into_unencrypted_opaque()
                        .encode(),
                    Altered::Raw(data) => data,
                },
                // pass through encrypted/undecodable messages
                Err(_) => plain.into_unencrypted_opaque().encode(),
            };

            let message_enc_reader: &mut dyn io::Read = &mut &message_enc[..];
            let len = right
                .read_tls(message_enc_reader)
                .unwrap();
            assert_eq!(len, message_enc.len());
        }
    }

    total
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

pub static ALL_KEY_TYPES: &[KeyType] = &[
    KeyType::Rsa2048,
    KeyType::Rsa3072,
    KeyType::Rsa4096,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    KeyType::EcdsaP521,
    KeyType::Ed25519,
];

impl KeyType {
    fn bytes_for(&self, part: &str) -> &'static [u8] {
        match self {
            Self::Rsa2048 => bytes_for("rsa-2048", part),
            Self::Rsa3072 => bytes_for("rsa-3072", part),
            Self::Rsa4096 => bytes_for("rsa-4096", part),
            Self::EcdsaP256 => bytes_for("ecdsa-p256", part),
            Self::EcdsaP384 => bytes_for("ecdsa-p384", part),
            Self::EcdsaP521 => bytes_for("ecdsa-p521", part),
            Self::Ed25519 => bytes_for("eddsa", part),
        }
    }

    pub fn get_chain(&self) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("end.fullchain")))
            .map(|result| result.unwrap())
            .collect()
    }

    pub fn get_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("end.key")))
                .next()
                .unwrap()
                .unwrap(),
        )
    }

    pub fn get_client_chain(&self) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("client.fullchain")))
            .map(|result| result.unwrap())
            .collect()
    }

    pub fn end_entity_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("end", "revoked")
    }

    pub fn client_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("client", "revoked")
    }

    pub fn intermediate_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("inter", "revoked")
    }

    pub fn end_entity_crl_expired(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("end", "expired")
    }

    pub fn get_client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                self.bytes_for("client.key"),
            ))
            .next()
            .unwrap()
            .unwrap(),
        )
    }

    fn get_crl(&self, role: &str, r#type: &str) -> CertificateRevocationListDer<'static> {
        rustls_pemfile::crls(&mut io::BufReader::new(
            self.bytes_for(&format!("{role}.{type}.crl.pem")),
        ))
        .map(|result| result.unwrap())
        .next() // We only expect one CRL.
        .unwrap()
    }

    pub fn ca_distinguished_name(&self) -> &'static [u8] {
        match self {
            KeyType::Rsa2048 => {
                &b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 2048 CA"[..]
            }
            KeyType::Rsa3072 => {
                &b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 3072 CA"[..]
            }
            KeyType::Rsa4096 => {
                &b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 4096 CA"[..]
            }
            KeyType::EcdsaP256 => {
                &b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p256 CA"[..]
            }
            KeyType::EcdsaP384 => {
                &b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p384 CA"[..]
            }
            KeyType::EcdsaP521 => {
                &b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p521 CA"[..]
            }
            KeyType::Ed25519 => &b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown EdDSA CA"[..],
        }
    }
}

pub fn server_config_builder() -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    // ensure `ServerConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(provider::provider().into())`.
    if exactly_one_provider() {
        rustls::ServerConfig::builder()
    } else {
        rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn server_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    if exactly_one_provider() {
        rustls::ServerConfig::builder_with_protocol_versions(versions)
    } else {
        rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
            .with_protocol_versions(versions)
            .unwrap()
    }
}

pub fn client_config_builder() -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    // ensure `ClientConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(provider::provider().into())`.
    if exactly_one_provider() {
        rustls::ClientConfig::builder()
    } else {
        rustls::ClientConfig::builder_with_provider(provider::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn client_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    if exactly_one_provider() {
        rustls::ClientConfig::builder_with_protocol_versions(versions)
    } else {
        rustls::ClientConfig::builder_with_provider(provider::default_provider().into())
            .with_protocol_versions(versions)
            .unwrap()
    }
}

pub fn finish_server_config(
    kt: KeyType,
    conf: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
) -> ServerConfig {
    conf.with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn make_server_config(kt: KeyType) -> ServerConfig {
    finish_server_config(kt, server_config_builder())
}

pub fn make_server_config_with_versions(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    finish_server_config(kt, server_config_builder_with_versions(versions))
}

pub fn make_server_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> ServerConfig {
    finish_server_config(
        kt,
        ServerConfig::builder_with_provider(
            CryptoProvider {
                kx_groups,
                ..provider::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    )
}

pub fn get_client_root_store(kt: KeyType) -> Arc<RootCertStore> {
    // The key type's chain file contains the DER encoding of the EE cert, the intermediate cert,
    // and the root trust anchor. We want only the trust anchor to build the root cert store.
    let chain = kt.get_chain();
    let trust_anchor = chain.last().unwrap();
    RootCertStore {
        roots: vec![anchor_from_trusted_cert(trust_anchor)
            .unwrap()
            .to_owned()],
    }
    .into()
}

pub fn make_server_config_with_mandatory_client_auth_crls(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt)).with_crls(crls),
    )
}

pub fn make_server_config_with_mandatory_client_auth(kt: KeyType) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt)),
    )
}

pub fn make_server_config_with_optional_client_auth(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt))
            .with_crls(crls)
            .allow_unknown_revocation_status()
            .allow_unauthenticated(),
    )
}

pub fn make_server_config_with_client_verifier(
    kt: KeyType,
    verifier_builder: ClientCertVerifierBuilder,
) -> ServerConfig {
    server_config_builder()
        .with_client_cert_verifier(verifier_builder.build().unwrap())
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn finish_client_config(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf = io::BufReader::new(kt.bytes_for("ca.cert"));
    root_store.add_parsable_certificates(
        rustls_pemfile::certs(&mut rootbuf).map(|result| result.unwrap()),
    );

    config
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

pub fn finish_client_config_with_creds(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf = io::BufReader::new(kt.bytes_for("ca.cert"));
    // Passing a reference here just for testing.
    root_store.add_parsable_certificates(
        rustls_pemfile::certs(&mut rootbuf).map(|result| result.unwrap()),
    );

    config
        .with_root_certificates(root_store)
        .with_client_auth_cert(kt.get_client_chain(), kt.get_client_key())
        .unwrap()
}

pub fn make_client_config(kt: KeyType) -> ClientConfig {
    finish_client_config(kt, client_config_builder())
}

pub fn make_client_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(
        CryptoProvider {
            kx_groups,
            ..provider::default_provider()
        }
        .into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap();
    finish_client_config(kt, builder)
}

pub fn make_client_config_with_versions(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    finish_client_config(kt, client_config_builder_with_versions(versions))
}

pub fn make_client_config_with_auth(kt: KeyType) -> ClientConfig {
    finish_client_config_with_creds(kt, client_config_builder())
}

pub fn make_client_config_with_versions_with_auth(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    finish_client_config_with_creds(kt, client_config_builder_with_versions(versions))
}

pub fn make_client_config_with_verifier(
    versions: &[&'static rustls::SupportedProtocolVersion],
    verifier_builder: ServerCertVerifierBuilder,
) -> ClientConfig {
    client_config_builder_with_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(verifier_builder.build().unwrap())
        .with_no_client_auth()
}

pub fn webpki_client_verifier_builder(roots: Arc<RootCertStore>) -> ClientCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiClientVerifier::builder(roots)
    } else {
        WebPkiClientVerifier::builder_with_provider(roots, provider::default_provider().into())
    }
}

pub fn webpki_server_verifier_builder(roots: Arc<RootCertStore>) -> ServerCertVerifierBuilder {
    if exactly_one_provider() {
        WebPkiServerVerifier::builder(roots)
    } else {
        WebPkiServerVerifier::builder_with_provider(roots, provider::default_provider().into())
    }
}

pub fn make_pair(kt: KeyType) -> (ClientConnection, ServerConnection) {
    make_pair_for_configs(make_client_config(kt), make_server_config(kt))
}

pub fn make_pair_for_configs(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config))
}

pub fn make_pair_for_arc_configs(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::clone(client_config), server_name("localhost")).unwrap(),
        ServerConnection::new(Arc::clone(server_config)).unwrap(),
    )
}

pub fn do_handshake(
    client: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    server: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client, server);
        server.process_new_packets().unwrap();
        to_client += transfer(server, client);
        client.process_new_packets().unwrap();
    }
    (to_server, to_client)
}

#[derive(PartialEq, Debug)]
pub enum ErrorFromPeer {
    Client(Error),
    Server(Error),
}

pub fn do_handshake_until_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), ErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server
            .process_new_packets()
            .map_err(ErrorFromPeer::Server)?;
        transfer(server, client);
        client
            .process_new_packets()
            .map_err(ErrorFromPeer::Client)?;
    }

    Ok(())
}

pub fn do_handshake_until_both_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Vec<ErrorFromPeer>> {
    match do_handshake_until_error(client, server) {
        Err(server_err @ ErrorFromPeer::Server(_)) => {
            let mut errors = vec![server_err];
            transfer(server, client);
            let client_err = client
                .process_new_packets()
                .map_err(ErrorFromPeer::Client)
                .expect_err("client didn't produce error after server error");
            errors.push(client_err);
            Err(errors)
        }

        Err(client_err @ ErrorFromPeer::Client(_)) => {
            let mut errors = vec![client_err];
            transfer(client, server);
            let server_err = server
                .process_new_packets()
                .map_err(ErrorFromPeer::Server)
                .expect_err("server didn't produce error after client error");
            errors.push(server_err);
            Err(errors)
        }

        Ok(()) => Ok(()),
    }
}

pub fn server_name(name: &'static str) -> ServerName<'static> {
    name.try_into().unwrap()
}

pub struct FailsReads {
    errkind: io::ErrorKind,
}

impl FailsReads {
    pub fn new(errkind: io::ErrorKind) -> Self {
        Self { errkind }
    }
}

impl io::Read for FailsReads {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.errkind))
    }
}

pub fn do_suite_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
    expect_suite: SupportedCipherSuite,
    expect_version: ProtocolVersion,
) {
    println!(
        "do_suite_test {:?} {:?}",
        expect_version,
        expect_suite.suite()
    );
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(None, server.negotiated_cipher_suite());
    assert_eq!(None, client.protocol_version());
    assert_eq!(None, server.protocol_version());
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert!(client.is_handshaking());
    assert!(server.is_handshaking());
    assert_eq!(None, client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(Some(expect_version), client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());
}

fn exactly_one_provider() -> bool {
    cfg!(any(
        all(feature = "ring", not(feature = "aws_lc_rs")),
        all(feature = "aws_lc_rs", not(feature = "ring"))
    ))
}

#[derive(Debug)]
pub struct MockServerVerifier {
    cert_rejection_error: Option<Error>,
    tls12_signature_error: Option<Error>,
    tls13_signature_error: Option<Error>,
    signature_schemes: Vec<SignatureScheme>,
    expected_ocsp_response: Option<Vec<u8>>,
}

impl ServerCertVerifier for MockServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        println!(
            "verify_server_cert({:?}, {:?}, {:?}, {:?}, {:?})",
            end_entity, intermediates, server_name, ocsp_response, now
        );
        if let Some(expected_ocsp) = &self.expected_ocsp_response {
            assert_eq!(expected_ocsp, ocsp_response);
        }
        if let Some(error) = &self.cert_rejection_error {
            Err(error.clone())
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!(
            "verify_tls12_signature({:?}, {:?}, {:?})",
            message, cert, dss
        );
        if let Some(error) = &self.tls12_signature_error {
            Err(error.clone())
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!(
            "verify_tls13_signature({:?}, {:?}, {:?})",
            message, cert, dss
        );
        if let Some(error) = &self.tls13_signature_error {
            Err(error.clone())
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_schemes.clone()
    }
}

impl MockServerVerifier {
    pub fn accepts_anything() -> Self {
        MockServerVerifier {
            cert_rejection_error: None,
            ..Default::default()
        }
    }

    pub fn expects_ocsp_response(response: &[u8]) -> Self {
        MockServerVerifier {
            expected_ocsp_response: Some(response.to_vec()),
            ..Default::default()
        }
    }

    pub fn rejects_certificate(err: Error) -> Self {
        MockServerVerifier {
            cert_rejection_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls12_signatures(err: Error) -> Self {
        MockServerVerifier {
            tls12_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls13_signatures(err: Error) -> Self {
        MockServerVerifier {
            tls13_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn offers_no_signature_schemes() -> Self {
        MockServerVerifier {
            signature_schemes: vec![],
            ..Default::default()
        }
    }
}

impl Default for MockServerVerifier {
    fn default() -> Self {
        MockServerVerifier {
            cert_rejection_error: None,
            tls12_signature_error: None,
            tls13_signature_error: None,
            signature_schemes: vec![
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ],
            expected_ocsp_response: None,
        }
    }
}

/// This allows injection/receipt of raw messages into a post-handshake connection.
///
/// It consumes one of the peers, extracts its secrets, and then reconstitutes the
/// message encrypter/decrypter.  It does not do fragmentation/joining.
pub struct RawTls {
    encrypter: Box<dyn MessageEncrypter>,
    enc_seq: u64,
    decrypter: Box<dyn MessageDecrypter>,
    dec_seq: u64,
}

impl RawTls {
    /// conn must be post-handshake, and must have been created with `enable_secret_extraction`
    pub fn new_client(conn: ClientConnection) -> Self {
        let suite = conn.negotiated_cipher_suite().unwrap();
        Self::new(
            suite,
            conn.dangerous_extract_secrets()
                .unwrap(),
        )
    }

    /// conn must be post-handshake, and must have been created with `enable_secret_extraction`
    pub fn new_server(conn: ServerConnection) -> Self {
        let suite = conn.negotiated_cipher_suite().unwrap();
        Self::new(
            suite,
            conn.dangerous_extract_secrets()
                .unwrap(),
        )
    }

    fn new(suite: SupportedCipherSuite, secrets: rustls::ExtractedSecrets) -> Self {
        let rustls::ExtractedSecrets {
            tx: (tx_seq, tx_keys),
            rx: (rx_seq, rx_keys),
        } = secrets;

        let encrypter = match (tx_keys, suite) {
            (
                rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv },
                SupportedCipherSuite::Tls13(tls13),
            ) => tls13.aead_alg.encrypter(key, iv),

            (
                rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv },
                SupportedCipherSuite::Tls12(tls12),
            ) => tls12
                .aead_alg
                .encrypter(key, &iv.as_ref()[..4], &iv.as_ref()[4..]),

            _ => todo!(),
        };

        let decrypter = match (rx_keys, suite) {
            (
                rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv },
                SupportedCipherSuite::Tls13(tls13),
            ) => tls13.aead_alg.decrypter(key, iv),

            (
                rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv },
                SupportedCipherSuite::Tls12(tls12),
            ) => tls12
                .aead_alg
                .decrypter(key, &iv.as_ref()[..4]),

            _ => todo!(),
        };

        Self {
            encrypter,
            enc_seq: tx_seq,
            decrypter,
            dec_seq: rx_seq,
        }
    }

    pub fn encrypt_and_send(
        &mut self,
        msg: &PlainMessage,
        peer: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    ) {
        let data = self
            .encrypter
            .encrypt(msg.borrow_outbound(), self.enc_seq)
            .unwrap()
            .encode();
        self.enc_seq += 1;
        peer.read_tls(&mut io::Cursor::new(data))
            .unwrap();
    }

    pub fn receive_and_decrypt(
        &mut self,
        peer: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        f: impl Fn(Message),
    ) {
        let mut data = vec![];
        peer.write_tls(&mut io::Cursor::new(&mut data))
            .unwrap();

        let mut reader = Reader::init(&data);
        let content_type = ContentType::read(&mut reader).unwrap();
        let version = ProtocolVersion::read(&mut reader).unwrap();
        let len = u16::read(&mut reader).unwrap();
        let left = &mut data[5..];
        assert_eq!(len as usize, left.len());

        let inbound = InboundOpaqueMessage::new(content_type, version, left);
        let plain = self
            .decrypter
            .decrypt(inbound, self.dec_seq)
            .unwrap();
        self.dec_seq += 1;

        let msg = Message::try_from(plain).unwrap();
        println!("receive_and_decrypt: {msg:?}");

        f(msg);
    }
}

pub fn tls13_aes_128_gcm_with_1024_confidentiality_limit() -> Arc<CryptoProvider> {
    const CONFIDENTIALITY_LIMIT: u64 = 1024;

    // needed to extend lifetime of Tls13CipherSuite to 'static
    static LIMITED_SUITE: OnceCell<rustls::Tls13CipherSuite> = OnceCell::new();

    let limited = LIMITED_SUITE.get_or_init(|| {
        let tls13 = provider::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();

        rustls::Tls13CipherSuite {
            common: rustls::crypto::CipherSuiteCommon {
                confidentiality_limit: CONFIDENTIALITY_LIMIT,
                ..tls13.common
            },
            ..*tls13
        }
    });

    CryptoProvider {
        cipher_suites: vec![SupportedCipherSuite::Tls13(limited)],
        ..provider::default_provider()
    }
    .into()
}
