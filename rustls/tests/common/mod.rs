#![allow(dead_code)]
#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]

use std::io;
use std::ops::DerefMut;
use std::sync::Arc;

use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use webpki::anchor_from_trusted_cert;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, OpaqueMessage, PlainMessage};
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, Connection, ConnectionCommon, DigitallySignedStruct, Error,
    RootCertStore, ServerConfig, ServerConnection, SideData, SignatureScheme,
};

#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
pub use rustls::crypto::aws_lc_rs as provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as provider;
use rustls::crypto::CryptoProvider;

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
    (ECDSA_P256_CLIENT_REQ, "ecdsa-p256", "client.req");
    (ECDSA_P256_END_CRL_PEM, "ecdsa-p256", "end.revoked.crl.pem");
    (ECDSA_P256_CLIENT_CRL_PEM, "ecdsa-p256", "client.revoked.crl.pem");
    (ECDSA_P256_INTERMEDIATE_CRL_PEM, "ecdsa-p256", "inter.revoked.crl.pem");
    (ECDSA_P256_END_CERT, "ecdsa-p256", "end.cert");
    (ECDSA_P256_END_CHAIN, "ecdsa-p256", "end.chain");
    (ECDSA_P256_END_FULLCHAIN, "ecdsa-p256", "end.fullchain");
    (ECDSA_P256_END_KEY, "ecdsa-p256", "end.key");
    (ECDSA_P256_END_REQ, "ecdsa-p256", "end.req");
    (ECDSA_P256_INTER_CERT, "ecdsa-p256", "inter.cert");
    (ECDSA_P256_INTER_KEY, "ecdsa-p256", "inter.key");
    (ECDSA_P256_INTER_REQ, "ecdsa-p256", "inter.req");

    (ECDSA_P384_CA_CERT, "ecdsa-p384", "ca.cert");
    (ECDSA_P384_CA_DER, "ecdsa-p384", "ca.der");
    (ECDSA_P384_CA_KEY, "ecdsa-p384", "ca.key");
    (ECDSA_P384_CLIENT_CERT, "ecdsa-p384", "client.cert");
    (ECDSA_P384_CLIENT_CHAIN, "ecdsa-p384", "client.chain");
    (ECDSA_P384_CLIENT_FULLCHAIN, "ecdsa-p384", "client.fullchain");
    (ECDSA_P384_CLIENT_KEY, "ecdsa-p384", "client.key");
    (ECDSA_P384_CLIENT_REQ, "ecdsa-p384", "client.req");
    (ECDSA_P384_END_CRL_PEM, "ecdsa-p384", "end.revoked.crl.pem");
    (ECDSA_P384_CLIENT_CRL_PEM, "ecdsa-p384", "client.revoked.crl.pem");
    (ECDSA_P384_INTERMEDIATE_CRL_PEM, "ecdsa-p384", "inter.revoked.crl.pem");
    (ECDSA_P384_END_CERT, "ecdsa-p384", "end.cert");
    (ECDSA_P384_END_CHAIN, "ecdsa-p384", "end.chain");
    (ECDSA_P384_END_FULLCHAIN, "ecdsa-p384", "end.fullchain");
    (ECDSA_P384_END_KEY, "ecdsa-p384", "end.key");
    (ECDSA_P384_END_REQ, "ecdsa-p384", "end.req");
    (ECDSA_P384_INTER_CERT, "ecdsa-p384", "inter.cert");
    (ECDSA_P384_INTER_KEY, "ecdsa-p384", "inter.key");
    (ECDSA_P384_INTER_REQ, "ecdsa-p384", "inter.req");

    (ECDSA_P521_CA_CERT, "ecdsa-p521", "ca.cert");
    (ECDSA_P521_CA_DER, "ecdsa-p521", "ca.der");
    (ECDSA_P521_CA_KEY, "ecdsa-p521", "ca.key");
    (ECDSA_P521_CLIENT_CERT, "ecdsa-p521", "client.cert");
    (ECDSA_P521_CLIENT_CHAIN, "ecdsa-p521", "client.chain");
    (ECDSA_P521_CLIENT_FULLCHAIN, "ecdsa-p521", "client.fullchain");
    (ECDSA_P521_CLIENT_KEY, "ecdsa-p521", "client.key");
    (ECDSA_P521_CLIENT_REQ, "ecdsa-p521", "client.req");
    (ECDSA_P521_END_CRL_PEM, "ecdsa-p521", "end.revoked.crl.pem");
    (ECDSA_P521_CLIENT_CRL_PEM, "ecdsa-p521", "client.revoked.crl.pem");
    (ECDSA_P521_INTERMEDIATE_CRL_PEM, "ecdsa-p521", "inter.revoked.crl.pem");
    (ECDSA_P521_END_CERT, "ecdsa-p521", "end.cert");
    (ECDSA_P521_END_CHAIN, "ecdsa-p521", "end.chain");
    (ECDSA_P521_END_FULLCHAIN, "ecdsa-p521", "end.fullchain");
    (ECDSA_P521_END_KEY, "ecdsa-p521", "end.key");
    (ECDSA_P521_END_REQ, "ecdsa-p521", "end.req");
    (ECDSA_P521_INTER_CERT, "ecdsa-p521", "inter.cert");
    (ECDSA_P521_INTER_KEY, "ecdsa-p521", "inter.key");
    (ECDSA_P521_INTER_REQ, "ecdsa-p521", "inter.req");

    (EDDSA_CA_CERT, "eddsa", "ca.cert");
    (EDDSA_CA_DER, "eddsa", "ca.der");
    (EDDSA_CA_KEY, "eddsa", "ca.key");
    (EDDSA_CLIENT_CERT, "eddsa", "client.cert");
    (EDDSA_CLIENT_CHAIN, "eddsa", "client.chain");
    (EDDSA_CLIENT_FULLCHAIN, "eddsa", "client.fullchain");
    (EDDSA_CLIENT_KEY, "eddsa", "client.key");
    (EDDSA_CLIENT_REQ, "eddsa", "client.req");
    (EDDSA_END_CRL_PEM, "eddsa", "end.revoked.crl.pem");
    (EDDSA_CLIENT_CRL_PEM, "eddsa", "client.revoked.crl.pem");
    (EDDSA_INTERMEDIATE_CRL_PEM, "eddsa", "inter.revoked.crl.pem");
    (EDDSA_END_CERT, "eddsa", "end.cert");
    (EDDSA_END_CHAIN, "eddsa", "end.chain");
    (EDDSA_END_FULLCHAIN, "eddsa", "end.fullchain");
    (EDDSA_END_KEY, "eddsa", "end.key");
    (EDDSA_END_REQ, "eddsa", "end.req");
    (EDDSA_INTER_CERT, "eddsa", "inter.cert");
    (EDDSA_INTER_KEY, "eddsa", "inter.key");
    (EDDSA_INTER_REQ, "eddsa", "inter.req");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CRL_PEM, "rsa", "end.revoked.crl.pem");
    (RSA_CLIENT_CRL_PEM, "rsa", "client.revoked.crl.pem");
    (RSA_INTERMEDIATE_CRL_PEM, "rsa", "inter.revoked.crl.pem");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
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
            let message = OpaqueMessage::read(&mut reader).unwrap();

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
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

pub static ALL_KEY_TYPES: &[KeyType] = &[
    KeyType::Rsa,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    KeyType::EcdsaP521,
    KeyType::Ed25519,
];

impl KeyType {
    fn bytes_for(&self, part: &str) -> &'static [u8] {
        match self {
            Self::Rsa => bytes_for("rsa", part),
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
        self.get_crl("end")
    }

    pub fn client_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("client")
    }

    pub fn intermediate_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("inter")
    }

    fn get_client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                self.bytes_for("client.key"),
            ))
            .next()
            .unwrap()
            .unwrap(),
        )
    }

    fn get_crl(&self, role: &str) -> CertificateRevocationListDer<'static> {
        rustls_pemfile::crls(&mut io::BufReader::new(
            self.bytes_for(&format!("{role}.revoked.crl.pem")),
        ))
        .map(|result| result.unwrap())
        .next() // We only expect one CRL.
        .unwrap()
    }

    pub fn ca_distinguished_name(&self) -> &'static [u8] {
        match self {
            KeyType::Rsa => &b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponytown RSA CA"[..],
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
    #[cfg(feature = "ring")]
    {
        rustls::ServerConfig::builder()
    }
    #[cfg(not(feature = "ring"))]
    {
        rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn server_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    #[cfg(feature = "ring")]
    {
        rustls::ServerConfig::builder_with_protocol_versions(versions)
    }
    #[cfg(not(feature = "ring"))]
    {
        rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
            .with_protocol_versions(versions)
            .unwrap()
    }
}

pub fn client_config_builder() -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    // ensure `ClientConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(provider::provider().into())`.
    #[cfg(feature = "ring")]
    {
        rustls::ClientConfig::builder()
    }

    #[cfg(not(feature = "ring"))]
    {
        rustls::ClientConfig::builder_with_provider(provider::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
    }
}

pub fn client_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    #[cfg(feature = "ring")]
    {
        rustls::ClientConfig::builder_with_protocol_versions(versions)
    }
    #[cfg(not(feature = "ring"))]
    {
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
    #[cfg(feature = "ring")]
    {
        WebPkiClientVerifier::builder(roots)
    }

    #[cfg(not(feature = "ring"))]
    {
        WebPkiClientVerifier::builder_with_provider(roots, provider::default_provider().into())
    }
}

pub fn webpki_server_verifier_builder(roots: Arc<RootCertStore>) -> ServerCertVerifierBuilder {
    #[cfg(feature = "ring")]
    {
        WebPkiServerVerifier::builder(roots)
    }

    #[cfg(not(feature = "ring"))]
    {
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

#[derive(Debug)]
pub struct MockServerVerifier {
    cert_rejection_error: Option<Error>,
    tls12_signature_error: Option<Error>,
    tls13_signature_error: Option<Error>,
    signature_schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for MockServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        oscp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        println!(
            "verify_server_cert({:?}, {:?}, {:?}, {:?}, {:?})",
            end_entity, intermediates, server_name, oscp_response, now
        );
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
        }
    }
}
