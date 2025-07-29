#![warn(
    clippy::alloc_instead_of_core,
    clippy::manual_let_else,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    elided_lifetimes_in_paths,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use core::ops::DerefMut;
use std::io;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    AlwaysResolvesClientRawPublicKeys, ServerCertVerifierBuilder, UnbufferedClientConnection,
    WebPkiServerVerifier,
};
use rustls::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key,
};
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{
    AlwaysResolvesServerRawPublicKeys, ClientCertVerifierBuilder, UnbufferedServerConnection,
    WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::unbuffered::{
    ConnectionState, EncodeError, UnbufferedConnectionCommon, UnbufferedStatus,
};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, Connection, ConnectionCommon, ContentType,
    DigitallySignedStruct, DistinguishedName, Error, InconsistentKeys, NamedGroup, ProtocolVersion,
    RootCertStore, ServerConfig, ServerConnection, SideData, SignatureScheme, SupportedCipherSuite,
};

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../test-ca/", $keytype, "/", $path));
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
    (ECDSA_P256_END_PEM_SPKI, "ecdsa-p256", "end.spki.pem");
    (ECDSA_P256_CLIENT_PEM_SPKI, "ecdsa-p256", "client.spki.pem");
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

    (ECDSA_P384_END_PEM_SPKI, "ecdsa-p384", "end.spki.pem");
    (ECDSA_P384_CLIENT_PEM_SPKI, "ecdsa-p384", "client.spki.pem");
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

    (ECDSA_P521_END_PEM_SPKI, "ecdsa-p521", "end.spki.pem");
    (ECDSA_P521_CLIENT_PEM_SPKI, "ecdsa-p521", "client.spki.pem");
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

    (EDDSA_END_PEM_SPKI, "eddsa", "end.spki.pem");
    (EDDSA_CLIENT_PEM_SPKI, "eddsa", "client.spki.pem");
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

    (RSA_2048_END_PEM_SPKI, "rsa-2048", "end.spki.pem");
    (RSA_2048_CLIENT_PEM_SPKI, "rsa-2048", "client.spki.pem");
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

    (RSA_3072_END_PEM_SPKI, "rsa-3072", "end.spki.pem");
    (RSA_3072_CLIENT_PEM_SPKI, "rsa-3072", "client.spki.pem");
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

    (RSA_4096_END_PEM_SPKI, "rsa-4096", "end.spki.pem");
    (RSA_4096_CLIENT_PEM_SPKI, "rsa-4096", "client.spki.pem");
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
    F: Fn(&mut Message<'_>) -> Altered,
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

static ALL_KEY_TYPES: &[KeyType] = &[
    KeyType::Rsa2048,
    KeyType::Rsa3072,
    KeyType::Rsa4096,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    KeyType::EcdsaP521,
    KeyType::Ed25519,
];

static ALL_KEY_TYPES_EXCEPT_P521: &[KeyType] = &[
    KeyType::Rsa2048,
    KeyType::Rsa3072,
    KeyType::Rsa4096,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    KeyType::Ed25519,
];

impl KeyType {
    pub fn all_for_provider(provider: &CryptoProvider) -> &'static [Self] {
        match provider
            .key_provider
            .load_private_key(Self::EcdsaP521.get_key())
            .is_ok()
        {
            true => ALL_KEY_TYPES,
            false => ALL_KEY_TYPES_EXCEPT_P521,
        }
    }

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

    pub fn ca_cert(&self) -> CertificateDer<'_> {
        self.get_chain()
            .into_iter()
            .next_back()
            .expect("cert chain cannot be empty")
    }

    pub fn get_chain(&self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(self.bytes_for("end.fullchain"))
            .map(|result| result.unwrap())
            .collect()
    }

    pub fn get_spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from_pem_slice(self.bytes_for("end.spki.pem")).unwrap()
    }

    pub fn get_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from_pem_slice(self.bytes_for("end.key"))
            .unwrap()
            .into()
    }

    pub fn get_client_chain(&self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(self.bytes_for("client.fullchain"))
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
        PrivatePkcs8KeyDer::from_pem_slice(self.bytes_for("client.key"))
            .unwrap()
            .into()
    }

    pub fn get_client_spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from_pem_slice(self.bytes_for("client.spki.pem")).unwrap()
    }

    pub fn get_certified_client_key(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Arc<CertifiedKey>, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.get_client_key())?;
        let public_key = private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))?;
        let public_key_as_cert = CertificateDer::from(public_key.to_vec());
        Ok(Arc::new(CertifiedKey::new_unchecked(
            vec![public_key_as_cert],
            private_key,
        )))
    }

    pub fn certified_key_with_raw_pub_key(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Arc<CertifiedKey>, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.get_key())?;
        let public_key = private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))?;
        let public_key_as_cert = CertificateDer::from(public_key.to_vec());
        Ok(Arc::new(CertifiedKey::new_unchecked(
            vec![public_key_as_cert],
            private_key,
        )))
    }

    pub fn certified_key_with_cert_chain(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Arc<CertifiedKey>, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.get_key())?;
        Ok(Arc::new(CertifiedKey::new(self.get_chain(), private_key)?))
    }

    fn get_crl(&self, role: &str, r#type: &str) -> CertificateRevocationListDer<'static> {
        CertificateRevocationListDer::from_pem_slice(
            self.bytes_for(&format!("{role}.{type}.crl.pem")),
        )
        .unwrap()
    }

    pub fn ca_distinguished_name(&self) -> &'static [u8] {
        match self {
            Self::Rsa2048 => b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 2048 CA",
            Self::Rsa3072 => b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 3072 CA",
            Self::Rsa4096 => b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 4096 CA",
            Self::EcdsaP256 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p256 CA",
            Self::EcdsaP384 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p384 CA",
            Self::EcdsaP521 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p521 CA",
            Self::Ed25519 => b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown EdDSA CA",
        }
    }
}

pub fn server_config_builder(
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    ServerConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .unwrap()
}

pub fn server_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
    ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(versions)
        .unwrap()
}

pub fn client_config_builder(
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .unwrap()
}

pub fn client_config_builder_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    ClientConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(versions)
        .unwrap()
}

pub fn finish_server_config(
    kt: KeyType,
    conf: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>,
) -> ServerConfig {
    conf.with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn make_server_config(kt: KeyType, provider: &CryptoProvider) -> ServerConfig {
    finish_server_config(kt, server_config_builder(provider))
}

pub fn make_server_config_with_versions(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> ServerConfig {
    finish_server_config(kt, server_config_builder_with_versions(versions, provider))
}

pub fn make_server_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    provider: &CryptoProvider,
) -> ServerConfig {
    finish_server_config(
        kt,
        ServerConfig::builder_with_provider(
            CryptoProvider {
                kx_groups,
                ..provider.clone()
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
    let mut roots = RootCertStore::empty();
    roots
        .add(chain.last().unwrap().clone())
        .unwrap();
    roots.into()
}

pub fn make_server_config_with_mandatory_client_auth_crls(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
    provider: &CryptoProvider,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt), provider).with_crls(crls),
        provider,
    )
}

pub fn make_server_config_with_mandatory_client_auth(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt), provider),
        provider,
    )
}

pub fn make_server_config_with_optional_client_auth(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
    provider: &CryptoProvider,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt), provider)
            .with_crls(crls)
            .allow_unknown_revocation_status()
            .allow_unauthenticated(),
        provider,
    )
}

pub fn make_server_config_with_client_verifier(
    kt: KeyType,
    verifier_builder: ClientCertVerifierBuilder,
    provider: &CryptoProvider,
) -> ServerConfig {
    server_config_builder(provider)
        .with_client_cert_verifier(verifier_builder.build().unwrap())
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn make_server_config_with_raw_key_support(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ServerConfig {
    let mut client_verifier =
        MockClientVerifier::new(|| Ok(ClientCertVerified::assertion()), kt, provider);
    let server_cert_resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(
        kt.certified_key_with_raw_pub_key(provider)
            .unwrap(),
    ));
    client_verifier.expect_raw_public_keys = true;
    // We don't support tls1.2 for Raw Public Keys, hence the version is hard-coded.
    server_config_builder_with_versions(&[&rustls::version::TLS13], provider)
        .with_client_cert_verifier(Arc::new(client_verifier))
        .with_cert_resolver(server_cert_resolver)
}

pub fn make_client_config_with_raw_key_support(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ClientConfig {
    let server_verifier = Arc::new(MockServerVerifier::expects_raw_public_keys(provider));
    let client_cert_resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(
        kt.get_certified_client_key(provider)
            .unwrap(),
    ));
    // We don't support tls1.2 for Raw Public Keys, hence the version is hard-coded.
    client_config_builder_with_versions(&[&rustls::version::TLS13], provider)
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(client_cert_resolver)
}

pub fn make_client_config_with_cipher_suite_and_raw_key_support(
    kt: KeyType,
    cipher_suite: SupportedCipherSuite,
    provider: &CryptoProvider,
) -> ClientConfig {
    let server_verifier = Arc::new(MockServerVerifier::expects_raw_public_keys(provider));
    let client_cert_resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(
        kt.get_certified_client_key(provider)
            .unwrap(),
    ));
    ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: vec![cipher_suite],
            ..provider.clone()
        }
        .into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(server_verifier)
    .with_client_cert_resolver(client_cert_resolver)
}

pub fn finish_client_config(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_slice_iter(kt.bytes_for("ca.cert")).map(|result| result.unwrap()),
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
    root_store.add_parsable_certificates(
        CertificateDer::pem_slice_iter(kt.bytes_for("ca.cert")).map(|result| result.unwrap()),
    );

    config
        .with_root_certificates(root_store)
        .with_client_auth_cert(kt.get_client_chain(), kt.get_client_key())
        .unwrap()
}

pub fn make_client_config(kt: KeyType, provider: &CryptoProvider) -> ClientConfig {
    finish_client_config(kt, client_config_builder(provider))
}

pub fn make_client_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    provider: &CryptoProvider,
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(
        CryptoProvider {
            kx_groups,
            ..provider.clone()
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
    provider: &CryptoProvider,
) -> ClientConfig {
    finish_client_config(kt, client_config_builder_with_versions(versions, provider))
}

pub fn make_client_config_with_auth(kt: KeyType, provider: &CryptoProvider) -> ClientConfig {
    finish_client_config_with_creds(kt, client_config_builder(provider))
}

pub fn make_client_config_with_versions_with_auth(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: &CryptoProvider,
) -> ClientConfig {
    finish_client_config_with_creds(kt, client_config_builder_with_versions(versions, provider))
}

pub fn make_client_config_with_verifier(
    versions: &[&'static rustls::SupportedProtocolVersion],
    verifier_builder: ServerCertVerifierBuilder,
    provider: &CryptoProvider,
) -> ClientConfig {
    client_config_builder_with_versions(versions, provider)
        .dangerous()
        .with_custom_certificate_verifier(verifier_builder.build().unwrap())
        .with_no_client_auth()
}

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ClientCertVerifierBuilder {
    WebPkiClientVerifier::builder_with_provider(roots, provider.clone().into())
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ServerCertVerifierBuilder {
    WebPkiServerVerifier::builder_with_provider(roots, provider.clone().into())
}

pub fn make_pair(kt: KeyType, provider: &CryptoProvider) -> (ClientConnection, ServerConnection) {
    make_pair_for_configs(
        make_client_config(kt, provider),
        make_server_config(kt, provider),
    )
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
        ClientConnection::new(client_config.clone(), server_name("localhost")).unwrap(),
        ServerConnection::new(server_config.clone()).unwrap(),
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

// Drive a handshake using unbuffered connections.
//
// Note that this drives the connection beyond the handshake until both
// connections are idle and there is no pending data waiting to be processed
// by either. In practice this just means that session tickets are processed
// by the client.
pub fn do_unbuffered_handshake(
    client: &mut UnbufferedClientConnection,
    server: &mut UnbufferedServerConnection,
) {
    fn is_idle<Data>(conn: &UnbufferedConnectionCommon<Data>, data: &[u8]) -> bool {
        !conn.is_handshaking() && !conn.wants_write() && data.is_empty()
    }

    let mut client_data = Vec::with_capacity(1024);
    let mut server_data = Vec::with_capacity(1024);

    while !is_idle(client, &client_data) || !is_idle(server, &server_data) {
        loop {
            let UnbufferedStatus { discard, state, .. } =
                client.process_tls_records(&mut client_data);
            let state = state.unwrap();

            match state {
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    client_data.drain(..discard);
                    break;
                }
                ConnectionState::Closed | ConnectionState::PeerClosed => unreachable!(),
                ConnectionState::ReadEarlyData(_) => (),
                ConnectionState::EncodeTlsData(mut data) => {
                    let required = match data.encode(&mut []) {
                        Err(EncodeError::InsufficientSize(err)) => err.required_size,
                        _ => unreachable!(),
                    };

                    let old_len = server_data.len();
                    server_data.resize(old_len + required, 0);
                    data.encode(&mut server_data[old_len..])
                        .unwrap();
                }
                ConnectionState::TransmitTlsData(data) => data.done(),
                st => unreachable!("unexpected connection state: {st:?}"),
            }

            client_data.drain(..discard);
        }

        loop {
            let UnbufferedStatus { discard, state, .. } =
                server.process_tls_records(&mut server_data);
            let state = state.unwrap();

            match state {
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    server_data.drain(..discard);
                    break;
                }
                ConnectionState::Closed | ConnectionState::PeerClosed => unreachable!(),
                ConnectionState::ReadEarlyData(_) => unreachable!(),
                ConnectionState::EncodeTlsData(mut data) => {
                    let required = match data.encode(&mut []) {
                        Err(EncodeError::InsufficientSize(err)) => err.required_size,
                        _ => unreachable!(),
                    };

                    let old_len = client_data.len();
                    client_data.resize(old_len + required, 0);
                    data.encode(&mut client_data[old_len..])
                        .unwrap();
                }
                ConnectionState::TransmitTlsData(data) => data.done(),
                _ => unreachable!(),
            }

            server_data.drain(..discard);
        }
    }

    assert!(server_data.is_empty());
    assert!(client_data.is_empty());
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

pub fn do_handshake_altered(
    client: ClientConnection,
    alter_server_message: impl Fn(&mut Message<'_>) -> Altered,
    alter_client_message: impl Fn(&mut Message<'_>) -> Altered,
    server: ServerConnection,
) -> Result<(), ErrorFromPeer> {
    let mut client: Connection = Connection::Client(client);
    let mut server: Connection = Connection::Server(server);

    while server.is_handshaking() || client.is_handshaking() {
        transfer_altered(&mut client, &alter_client_message, &mut server);

        server
            .process_new_packets()
            .map_err(ErrorFromPeer::Server)?;

        transfer_altered(&mut server, &alter_server_message, &mut client);

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

/// An object that impls `io::Read` and `io::Write` for testing.
///
/// The `reads` and `writes` fields set the behaviour of these trait
/// implementations.  They return the `WouldBlock` error if not otherwise
/// configured -- `TestNonBlockIo::default()` does this permanently.
///
/// This object panics on drop if the configured expected reads/writes
/// didn't take place.
#[derive(Debug, Default)]
pub struct TestNonBlockIo {
    /// Each `write()` call is satisfied by inspecting this field.
    ///
    /// If it is empty, `WouldBlock` is returned.  Otherwise the write is
    /// satisfied by popping a value and returning it (reduced by the size
    /// of the write buffer, if needed).
    pub writes: Vec<usize>,

    /// Each `read()` call is satisfied by inspecting this field.
    ///
    /// If it is empty, `WouldBlock` is returned.  Otherwise the read is
    /// satisfied by popping a value and copying it into the output
    /// buffer.  Each value must be no longer than the buffer for that
    /// call.
    pub reads: Vec<Vec<u8>>,
}

impl io::Read for TestNonBlockIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        println!("read {:?}", buf.len());
        match self.reads.pop() {
            None => Err(io::ErrorKind::WouldBlock.into()),
            Some(data) => {
                assert!(data.len() <= buf.len());
                let take = core::cmp::min(data.len(), buf.len());
                buf[..take].clone_from_slice(&data[..take]);
                Ok(take)
            }
        }
    }
}

impl io::Write for TestNonBlockIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("write {:?}", buf.len());
        match self.writes.pop() {
            None => Err(io::ErrorKind::WouldBlock.into()),
            Some(n) => Ok(core::cmp::min(n, buf.len())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        println!("flush");
        Ok(())
    }
}

impl Drop for TestNonBlockIo {
    fn drop(&mut self) {
        // ensure the object was exhausted as expected
        assert!(self.reads.is_empty());
        assert!(self.writes.is_empty());
    }
}

pub fn do_suite_and_kx_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
    expect_suite: SupportedCipherSuite,
    expect_kx: NamedGroup,
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
    assert!(
        client
            .negotiated_key_exchange_group()
            .is_none()
    );
    assert!(
        server
            .negotiated_key_exchange_group()
            .is_none()
    );
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
    assert!(
        client
            .negotiated_key_exchange_group()
            .is_none()
    );
    if matches!(expect_version, ProtocolVersion::TLSv1_2) {
        assert!(
            server
                .negotiated_key_exchange_group()
                .is_none()
        );
    } else {
        assert_eq!(
            expect_kx,
            server
                .negotiated_key_exchange_group()
                .unwrap()
                .name()
        );
    }

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());
    assert_eq!(
        expect_kx,
        client
            .negotiated_key_exchange_group()
            .unwrap()
            .name()
    );
    if matches!(expect_version, ProtocolVersion::TLSv1_2) {
        assert!(
            server
                .negotiated_key_exchange_group()
                .is_none()
        );
    } else {
        assert_eq!(
            expect_kx,
            server
                .negotiated_key_exchange_group()
                .unwrap()
                .name()
        );
    }

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
    assert_eq!(
        expect_kx,
        client
            .negotiated_key_exchange_group()
            .unwrap()
            .name()
    );
    assert_eq!(
        expect_kx,
        server
            .negotiated_key_exchange_group()
            .unwrap()
            .name()
    );
}

#[derive(Debug)]
pub struct MockServerVerifier {
    cert_rejection_error: Option<Error>,
    tls12_signature_error: Option<Error>,
    tls13_signature_error: Option<Error>,
    signature_schemes: Vec<SignatureScheme>,
    expected_ocsp_response: Option<Vec<u8>>,
    requires_raw_public_keys: bool,
    raw_public_key_algorithms: Option<WebPkiSupportedAlgorithms>,
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
            "verify_server_cert({end_entity:?}, {intermediates:?}, {server_name:?}, {ocsp_response:?}, {now:?})"
        );
        if let Some(expected_ocsp) = &self.expected_ocsp_response {
            assert_eq!(expected_ocsp, ocsp_response);
        }
        match &self.cert_rejection_error {
            Some(error) => Err(error.clone()),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!("verify_tls12_signature({message:?}, {cert:?}, {dss:?})");
        match &self.tls12_signature_error {
            Some(error) => Err(error.clone()),
            _ => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!("verify_tls13_signature({message:?}, {cert:?}, {dss:?})");
        match &self.tls13_signature_error {
            Some(error) => Err(error.clone()),
            _ if self.requires_raw_public_keys => verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                self.raw_public_key_algorithms
                    .as_ref()
                    .unwrap(),
            ),
            _ => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_schemes.clone()
    }

    fn request_ocsp_response(&self) -> bool {
        self.expected_ocsp_response.is_some()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.requires_raw_public_keys
    }
}

impl MockServerVerifier {
    pub fn accepts_anything() -> Self {
        Self {
            cert_rejection_error: None,
            ..Default::default()
        }
    }

    pub fn expects_ocsp_response(response: &[u8]) -> Self {
        Self {
            expected_ocsp_response: Some(response.to_vec()),
            ..Default::default()
        }
    }

    pub fn rejects_certificate(err: Error) -> Self {
        Self {
            cert_rejection_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls12_signatures(err: Error) -> Self {
        Self {
            tls12_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn rejects_tls13_signatures(err: Error) -> Self {
        Self {
            tls13_signature_error: Some(err),
            ..Default::default()
        }
    }

    pub fn offers_no_signature_schemes() -> Self {
        Self {
            signature_schemes: vec![],
            ..Default::default()
        }
    }

    pub fn expects_raw_public_keys(provider: &CryptoProvider) -> Self {
        Self {
            requires_raw_public_keys: true,
            raw_public_key_algorithms: Some(provider.signature_verification_algorithms),
            ..Default::default()
        }
    }
}

impl Default for MockServerVerifier {
    fn default() -> Self {
        Self {
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
            requires_raw_public_keys: false,
            raw_public_key_algorithms: None,
        }
    }
}

#[derive(Debug)]
pub struct MockClientVerifier {
    pub verified: fn() -> Result<ClientCertVerified, Error>,
    pub subjects: Arc<[DistinguishedName]>,
    pub mandatory: bool,
    pub offered_schemes: Option<Vec<SignatureScheme>>,
    expect_raw_public_keys: bool,
    raw_public_key_algorithms: Option<WebPkiSupportedAlgorithms>,
    parent: Arc<dyn ClientCertVerifier>,
}

impl MockClientVerifier {
    pub fn new(
        verified: fn() -> Result<ClientCertVerified, Error>,
        kt: KeyType,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            parent: webpki_client_verifier_builder(get_client_root_store(kt), provider)
                .build()
                .unwrap(),
            verified,
            subjects: Arc::from(get_client_root_store(kt).subjects()),
            mandatory: true,
            offered_schemes: None,
            expect_raw_public_keys: false,
            raw_public_key_algorithms: Some(provider.signature_verification_algorithms),
        }
    }
}

impl ClientCertVerifier for MockClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        self.subjects.clone()
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        (self.verified)()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if self.expect_raw_public_keys {
            Ok(HandshakeSignatureValid::assertion())
        } else {
            self.parent
                .verify_tls12_signature(message, cert, dss)
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if self.expect_raw_public_keys {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                self.raw_public_key_algorithms
                    .as_ref()
                    .unwrap(),
            )
        } else {
            self.parent
                .verify_tls13_signature(message, cert, dss)
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(schemes) = &self.offered_schemes {
            schemes.clone()
        } else {
            self.parent.supported_verify_schemes()
        }
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.expect_raw_public_keys
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
        f: impl Fn(Message<'_>),
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

pub fn aes_128_gcm_with_1024_confidentiality_limit(
    provider: CryptoProvider,
) -> Arc<CryptoProvider> {
    const CONFIDENTIALITY_LIMIT: u64 = 1024;

    // needed to extend lifetime of Tls13CipherSuite to 'static
    static TLS13_LIMITED_SUITE: OnceLock<rustls::Tls13CipherSuite> = OnceLock::new();
    static TLS12_LIMITED_SUITE: OnceLock<rustls::Tls12CipherSuite> = OnceLock::new();

    let tls13_limited = TLS13_LIMITED_SUITE.get_or_init(|| {
        let tls13 = provider
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
            .unwrap()
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

    let tls12_limited = TLS12_LIMITED_SUITE.get_or_init(|| {
        let SupportedCipherSuite::Tls12(tls12) = *provider
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            .unwrap()
        else {
            unreachable!();
        };

        rustls::Tls12CipherSuite {
            common: rustls::crypto::CipherSuiteCommon {
                confidentiality_limit: CONFIDENTIALITY_LIMIT,
                ..tls12.common
            },
            ..*tls12
        }
    });

    CryptoProvider {
        cipher_suites: vec![
            SupportedCipherSuite::Tls13(tls13_limited),
            SupportedCipherSuite::Tls12(tls12_limited),
        ],
        ..provider
    }
    .into()
}

pub fn unsafe_plaintext_crypto_provider(provider: CryptoProvider) -> Arc<CryptoProvider> {
    static TLS13_PLAIN_SUITE: OnceLock<rustls::Tls13CipherSuite> = OnceLock::new();

    let tls13 = TLS13_PLAIN_SUITE.get_or_init(|| {
        let tls13 = provider
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == CipherSuite::TLS13_AES_256_GCM_SHA384)
            .unwrap()
            .tls13()
            .unwrap();

        rustls::Tls13CipherSuite {
            aead_alg: &plaintext::Aead,
            common: rustls::crypto::CipherSuiteCommon { ..tls13.common },
            ..*tls13
        }
    });

    CryptoProvider {
        cipher_suites: vec![SupportedCipherSuite::Tls13(tls13)],
        ..provider
    }
    .into()
}

mod plaintext {
    use rustls::ConnectionTrafficSecrets;
    use rustls::crypto::cipher::{
        AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
        OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    };

    use super::*;

    pub(super) struct Aead;

    impl Tls13AeadAlgorithm for Aead {
        fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
            Box::new(Encrypter)
        }

        fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
            Box::new(Decrypter)
        }

        fn key_len(&self) -> usize {
            32
        }

        fn extract_keys(
            &self,
            _key: AeadKey,
            _iv: Iv,
        ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
            Err(UnsupportedOperationError)
        }
    }

    struct Encrypter;

    impl MessageEncrypter for Encrypter {
        fn encrypt(
            &mut self,
            msg: OutboundPlainMessage<'_>,
            _seq: u64,
        ) -> Result<OutboundOpaqueMessage, Error> {
            let mut payload = PrefixedPayload::with_capacity(msg.payload.len());
            payload.extend_from_chunks(&msg.payload);

            Ok(OutboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            ))
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len
        }
    }

    struct Decrypter;

    impl MessageDecrypter for Decrypter {
        fn decrypt<'a>(
            &mut self,
            msg: InboundOpaqueMessage<'a>,
            _seq: u64,
        ) -> Result<InboundPlainMessage<'a>, Error> {
            Ok(msg.into_plain_message())
        }
    }
}

/// Deeply inefficient, test-only TLS encoding helpers
pub mod encoding {
    use rustls::internal::msgs::codec::Codec;
    use rustls::internal::msgs::enums::ExtensionType;
    use rustls::{
        CipherSuite, ContentType, HandshakeType, NamedGroup, ProtocolVersion, SignatureScheme,
    };

    /// Return a client hello with mandatory extensions added to `extensions`
    ///
    /// The returned bytes are handshake-framed, but not message-framed.
    pub fn basic_client_hello(mut extensions: Vec<Extension>) -> Vec<u8> {
        extensions.push(Extension::new_kx_groups());
        extensions.push(Extension::new_sig_algs());
        extensions.push(Extension::new_versions());
        extensions.push(Extension::new_dummy_key_share());
        client_hello_with_extensions(extensions)
    }

    /// Return a client hello with exactly `extensions`
    ///
    /// The returned bytes are handshake-framed, but not message-framed.
    pub fn client_hello_with_extensions(extensions: Vec<Extension>) -> Vec<u8> {
        client_hello(
            ProtocolVersion::TLSv1_2,
            &[0u8; 32],
            &[0],
            vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
            ],
            extensions,
        )
    }

    pub fn client_hello(
        legacy_version: ProtocolVersion,
        random: &[u8; 32],
        session_id: &[u8],
        cipher_suites: Vec<CipherSuite>,
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let mut out = vec![];

        legacy_version.encode(&mut out);
        out.extend_from_slice(random);
        out.extend_from_slice(session_id);
        cipher_suites.to_vec().encode(&mut out);
        out.extend_from_slice(&[0x01, 0x00]); // only null compression

        let mut exts = vec![];
        for e in extensions {
            e.typ.encode(&mut exts);
            exts.extend_from_slice(&(e.body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&e.body);
        }

        out.extend(len_u16(exts));
        handshake_framing(HandshakeType::ClientHello, out)
    }

    /// Apply handshake framing to `body`.
    ///
    /// This does not do fragmentation.
    pub fn handshake_framing(ty: HandshakeType, body: Vec<u8>) -> Vec<u8> {
        let mut body = len_u24(body);
        body.splice(0..0, ty.to_array());
        body
    }

    /// Apply message framing to `body`.
    pub fn message_framing(ty: ContentType, vers: ProtocolVersion, body: Vec<u8>) -> Vec<u8> {
        let mut body = len_u16(body);
        body.splice(0..0, vers.to_array());
        body.splice(0..0, ty.to_array());
        body
    }

    #[derive(Clone)]
    pub struct Extension {
        pub typ: ExtensionType,
        pub body: Vec<u8>,
    }

    impl Extension {
        pub fn new_sig_algs() -> Self {
            Self {
                typ: ExtensionType::SignatureAlgorithms,
                body: len_u16(
                    SignatureScheme::RSA_PKCS1_SHA256
                        .to_array()
                        .to_vec(),
                ),
            }
        }

        pub fn new_kx_groups() -> Self {
            Self {
                typ: ExtensionType::EllipticCurves,
                body: len_u16(vector_of([NamedGroup::secp256r1].into_iter())),
            }
        }

        pub fn new_versions() -> Self {
            Self {
                typ: ExtensionType::SupportedVersions,
                body: len_u8(vector_of(
                    [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2].into_iter(),
                )),
            }
        }

        pub fn new_dummy_key_share() -> Self {
            const SOME_POINT_ON_P256: &[u8] = &[
                4, 41, 39, 177, 5, 18, 186, 227, 237, 220, 254, 70, 120, 40, 18, 139, 173, 41, 3,
                38, 153, 25, 247, 8, 96, 105, 200, 196, 223, 108, 115, 40, 56, 199, 120, 121, 100,
                234, 172, 0, 229, 146, 31, 177, 73, 138, 96, 244, 96, 103, 102, 179, 217, 104, 80,
                1, 85, 141, 26, 151, 78, 115, 65, 81, 62,
            ];

            let mut share = len_u16(SOME_POINT_ON_P256.to_vec());
            share.splice(0..0, NamedGroup::secp256r1.to_array());

            Self {
                typ: ExtensionType::KeyShare,
                body: len_u16(share),
            }
        }
    }

    /// Prefix with u8 length
    pub fn len_u8(mut body: Vec<u8>) -> Vec<u8> {
        body.splice(0..0, [body.len() as u8]);
        body
    }

    /// Prefix with u16 length
    pub fn len_u16(mut body: Vec<u8>) -> Vec<u8> {
        body.splice(0..0, (body.len() as u16).to_be_bytes());
        body
    }

    /// Prefix with u24 length
    pub fn len_u24(mut body: Vec<u8>) -> Vec<u8> {
        let len = (body.len() as u32).to_be_bytes();
        body.insert(0, len[1]);
        body.insert(1, len[2]);
        body.insert(2, len[3]);
        body
    }

    /// Encode each of `items`
    pub fn vector_of<'a, T: Codec<'a>>(items: impl Iterator<Item = T>) -> Vec<u8> {
        let mut body = Vec::new();

        for i in items {
            i.encode(&mut body);
        }
        body
    }
}
