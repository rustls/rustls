use core::hash::Hasher;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};
use std::borrow::Cow;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use rustls::client::danger::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
};
use rustls::client::{
    ClientSessionKey, ServerVerifierBuilder, Tls13Session, WantsClientCert, WebPkiServerVerifier,
};
use rustls::crypto::cipher::{
    EncodedMessage, InboundOpaque, MessageDecrypter, MessageEncrypter, Payload,
};
use rustls::crypto::kx::{NamedGroup, SupportedKxGroup};
use rustls::crypto::{
    CipherSuite, Credentials, CryptoProvider, Identity, InconsistentKeys, SelectedCredential,
    SignatureScheme, SigningKey, SingleCredential, WebPkiSupportedAlgorithms,
    verify_tls13_signature,
};
use rustls::enums::{CertificateType, ContentType, ProtocolVersion};
use rustls::error::{CertificateError, Error};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer,
    ServerName, SubjectPublicKeyInfoDer,
};
use rustls::server::danger::{ClientIdentity, ClientVerifier, SignatureVerificationInput};
use rustls::server::{
    ClientHello, ClientVerifierBuilder, ServerCredentialResolver, WebPkiClientVerifier,
};
use rustls::{
    ClientConfig, ClientConnection, ConfigBuilder, Connection, ConnectionCommon,
    ConnectionTrafficSecrets, DistinguishedName, RootCertStore, ServerConfig, ServerConnection,
    SideData, SupportedCipherSuite, WantsVerifier,
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
    F: Fn(&mut EncodedMessage<Vec<u8>>) -> Altered,
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

        let mut offset = 0;
        while offset < sz {
            assert!(
                offset + 5 <= sz,
                "incomplete TLS record header at offset {offset}"
            );

            let typ = ContentType::from(buf[offset]);
            let version =
                ProtocolVersion::from(u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]));
            let payload_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;

            assert!(
                offset + 5 + payload_len <= sz,
                "incomplete TLS record payload at offset {offset}"
            );

            let payload = buf[offset + 5..offset + 5 + payload_len].to_vec();
            offset += 5 + payload_len;

            let mut encoded = EncodedMessage {
                typ,
                version,
                payload,
            };

            let message_enc = match filter(&mut encoded) {
                Altered::InPlace => {
                    encoding::message_framing(encoded.typ, encoded.version, encoded.payload.clone())
                }
                Altered::Raw(data) => data,
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
            .load_private_key(Self::EcdsaP521.key())
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

    pub fn identity(&self) -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(
                CertificateDer::pem_slice_iter(self.bytes_for("end.fullchain"))
                    .map(|result| result.unwrap())
                    .collect(),
            )
            .unwrap(),
        )
    }

    pub fn spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from_pem_slice(self.bytes_for("end.spki.pem")).unwrap()
    }

    pub fn load_key(&self, provider: &CryptoProvider) -> Box<dyn SigningKey> {
        provider
            .key_provider
            .load_private_key(self.key())
            .expect("valid key")
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from_pem_slice(self.bytes_for("end.key"))
            .unwrap()
            .into()
    }

    pub fn client_identity(&self) -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(
                CertificateDer::pem_slice_iter(self.bytes_for("client.fullchain"))
                    .map(|result| result.unwrap())
                    .collect(),
            )
            .unwrap(),
        )
    }

    pub fn end_entity_crl(&self) -> CertificateRevocationListDer<'static> {
        self.crl("end", "revoked")
    }

    pub fn client_crl(&self) -> CertificateRevocationListDer<'static> {
        self.crl("client", "revoked")
    }

    pub fn intermediate_crl(&self) -> CertificateRevocationListDer<'static> {
        self.crl("inter", "revoked")
    }

    pub fn end_entity_crl_expired(&self) -> CertificateRevocationListDer<'static> {
        self.crl("end", "expired")
    }

    pub fn client_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from_pem_slice(self.bytes_for("client.key"))
            .unwrap()
            .into()
    }

    pub fn client_spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from_pem_slice(self.bytes_for("client.spki.pem")).unwrap()
    }

    pub fn certified_client_key(&self, provider: &CryptoProvider) -> Result<Credentials, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.client_key())?;
        let public_key = private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))?
            .into_owned();
        Ok(Credentials::new_unchecked(
            Arc::new(Identity::RawPublicKey(public_key)),
            private_key,
        ))
    }

    pub fn credentials_with_raw_pub_key(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Credentials, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.key())?;
        let public_key = private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))?
            .into_owned();
        Ok(Credentials::new_unchecked(
            Arc::new(Identity::RawPublicKey(public_key)),
            private_key,
        ))
    }

    pub fn credentials_with_cert_chain(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Credentials, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(self.key())?;
        Credentials::new(self.identity(), private_key)
    }

    fn crl(&self, role: &str, r#type: &str) -> CertificateRevocationListDer<'static> {
        CertificateRevocationListDer::from_pem_slice(
            self.bytes_for(&format!("{role}.{type}.crl.pem")),
        )
        .unwrap()
    }

    pub fn ca_distinguished_name(&self) -> DistinguishedName {
        match self {
            Self::Rsa2048 => &b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 2048 CA"[..],
            Self::Rsa3072 => b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 3072 CA",
            Self::Rsa4096 => b"0\x1f1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14ponytown RSA 4096 CA",
            Self::EcdsaP256 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p256 CA",
            Self::EcdsaP384 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p384 CA",
            Self::EcdsaP521 => b"0\x211\x1f0\x1d\x06\x03U\x04\x03\x0c\x16ponytown ECDSA p521 CA",
            Self::Ed25519 => b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown EdDSA CA",
        }
        .to_vec()
        .into()
    }

    pub fn client_root_store(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_cert()).unwrap();
        roots.into()
    }

    pub fn ca_cert(&self) -> CertificateDer<'_> {
        let Identity::X509(id) = &*self.identity() else {
            panic!("expected raw key identity");
        };

        id.intermediates
            .iter()
            .next_back()
            .cloned()
            .expect("cert chain cannot be empty")
    }
}

pub trait ServerConfigExt {
    fn finish(self, kt: KeyType) -> ServerConfig;
}

impl ServerConfigExt for ConfigBuilder<ServerConfig, WantsVerifier> {
    fn finish(self, kt: KeyType) -> ServerConfig {
        self.with_no_client_auth()
            .with_single_cert(kt.identity(), kt.key())
            .unwrap()
    }
}

pub fn make_server_config(kt: KeyType, provider: &CryptoProvider) -> ServerConfig {
    ServerConfig::builder(provider.clone().into()).finish(kt)
}

pub fn make_server_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
    provider: &CryptoProvider,
) -> ServerConfig {
    ServerConfig::builder(
        CryptoProvider {
            kx_groups: Cow::Owned(kx_groups),
            ..provider.clone()
        }
        .into(),
    )
    .finish(kt)
}

pub fn make_server_config_with_mandatory_client_auth_crls(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
    provider: &CryptoProvider,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(kt.client_root_store(), provider).with_crls(crls),
        provider,
    )
}

pub fn make_server_config_with_mandatory_client_auth(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(kt.client_root_store(), provider),
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
        webpki_client_verifier_builder(kt.client_root_store(), provider)
            .with_crls(crls)
            .allow_unknown_revocation_status()
            .allow_unauthenticated(),
        provider,
    )
}

pub fn make_server_config_with_client_verifier(
    kt: KeyType,
    verifier_builder: ClientVerifierBuilder,
    provider: &CryptoProvider,
) -> ServerConfig {
    ServerConfig::builder(provider.clone().into())
        .with_client_cert_verifier(Arc::new(verifier_builder.build().unwrap()))
        .with_single_cert(kt.identity(), kt.key())
        .unwrap()
}

pub fn make_server_config_with_raw_key_support(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ServerConfig {
    let mut client_verifier =
        MockClientVerifier::new(|| Ok(PeerVerified::assertion()), kt, provider);
    let server_cert_resolver = Arc::new(SingleCredential::from(
        kt.credentials_with_raw_pub_key(provider)
            .unwrap(),
    ));
    client_verifier.expect_raw_public_keys = true;
    // We don't support tls1.2 for Raw Public Keys, hence the version is hard-coded.
    ServerConfig::builder(provider.clone().into())
        .with_client_cert_verifier(Arc::new(client_verifier))
        .with_server_credential_resolver(server_cert_resolver)
        .unwrap()
}

pub fn make_client_config_with_raw_key_support(
    kt: KeyType,
    provider: &CryptoProvider,
) -> ClientConfig {
    let server_verifier = Arc::new(MockServerVerifier::expects_raw_public_keys(provider));
    let client_cert_resolver = Arc::new(SingleCredential::from(
        kt.certified_client_key(provider)
            .unwrap(),
    ));
    // We don't support tls1.2 for Raw Public Keys, hence the version is hard-coded.
    ClientConfig::builder(provider.clone().into())
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_credential_resolver(client_cert_resolver)
        .unwrap()
}

pub trait ClientConfigExt {
    fn finish(self, kt: KeyType) -> ClientConfig;
    fn finish_with_creds(self, kt: KeyType) -> ClientConfig;
    fn add_root_certs(self, kt: KeyType) -> ConfigBuilder<ClientConfig, WantsClientCert>;
}

impl ClientConfigExt for ConfigBuilder<ClientConfig, WantsVerifier> {
    fn finish(self, kt: KeyType) -> ClientConfig {
        self.add_root_certs(kt)
            .with_no_client_auth()
            .unwrap()
    }

    fn finish_with_creds(self, kt: KeyType) -> ClientConfig {
        self.add_root_certs(kt)
            .with_client_auth_cert(kt.client_identity(), kt.client_key())
            .unwrap()
    }

    fn add_root_certs(self, kt: KeyType) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            CertificateDer::pem_slice_iter(kt.bytes_for("ca.cert")).map(|result| result.unwrap()),
        );

        self.with_root_certificates(root_store)
    }
}

pub fn make_client_config(kt: KeyType, provider: &CryptoProvider) -> ClientConfig {
    ClientConfig::builder(provider.clone().into()).finish(kt)
}

pub fn make_client_config_with_kx_groups(
    kt: KeyType,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
    provider: &CryptoProvider,
) -> ClientConfig {
    ClientConfig::builder(
        CryptoProvider {
            kx_groups: Cow::Owned(kx_groups),
            ..provider.clone()
        }
        .into(),
    )
    .finish(kt)
}

pub fn make_client_config_with_auth(kt: KeyType, provider: &CryptoProvider) -> ClientConfig {
    ClientConfig::builder(provider.clone().into()).finish_with_creds(kt)
}

pub fn make_client_config_with_verifier(
    verifier_builder: ServerVerifierBuilder,
    provider: &CryptoProvider,
) -> ClientConfig {
    ClientConfig::builder(provider.clone().into())
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier_builder.build().unwrap()))
        .with_no_client_auth()
        .unwrap()
}

pub fn webpki_client_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ClientVerifierBuilder {
    WebPkiClientVerifier::builder(roots, provider)
}

pub fn webpki_server_verifier_builder(
    roots: Arc<RootCertStore>,
    provider: &CryptoProvider,
) -> ServerVerifierBuilder {
    WebPkiServerVerifier::builder(roots, provider)
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
        client_config
            .connect(server_name("localhost"))
            .build()
            .unwrap(),
        ServerConnection::new(server_config.clone()).unwrap(),
    )
}

/// Return a client and server config that don't share a common cipher suite
pub fn make_disjoint_suite_configs(provider: CryptoProvider) -> (ClientConfig, ServerConfig) {
    let kt = KeyType::Rsa2048;
    let client_provider = CryptoProvider {
        tls13_cipher_suites: provider
            .tls13_cipher_suites
            .iter()
            .copied()
            .filter(|cs| cs.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256)
            .collect(),
        ..provider.clone()
    };
    let server_config = ServerConfig::builder(client_provider.into()).finish(kt);

    let server_provider = CryptoProvider {
        tls13_cipher_suites: provider
            .tls13_cipher_suites
            .iter()
            .copied()
            .filter(|cs| cs.common.suite == CipherSuite::TLS13_AES_256_GCM_SHA384)
            .collect(),
        ..provider
    };
    let client_config = ClientConfig::builder(server_provider.into()).finish(kt);

    (client_config, server_config)
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

pub fn do_handshake_altered(
    client: ClientConnection,
    alter_server_message: impl Fn(&mut EncodedMessage<Vec<u8>>) -> Altered,
    alter_client_message: impl Fn(&mut EncodedMessage<Vec<u8>>) -> Altered,
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
        match self.writes.pop() {
            None => Err(io::ErrorKind::WouldBlock.into()),
            Some(n) => Ok(core::cmp::min(n, buf.len())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
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

impl ServerVerifier for MockServerVerifier {
    fn verify_identity(&self, identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        println!("verify_identity({identity:?})");
        if let Some(expected_ocsp) = &self.expected_ocsp_response {
            assert_eq!(expected_ocsp, identity.ocsp_response);
        }
        match &self.cert_rejection_error {
            Some(error) => Err(error.clone()),
            _ => Ok(PeerVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!("verify_tls12_signature({input:?})");
        match &self.tls12_signature_error {
            Some(error) => Err(error.clone()),
            _ => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        println!("verify_tls13_signature({input:?})");
        match &self.tls13_signature_error {
            Some(error) => Err(error.clone()),
            _ if self.requires_raw_public_keys => verify_tls13_signature(
                input,
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

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        match self.requires_raw_public_keys {
            false => &[CertificateType::X509],
            true => &[CertificateType::RawPublicKey],
        }
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
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
    pub verified: fn() -> Result<PeerVerified, Error>,
    pub subjects: Arc<[DistinguishedName]>,
    pub mandatory: bool,
    pub offered_schemes: Option<Vec<SignatureScheme>>,
    expect_raw_public_keys: bool,
    raw_public_key_algorithms: Option<WebPkiSupportedAlgorithms>,
    parent: Arc<dyn ClientVerifier>,
}

impl MockClientVerifier {
    pub fn new(
        verified: fn() -> Result<PeerVerified, Error>,
        kt: KeyType,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            parent: Arc::new(
                webpki_client_verifier_builder(kt.client_root_store(), provider)
                    .build()
                    .unwrap(),
            ),
            verified,
            subjects: Arc::from(kt.client_root_store().subjects()),
            mandatory: true,
            offered_schemes: None,
            expect_raw_public_keys: false,
            raw_public_key_algorithms: Some(provider.signature_verification_algorithms),
        }
    }
}

impl ClientVerifier for MockClientVerifier {
    fn verify_identity(&self, _identity: &ClientIdentity<'_>) -> Result<PeerVerified, Error> {
        (self.verified)()
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        if self.expect_raw_public_keys {
            Ok(HandshakeSignatureValid::assertion())
        } else {
            self.parent
                .verify_tls12_signature(input)
        }
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        if self.expect_raw_public_keys {
            verify_tls13_signature(
                input,
                self.raw_public_key_algorithms
                    .as_ref()
                    .unwrap(),
            )
        } else {
            self.parent
                .verify_tls13_signature(input)
        }
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        self.subjects.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        if let Some(schemes) = &self.offered_schemes {
            schemes.clone()
        } else {
            self.parent.supported_verify_schemes()
        }
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        match self.expect_raw_public_keys {
            false => &[CertificateType::X509],
            true => &[CertificateType::RawPublicKey],
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
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
                | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
                | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
                SupportedCipherSuite::Tls13(tls13),
            ) => tls13.aead_alg.encrypter(key, iv),

            (
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
                | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
                | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
                SupportedCipherSuite::Tls12(tls12),
            ) => tls12
                .aead_alg
                .encrypter(key, &iv.as_ref()[..4], &iv.as_ref()[4..]),

            _ => todo!(),
        };

        let decrypter = match (rx_keys, suite) {
            (
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
                | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
                | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
                SupportedCipherSuite::Tls13(tls13),
            ) => tls13.aead_alg.decrypter(key, iv),

            (
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
                | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
                | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
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
        msg: &EncodedMessage<Payload<'_>>,
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
        f: impl Fn(EncodedMessage<&[u8]>),
    ) {
        let mut data = vec![];
        peer.write_tls(&mut io::Cursor::new(&mut data))
            .unwrap();

        // Parse TLS record header: 1 byte type, 2 bytes version, 2 bytes length
        assert!(data.len() >= 5, "incomplete TLS record header");
        let typ = ContentType::from(data[0]);
        let version = ProtocolVersion::from(u16::from_be_bytes([data[1], data[2]]));
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let left = &mut data[5..];
        assert_eq!(len, left.len());

        let inbound = EncodedMessage {
            typ,
            version,
            payload: InboundOpaque(left),
        };

        let msg = self
            .decrypter
            .decrypt(inbound, self.dec_seq)
            .unwrap();
        self.dec_seq += 1;

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
            .tls13_cipher_suites
            .iter()
            .find(|cs| cs.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256)
            .unwrap();

        rustls::Tls13CipherSuite {
            common: rustls::crypto::CipherSuiteCommon {
                confidentiality_limit: CONFIDENTIALITY_LIMIT,
                ..tls13.common
            },
            ..**tls13
        }
    });

    let tls12_limited = TLS12_LIMITED_SUITE.get_or_init(|| {
        let tls12 = provider
            .tls12_cipher_suites
            .iter()
            .find(|cs| cs.common.suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            .unwrap();

        rustls::Tls12CipherSuite {
            common: rustls::crypto::CipherSuiteCommon {
                confidentiality_limit: CONFIDENTIALITY_LIMIT,
                ..tls12.common
            },
            ..**tls12
        }
    });

    CryptoProvider {
        tls12_cipher_suites: Cow::Owned(vec![tls12_limited]),
        tls13_cipher_suites: Cow::Owned(vec![tls13_limited]),
        ..provider
    }
    .into()
}

pub fn unsafe_plaintext_crypto_provider(provider: CryptoProvider) -> Arc<CryptoProvider> {
    static TLS13_PLAIN_SUITE: OnceLock<rustls::Tls13CipherSuite> = OnceLock::new();

    let tls13 = TLS13_PLAIN_SUITE.get_or_init(|| {
        let tls13 = provider
            .tls13_cipher_suites
            .iter()
            .find(|cs| cs.common.suite == CipherSuite::TLS13_AES_256_GCM_SHA384)
            .unwrap();

        rustls::Tls13CipherSuite {
            aead_alg: &plaintext::Aead,
            common: rustls::crypto::CipherSuiteCommon { ..tls13.common },
            ..**tls13
        }
    });

    CryptoProvider {
        tls13_cipher_suites: Cow::Owned(vec![tls13]),
        ..provider
    }
    .into()
}

#[derive(Default, Debug)]
pub struct ServerCheckCertResolve {
    pub expected_sni: Option<DnsName<'static>>,
    pub expected_sigalgs: Option<Vec<SignatureScheme>>,
    pub expected_alpn: Option<Vec<Vec<u8>>>,
    pub expected_cipher_suites: Option<Vec<CipherSuite>>,
    pub expected_server_cert_types: Option<Vec<CertificateType>>,
    pub expected_client_cert_types: Option<Vec<CertificateType>>,
    pub expected_named_groups: Option<Vec<NamedGroup>>,
}

impl ServerCredentialResolver for ServerCheckCertResolve {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        if client_hello
            .signature_schemes()
            .is_empty()
        {
            panic!("no signature schemes shared by client");
        }

        if client_hello.cipher_suites().is_empty() {
            panic!("no cipher suites shared by client");
        }

        if let Some(expected_sni) = &self.expected_sni {
            let sni = client_hello
                .server_name()
                .expect("sni unexpectedly absent");
            assert_eq!(expected_sni, sni);
        }

        if let Some(expected_sigalgs) = &self.expected_sigalgs {
            assert_eq!(
                expected_sigalgs,
                client_hello.signature_schemes(),
                "unexpected signature schemes"
            );
        }

        if let Some(expected_alpn) = &self.expected_alpn {
            let alpn = client_hello
                .alpn()
                .expect("alpn unexpectedly absent")
                .collect::<Vec<_>>();
            assert_eq!(alpn.len(), expected_alpn.len());

            for (got, wanted) in alpn.iter().zip(expected_alpn.iter()) {
                assert_eq!(got, &wanted.as_slice());
            }
        }

        if let Some(expected_cipher_suites) = &self.expected_cipher_suites {
            assert_eq!(
                expected_cipher_suites,
                client_hello.cipher_suites(),
                "unexpected cipher suites"
            );
        }

        if let Some(expected_server_cert) = &self.expected_server_cert_types {
            assert_eq!(
                expected_server_cert,
                client_hello
                    .server_cert_types()
                    .expect("Server cert types not present"),
                "unexpected server cert"
            );
        }

        if let Some(expected_client_cert) = &self.expected_client_cert_types {
            assert_eq!(
                expected_client_cert,
                client_hello
                    .client_cert_types()
                    .expect("Client cert types not present"),
                "unexpected client cert"
            );
        }

        if let Some(expected_named_groups) = &self.expected_named_groups {
            assert_eq!(
                expected_named_groups,
                client_hello
                    .named_groups()
                    .expect("Named groups not present"),
            )
        }

        Err(Error::NoSuitableCertificate)
    }
}

pub struct OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    sess: &'a mut C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<Error>,
    pub buffered: bool,
    buffer: Vec<Vec<u8>>,
}

impl<'a, C, S> OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    pub fn new(sess: &'a mut C) -> Self {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
            buffered: false,
            buffer: vec![],
        }
    }

    pub fn new_buffered(sess: &'a mut C) -> Self {
        let mut os = OtherSession::new(sess);
        os.buffered = true;
        os
    }

    pub fn new_fails(sess: &'a mut C) -> Self {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }

    fn flush_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = self.sess.process_new_packets();
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

impl<C, S> io::Read for OtherSession<'_, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(&mut b)
    }
}

impl<C, S> io::Write for OtherSession<'_, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buffer = mem::take(&mut self.buffer);
            let slices = buffer
                .iter()
                .map(|b| io::IoSlice::new(b))
                .collect::<Vec<_>>();
            self.flush_vectored(&slices)?;
        }
        Ok(())
    }

    fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if self.buffered {
            self.buffer
                .extend(b.iter().map(|s| s.to_vec()));
            return Ok(b.iter().map(|s| s.len()).sum());
        }
        self.flush_vectored(b)
    }
}

/// Check `reader` has available exactly `bytes`
pub fn check_read(reader: &mut dyn io::Read, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read(&mut buf).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}

/// Check `reader has available exactly `bytes`, followed by EOF
pub fn check_read_and_close(reader: &mut dyn io::Read, expect: &[u8]) {
    check_read(reader, expect);
    assert!(matches!(reader.read(&mut [0u8; 5]), Ok(0)));
}

/// Check `reader` yields only an error of kind `err_kind`
pub fn check_read_err(reader: &mut dyn io::Read, err_kind: io::ErrorKind) {
    let mut buf = vec![0u8; 1];
    let err = reader.read(&mut buf).unwrap_err();
    assert!(matches!(err, err  if err.kind()  == err_kind))
}

/// Check `reader` has available exactly `bytes`
pub fn check_fill_buf(reader: &mut dyn io::BufRead, bytes: &[u8]) {
    let b = reader.fill_buf().unwrap();
    assert_eq!(b, bytes);
    let len = b.len();
    reader.consume(len);
}

/// Check `reader` yields only an error of kind `err_kind`
pub fn check_fill_buf_err(reader: &mut dyn io::BufRead, err_kind: io::ErrorKind) {
    let err = reader.fill_buf().unwrap_err();
    assert!(matches!(err, err if err.kind() == err_kind))
}

pub fn certificate_error_expecting_name(expected: &str) -> CertificateError {
    CertificateError::NotValidForNameContext {
        expected: ServerName::try_from(expected)
            .unwrap()
            .to_owned(),
        presented: vec![
            // ref. examples/internal/test_ca.rs
            r#"DnsName("testserver.com")"#.into(),
            r#"DnsName("second.testserver.com")"#.into(),
            r#"DnsName("localhost")"#.into(),
            "IpAddress(198.51.100.1)".into(),
            "IpAddress(2001:db8::1)".into(),
        ],
    }
}

mod plaintext {
    use rustls::ConnectionTrafficSecrets;
    use rustls::crypto::cipher::{
        AeadKey, InboundOpaque, Iv, MessageDecrypter, MessageEncrypter, OutboundOpaque,
        OutboundPlain, Tls13AeadAlgorithm, UnsupportedOperationError,
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
            msg: EncodedMessage<OutboundPlain<'_>>,
            _seq: u64,
        ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
            let mut payload = OutboundOpaque::with_capacity(msg.payload.len());
            payload.extend_from_chunks(&msg.payload);

            Ok(EncodedMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload,
            })
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len
        }
    }

    struct Decrypter;

    impl MessageDecrypter for Decrypter {
        fn decrypt<'a>(
            &mut self,
            msg: EncodedMessage<InboundOpaque<'a>>,
            _seq: u64,
        ) -> Result<EncodedMessage<&'a [u8]>, Error> {
            Ok(msg.into_plain_message())
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // complete mock, but not 100% used in tests
pub enum ClientStorageOp {
    SetKxHint(ClientSessionKey<'static>, NamedGroup),
    GetKxHint(ClientSessionKey<'static>, Option<NamedGroup>),
    SetTls12Session(ClientSessionKey<'static>),
    GetTls12Session(ClientSessionKey<'static>, bool),
    RemoveTls12Session(ClientSessionKey<'static>),
    InsertTls13Ticket(ClientSessionKey<'static>),
    TakeTls13Ticket(ClientSessionKey<'static>, bool),
}

pub struct ClientStorage {
    storage: Arc<dyn rustls::client::ClientSessionStore>,
    ops: Mutex<Vec<ClientStorageOp>>,
    alter_max_early_data_size: Option<(u32, u32)>,
}

impl ClientStorage {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(rustls::client::ClientSessionMemoryCache::new(1024)),
            ops: Mutex::new(Vec::new()),
            alter_max_early_data_size: None,
        }
    }

    pub fn alter_max_early_data_size(&mut self, expected: u32, altered: u32) {
        self.alter_max_early_data_size = Some((expected, altered));
    }

    pub fn ops(&self) -> Vec<ClientStorageOp> {
        self.ops.lock().unwrap().clone()
    }

    pub fn ops_and_reset(&self) -> Vec<ClientStorageOp> {
        mem::take(&mut self.ops.lock().unwrap())
    }
}

impl fmt::Debug for ClientStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(ops: {:?})", self.ops.lock().unwrap())
    }
}

impl rustls::client::ClientSessionStore for ClientStorage {
    fn set_kx_hint(&self, key: ClientSessionKey<'static>, group: NamedGroup) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetKxHint(key.clone(), group));
        self.storage.set_kx_hint(key, group)
    }

    fn kx_hint(&self, key: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        let rc = self.storage.kx_hint(key);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetKxHint(key.to_owned(), rc));
        rc
    }

    fn set_tls12_session(
        &self,
        key: ClientSessionKey<'static>,
        value: rustls::client::Tls12Session,
    ) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetTls12Session(key.clone()));
        self.storage
            .set_tls12_session(key, value)
    }

    fn tls12_session(&self, key: &ClientSessionKey<'_>) -> Option<rustls::client::Tls12Session> {
        let rc = self.storage.tls12_session(key);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetTls12Session(
                key.to_owned(),
                rc.is_some(),
            ));
        rc
    }

    fn remove_tls12_session(&self, key: &ClientSessionKey<'static>) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::RemoveTls12Session(key.clone()));
        self.storage.remove_tls12_session(key);
    }

    fn insert_tls13_ticket(&self, key: ClientSessionKey<'static>, mut value: Tls13Session) {
        if let Some((expected, desired)) = self.alter_max_early_data_size {
            value._reset_max_early_data_size(expected, desired);
        }

        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::InsertTls13Ticket(key.clone()));
        self.storage
            .insert_tls13_ticket(key, value);
    }

    fn take_tls13_ticket(&self, key: &ClientSessionKey<'static>) -> Option<Tls13Session> {
        let rc = self.storage.take_tls13_ticket(key);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::TakeTls13Ticket(key.clone(), rc.is_some()));
        rc
    }
}

pub fn provider_with_one_suite(
    provider: &CryptoProvider,
    suite: SupportedCipherSuite,
) -> CryptoProvider {
    provider_with_suites(provider, &[suite])
}

pub fn provider_with_suites(
    provider: &CryptoProvider,
    suites: &[SupportedCipherSuite],
) -> CryptoProvider {
    let mut tls12_cipher_suites = vec![];
    let mut tls13_cipher_suites = vec![];

    for suite in suites {
        match suite {
            SupportedCipherSuite::Tls12(suite) => {
                tls12_cipher_suites.push(*suite);
            }
            SupportedCipherSuite::Tls13(suite) => {
                tls13_cipher_suites.push(*suite);
            }
            _ => unreachable!(),
        }
    }
    CryptoProvider {
        tls12_cipher_suites: Cow::Owned(tls12_cipher_suites),
        tls13_cipher_suites: Cow::Owned(tls13_cipher_suites),
        ..provider.clone()
    }
}

pub mod macros {
    //! Macros that bring a provider into the current scope.
    //!
    //! The selected provider module is bound as `provider`; you can rely on this
    //! having the union of the public items common to the `rustls::crypto::ring`
    //! and `rustls::crypto::aws_lc_rs` modules.

    #[macro_export]
    macro_rules! provider_ring {
        () => {
            #[allow(unused_imports)]
            use rustls_ring as provider;
            #[allow(dead_code)]
            const fn provider_is_aws_lc_rs() -> bool {
                false
            }
            #[allow(dead_code)]
            const fn provider_is_ring() -> bool {
                true
            }
            #[allow(dead_code)]
            const fn provider_is_fips() -> rustls::pki_types::FipsStatus {
                rustls::pki_types::FipsStatus::Unvalidated
            }
            #[allow(dead_code)]
            const ALL_VERSIONS: [rustls::crypto::CryptoProvider; 2] = [
                provider::DEFAULT_TLS12_PROVIDER,
                provider::DEFAULT_TLS13_PROVIDER,
            ];
        };
    }

    #[macro_export]
    macro_rules! provider_aws_lc_rs {
        () => {
            #[allow(unused_imports)]
            use rustls_aws_lc_rs as provider;
            #[allow(dead_code)]
            const fn provider_is_aws_lc_rs() -> bool {
                true
            }
            #[allow(dead_code)]
            const fn provider_is_ring() -> bool {
                false
            }
            #[allow(dead_code)]
            const fn provider_is_fips() -> rustls::pki_types::FipsStatus {
                if cfg!(feature = "fips") {
                    rustls::pki_types::FipsStatus::Pending
                } else {
                    rustls::pki_types::FipsStatus::Unvalidated
                }
            }
            #[allow(dead_code)]
            const ALL_VERSIONS: [rustls::crypto::CryptoProvider; 2] = [
                provider::DEFAULT_TLS12_PROVIDER,
                provider::DEFAULT_TLS13_PROVIDER,
            ];
        };
    }
}

/// Deeply inefficient, test-only TLS encoding helpers
pub mod encoding {
    use rustls::crypto::kx::NamedGroup;
    use rustls::crypto::{CipherSuite, SignatureScheme};
    use rustls::enums::{ContentType, HandshakeType, ProtocolVersion};
    use rustls::error::AlertDescription;

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

        out.extend_from_slice(&legacy_version.to_array());
        out.extend_from_slice(random);
        out.extend_from_slice(session_id);
        out.extend(len_u16(vector_of(
            cipher_suites
                .into_iter()
                .map(|cs| cs.to_array()),
        )));
        out.extend_from_slice(&[0x01, 0x00]); // only null compression

        let mut exts = vec![];
        for e in extensions {
            exts.extend_from_slice(&e.typ.to_be_bytes());
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
        pub typ: u16,
        pub body: Vec<u8>,
    }

    impl Extension {
        pub fn new_sig_algs() -> Self {
            Self {
                typ: Self::SIGNATURE_ALGORITHMS,
                body: len_u16(vector_of(
                    [
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                    ]
                    .map(|s| s.to_array()),
                )),
            }
        }

        pub fn new_kx_groups() -> Self {
            Self {
                typ: Self::ELLIPTIC_CURVES,
                body: len_u16(vector_of([NamedGroup::secp256r1.to_array()])),
            }
        }

        pub fn new_versions() -> Self {
            Self {
                typ: Self::SUPPORTED_VERSIONS,
                body: len_u8(vector_of(
                    [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2].map(|v| v.to_array()),
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
                typ: Self::KEY_SHARE,
                body: len_u16(share),
            }
        }

        pub fn new_quic_transport_params(body: &[u8]) -> Self {
            Self {
                typ: Self::TRANSPORT_PARAMETERS,
                body: len_u16(body.to_vec()),
            }
        }

        pub const ELLIPTIC_CURVES: u16 = 0x000a;
        pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
        pub const SUPPORTED_VERSIONS: u16 = 0x002b;
        pub const KEY_SHARE: u16 = 0x0033;
        pub const TRANSPORT_PARAMETERS: u16 = 0x0039;
    }

    /// Return a full TLS message containing a fatal alert.
    pub fn alert(desc: AlertDescription, suffix: &[u8]) -> Vec<u8> {
        let mut body = vec![ALERT_LEVEL_FATAL, desc.into()];
        body.extend_from_slice(suffix);
        message_framing(ContentType::Alert, ProtocolVersion::TLSv1_2, body)
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
    pub fn vector_of<const N: usize>(items: impl IntoIterator<Item = [u8; N]>) -> Vec<u8> {
        items.into_iter().flatten().collect()
    }

    const ALERT_LEVEL_FATAL: u8 = 2;
}
