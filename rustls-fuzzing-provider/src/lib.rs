use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::{
    hash, tls12, tls13, CipherSuiteCommon, GetRandomFailed, KeyExchangeAlgorithm,
    WebPkiSupportedAlgorithms,
};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, PrivateKeyDer,
    SignatureVerificationAlgorithm,
};
use rustls::{
    crypto, server, sign, CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup,
    PeerMisbehaved, ProtocolVersion, RootCertStore, SignatureAlgorithm, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};
use webpki::alg_id;

/// This is a `CryptoProvider` that provides NO SECURITY and is for fuzzing only.
pub fn provider() -> crypto::CryptoProvider {
    crypto::CryptoProvider {
        cipher_suites: vec![TLS13_FUZZING_SUITE, TLS_FUZZING_SUITE],
        kx_groups: vec![&KeyExchangeGroup as &dyn crypto::SupportedKxGroup],
        signature_verification_algorithms: VERIFY_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

pub fn server_verifier() -> Arc<dyn ServerCertVerifier> {
    // we need one of these, but it doesn't matter what it is
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates([CertificateDer::from(
        &include_bytes!("../../test-ca/ecdsa-p256/inter.der")[..],
    )]);

    WebPkiServerVerifier::builder_with_provider(root_store.into(), provider().into())
        .build()
        .unwrap()
}

pub fn server_cert_resolver() -> Arc<dyn server::ResolvesServerCert> {
    let cert = CertificateDer::from(&include_bytes!("../../test-ca/ecdsa-p256/end.der")[..]);
    let certified_key = sign::CertifiedKey::new(vec![cert], Arc::new(SigningKey));
    Arc::new(DummyCert(certified_key.into()))
}

#[derive(Debug)]
struct DummyCert(Arc<sign::CertifiedKey>);

impl server::ResolvesServerCert for DummyCert {
    fn resolve(&self, _client_hello: server::ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Debug)]
struct Provider;

impl crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        for (out, value) in bytes
            .iter_mut()
            .zip(RAND.iter().cycle())
        {
            *out = *value;
        }
        Ok(())
    }
}

const RAND: &[u8] = b"Rand";

impl crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn sign::SigningKey>, Error> {
        Ok(Arc::new(SigningKey))
    }
}

static TLS13_FUZZING_SUITE: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::Unknown(0xff13),
        hash_provider: &Hash,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &tls13::HkdfUsingHmac(&Hmac),
    aead_alg: &Aead,
    quic: None,
});

static TLS_FUZZING_SUITE: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::Unknown(0xff12),
        hash_provider: &Hash,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &[SIGNATURE_SCHEME],
    prf_provider: &tls12::PrfUsingHmac(&Hmac),
    aead_alg: &Aead,
});

struct Hash;

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext)
    }

    fn hash(&self, _data: &[u8]) -> hash::Output {
        hash::Output::new(HASH_OUTPUT)
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::from(0xff)
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct HashContext;

impl hash::Context for HashContext {
    fn fork_finish(&self) -> hash::Output {
        self.fork().finish()
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext)
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(HASH_OUTPUT)
    }

    fn update(&mut self, _data: &[u8]) {}
}

const HASH_OUTPUT: &[u8] = b"HashHashHashHashHashHashHashHash";

struct Hmac;

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, _key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey)
    }

    fn hash_output_len(&self) -> usize {
        HASH_OUTPUT.len()
    }
}

struct HmacKey;

impl crypto::hmac::Key for HmacKey {
    fn sign_concat(&self, _first: &[u8], _middle: &[&[u8]], _last: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(HMAC_OUTPUT)
    }

    fn tag_len(&self) -> usize {
        HMAC_OUTPUT.len()
    }
}

const HMAC_OUTPUT: &[u8] = b"HmacHmacHmacHmacHmacHmacHmacHmac";

struct ActiveKeyExchange;

impl crypto::ActiveKeyExchange for ActiveKeyExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, Error> {
        match peer {
            KX_PEER_SHARE => Ok(crypto::SharedSecret::from(KX_SHARED_SECRET)),
            _ => Err(Error::from(PeerMisbehaved::InvalidKeyShare)),
        }
    }

    fn pub_key(&self) -> &[u8] {
        KX_PEER_SHARE
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::from(0xfe00)
    }
}

#[derive(Debug)]
struct KeyExchangeGroup;

impl crypto::SupportedKxGroup for KeyExchangeGroup {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, Error> {
        Ok(Box::new(ActiveKeyExchange))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(0xfe00)
    }
}

const KX_PEER_SHARE: &[u8] = b"KxPeerShareKxPeerShareKxPeerShare";
const KX_SHARED_SECRET: &[u8] = b"KxSharedSecretKxSharedSecret";

struct Aead;

impl Tls13AeadAlgorithm for Aead {
    fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher)
    }

    fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher)
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

impl Tls12AeadAlgorithm for Aead {
    fn encrypter(&self, _key: AeadKey, _iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12Cipher)
    }

    fn decrypter(&self, _key: AeadKey, _iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Cipher)
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Tls13Cipher;

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        for (p, mask) in payload
            .as_mut()
            .iter_mut()
            .zip(AEAD_MASK.iter().cycle())
        {
            *p ^= *mask;
        }

        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(AEAD_TAG);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AEAD_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut m.payload;

        let mut expected_tag = vec![];
        expected_tag.extend_from_slice(&seq.to_be_bytes());
        expected_tag.extend_from_slice(AEAD_TAG);

        if payload.len() < AEAD_OVERHEAD
            || payload.as_ref()[payload.len() - AEAD_OVERHEAD..] != expected_tag
        {
            return Err(Error::DecryptError);
        }

        payload.truncate(payload.len() - AEAD_OVERHEAD);

        for (p, mask) in payload
            .as_mut()
            .iter_mut()
            .zip(AEAD_MASK.iter().cycle())
        {
            *p ^= *mask;
        }

        m.into_tls13_unpadded_message()
    }
}

struct Tls12Cipher;

impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&m.payload);

        for (p, mask) in payload
            .as_mut()
            .iter_mut()
            .zip(AEAD_MASK.iter().cycle())
        {
            *p ^= *mask;
        }

        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(AEAD_TAG);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + AEAD_OVERHEAD
    }
}

impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut m.payload;

        let mut expected_tag = vec![];
        expected_tag.extend_from_slice(&seq.to_be_bytes());
        expected_tag.extend_from_slice(AEAD_TAG);

        if payload.len() < AEAD_OVERHEAD
            || payload.as_ref()[payload.len() - AEAD_OVERHEAD..] != expected_tag
        {
            return Err(Error::DecryptError);
        }

        payload.truncate(payload.len() - AEAD_OVERHEAD);

        for (p, mask) in payload
            .as_mut()
            .iter_mut()
            .zip(AEAD_MASK.iter().cycle())
        {
            *p ^= *mask;
        }

        Ok(m.into_plain_message())
    }
}

const AEAD_MASK: &[u8] = b"AeadMaskPattern";
const AEAD_TAG: &[u8] = b"AeadTagA";
const AEAD_OVERHEAD: usize = 16;

pub static VERIFY_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[VERIFY_ALGORITHM],
    mapping: &[(SIGNATURE_SCHEME, &[VERIFY_ALGORITHM])],
};

static VERIFY_ALGORITHM: &dyn SignatureVerificationAlgorithm = &VerifyAlgorithm;

#[derive(Debug)]
struct VerifyAlgorithm;

impl SignatureVerificationAlgorithm for VerifyAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }

    fn verify_signature(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match signature {
            SIGNATURE => Ok(()),
            _ => Err(InvalidSignature),
        }
    }
}

#[derive(Debug)]
pub struct SigningKey;

impl sign::SigningKey for SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn sign::Signer>> {
        match offered.contains(&SIGNATURE_SCHEME) {
            true => Some(Box::new(SigningKey)),
            false => None,
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl sign::Signer for SigningKey {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(SIGNATURE.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SIGNATURE_SCHEME
    }
}

const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
// extracted from cert
const SIGNATURE: &[u8] = &[
    48u8, 69, 2, 32, 11, 49, 87, 201, 222, 105, 47, 52, 194, 171, 246, 150, 240, 199, 213, 121, 77,
    195, 71, 91, 166, 33, 223, 173, 55, 134, 249, 113, 185, 139, 161, 151, 2, 33, 0, 162, 53, 205,
    227, 18, 175, 158, 210, 251, 138, 30, 135, 109, 203, 124, 52, 208, 103, 221, 35, 80, 88, 101,
    202, 111, 191, 169, 142, 119, 76, 116, 221,
];
