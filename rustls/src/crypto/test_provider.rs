use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;
use std::borrow::Cow;

use crate::crypto::cipher::{
    AeadKey, EncodedMessage, InboundOpaque, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter,
    OutboundOpaque, OutboundPlain, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use crate::crypto::kx::{
    KeyExchangeAlgorithm, NamedGroup, SharedSecret, StartedKeyExchange, SupportedKxGroup,
};
use crate::crypto::{
    self, CipherSuite, CipherSuiteCommon, GetRandomFailed, HashAlgorithm, SignatureScheme,
    TicketProducer, WebPkiSupportedAlgorithms, hash, hmac, tls12, tls13,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::PeerMisbehaved;
use crate::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm,
    SubjectPublicKeyInfoDer, alg_id,
};
use crate::sync::Arc;
use crate::{ConnectionTrafficSecrets, Error, Tls12CipherSuite, Tls13CipherSuite};

/// This is a `CryptoProvider` that provides NO SECURITY and is for testing only.
#[cfg_attr(not(doc), expect(unreachable_pub))]
pub const TEST_PROVIDER: crypto::CryptoProvider = crypto::CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[TLS_TEST_SUITE]),
    tls13_cipher_suites: Cow::Borrowed(&[TLS13_TEST_SUITE]),
    kx_groups: Cow::Borrowed(&[KEY_EXCHANGE_GROUP]),
    signature_verification_algorithms: VERIFY_ALGORITHMS,
    secure_random: &Provider,
    key_provider: &Provider,
    ticketer_factory: &Provider,
};

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
    ) -> Result<Box<dyn crypto::SigningKey>, Error> {
        Ok(Box::new(SigningKey))
    }
}

impl crypto::TicketerFactory for Provider {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        Ok(Arc::new(Ticketer))
    }
}

pub(crate) const TLS13_TEST_SUITE: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::Unknown(0xff13),
        hash_provider: FAKE_HASH,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: crate::version::TLS13_VERSION,
    hkdf_provider: &tls13::HkdfUsingHmac(FAKE_HMAC),
    aead_alg: &Aead,
    quic: None,
};

const TLS_TEST_SUITE: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::Unknown(0xff12),
        hash_provider: FAKE_HASH,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: crate::version::TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &[SIGNATURE_SCHEME],
    prf_provider: &tls12::PrfUsingHmac(FAKE_HMAC),
    aead_alg: &Aead,
};

#[derive(Debug, Default)]
struct Ticketer;

impl TicketProducer for Ticketer {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        Some(plain.to_vec())
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        Some(cipher.to_vec())
    }

    fn lifetime(&self) -> Duration {
        Duration::from_secs(60 * 60 * 6)
    }
}

#[cfg(all(not(doc), any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) use hash_impl::SHA256;
pub(crate) use hash_impl::{FAKE_HASH, FAKE_HMAC};

#[cfg(all(not(doc), any(target_arch = "aarch64", target_arch = "x86_64")))]
mod hash_impl {
    use graviola::hashing::sha2::Sha256Context;
    use graviola::hashing::{Hash as _, HashContext as _};

    use super::*;

    pub(crate) const FAKE_HASH: &dyn hash::Hash = SHA256;
    pub(crate) const SHA256: &'static dyn hash::Hash = &graviola::hashing::Sha256;

    impl hash::Hash for graviola::hashing::Sha256 {
        fn start(&self) -> Box<dyn hash::Context> {
            Box::new(Sha256Context::new())
        }

        fn hash(&self, data: &[u8]) -> hash::Output {
            let mut cx = Self::new();
            cx.update(data);
            hash::Output::new(cx.finish().as_ref())
        }

        fn output_len(&self) -> usize {
            Sha256Context::OUTPUT_SZ
        }

        fn algorithm(&self) -> HashAlgorithm {
            HashAlgorithm::SHA256
        }
    }

    impl hash::Context for Sha256Context {
        fn fork_finish(&self) -> hash::Output {
            hash::Output::new(self.clone().finish().as_ref())
        }

        fn fork(&self) -> Box<dyn hash::Context> {
            Box::new(self.clone())
        }

        fn finish(self: Box<Self>) -> hash::Output {
            hash::Output::new((*self).finish().as_ref())
        }

        fn update(&mut self, data: &[u8]) {
            self.update(data);
        }
    }

    pub(crate) const FAKE_HMAC: &dyn hmac::Hmac = &Sha256Hmac;

    pub(super) struct Sha256Hmac;

    impl hmac::Hmac for Sha256Hmac {
        fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
            Box::new(Sha256HmacKey(graviola::hashing::hmac::Hmac::<
                graviola::hashing::Sha256,
            >::new(key)))
        }

        fn hash_output_len(&self) -> usize {
            Sha256Context::OUTPUT_SZ
        }
    }

    struct Sha256HmacKey(graviola::hashing::hmac::Hmac<graviola::hashing::Sha256>);

    impl hmac::Key for Sha256HmacKey {
        fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
            let mut ctx = self.0.clone();
            ctx.update(first);
            for m in middle {
                ctx.update(m);
            }
            ctx.update(last);
            hmac::Tag::new(ctx.finish().as_ref())
        }

        fn tag_len(&self) -> usize {
            Sha256Context::OUTPUT_SZ
        }
    }
}

#[cfg(any(doc, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod hash_impl {
    use super::*;

    pub(crate) const FAKE_HASH: &dyn hash::Hash = &Hash;

    pub(super) struct Hash;

    impl hash::Hash for Hash {
        fn start(&self) -> Box<dyn hash::Context> {
            Box::new(HashContext)
        }

        fn hash(&self, _data: &[u8]) -> hash::Output {
            hash::Output::new(HASH_OUTPUT)
        }

        fn algorithm(&self) -> HashAlgorithm {
            HashAlgorithm::from(0xff)
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
            Box::new(Self)
        }

        fn finish(self: Box<Self>) -> hash::Output {
            hash::Output::new(HASH_OUTPUT)
        }

        fn update(&mut self, _data: &[u8]) {}
    }

    const HASH_OUTPUT: &[u8] = b"HashHashHashHashHashHashHashHash";

    pub(crate) const FAKE_HMAC: &dyn hmac::Hmac = &Hmac;

    pub(super) struct Hmac;

    impl hmac::Hmac for Hmac {
        fn with_key(&self, _key: &[u8]) -> Box<dyn hmac::Key> {
            Box::new(HmacKey)
        }

        fn hash_output_len(&self) -> usize {
            HASH_OUTPUT.len()
        }
    }

    struct HmacKey;

    impl hmac::Key for HmacKey {
        fn sign_concat(&self, _first: &[u8], _middle: &[&[u8]], _last: &[u8]) -> hmac::Tag {
            hmac::Tag::new(HMAC_OUTPUT)
        }

        fn tag_len(&self) -> usize {
            HMAC_OUTPUT.len()
        }
    }

    const HMAC_OUTPUT: &[u8] = b"HmacHmacHmacHmacHmacHmacHmacHmac";
}

struct ActiveKeyExchange(NamedGroup);

impl crypto::kx::ActiveKeyExchange for ActiveKeyExchange {
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
        self.0
    }
}

const KEY_EXCHANGE_GROUP: &dyn SupportedKxGroup =
    &FakeKeyExchangeGroup(NamedGroup::Unknown(0xfe00));

#[derive(Debug)]
pub(crate) struct FakeKeyExchangeGroup(pub(crate) NamedGroup);

impl SupportedKxGroup for FakeKeyExchangeGroup {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        Ok(StartedKeyExchange::Single(Box::new(ActiveKeyExchange(
            self.0,
        ))))
    }

    fn name(&self) -> NamedGroup {
        self.0
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
        16
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
        m: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = OutboundOpaque::with_capacity(total_len);

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

        Ok(EncodedMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AEAD_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
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
        m: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = OutboundOpaque::with_capacity(total_len);
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

        Ok(EncodedMessage {
            typ: m.typ,
            version: m.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + AEAD_OVERHEAD
    }
}

impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
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

static VERIFY_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
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
struct SigningKey;

impl crypto::SigningKey for SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn crypto::Signer>> {
        match offered.contains(&SIGNATURE_SCHEME) {
            true => Some(Box::new(Self)),
            false => None,
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(SUBJECT_PUBLIC_KEY_INFO_DER))
    }
}

const SUBJECT_PUBLIC_KEY_INFO_DER: &[u8] = &[
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66,
    0, 4, 179, 82, 178, 210, 233, 245, 65, 87, 222, 175, 222, 238, 202, 123, 3, 223, 151, 55, 26,
    185, 76, 2, 57, 106, 210, 52, 118, 214, 156, 243, 103, 157, 241, 100, 226, 121, 64, 29, 33,
    156, 232, 118, 42, 168, 148, 123, 58, 120, 149, 133, 68, 119, 106, 127, 181, 109, 58, 72, 39,
    17, 103, 222, 144, 46,
];

impl crypto::Signer for SigningKey {
    fn sign(self: Box<Self>, _message: &[u8]) -> Result<Vec<u8>, Error> {
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
