use crate::crypto::cipher::{
    make_nonce, Iv, MessageDecrypter, MessageEncrypter, Tls12AeadAlgorithm,
};
use crate::enums::CipherSuite;
use crate::enums::ContentType;
use crate::enums::ProtocolVersion;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::codec;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};
use crate::tls12::Tls12CipherSuite;

use ring::aead;

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 12,
        aead_key_len: 32,
        explicit_nonce_len: 0,
        aead_alg: &ChaCha20Poly1305,
        hmac_provider: &super::hmac::HMAC_SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 12,
        aead_key_len: 32,
        explicit_nonce_len: 0,
        aead_alg: &ChaCha20Poly1305,
        hmac_provider: &super::hmac::HMAC_SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 4,
        aead_key_len: 16,
        explicit_nonce_len: 8,
        aead_alg: &Aes128Gcm,
        hmac_provider: &super::hmac::HMAC_SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 4,
        aead_key_len: 32,
        explicit_nonce_len: 8,
        aead_alg: &Aes256Gcm,
        hmac_provider: &super::hmac::HMAC_SHA384,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 4,
        aead_key_len: 16,
        explicit_nonce_len: 8,
        aead_alg: &Aes128Gcm,
        hmac_provider: &super::hmac::HMAC_SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 4,
        aead_key_len: 32,
        explicit_nonce_len: 8,
        aead_alg: &Aes256Gcm,
        hmac_provider: &super::hmac::HMAC_SHA384,
    });

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> aead::Aad<[u8; TLS12_AAD_SIZE]> {
    let mut out = [0; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.get_u8();
    codec::put_u16(vers.get_u16(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    ring::aead::Aad::from(out)
}

fn make_aesgcm_decrypter(
    dec_key: &[u8],
    dec_iv: &[u8],
    aead_alg: &'static aead::Algorithm,
) -> Box<dyn MessageDecrypter> {
    let dec_key = aead::LessSafeKey::new(aead::UnboundKey::new(aead_alg, dec_key).unwrap());

    let mut ret = GcmMessageDecrypter {
        dec_key,
        dec_salt: [0u8; 4],
    };

    debug_assert_eq!(dec_iv.len(), 4);
    ret.dec_salt.copy_from_slice(dec_iv);
    Box::new(ret)
}

fn make_aesgcm_encrypter(
    enc_key: &[u8],
    write_iv: &[u8],
    explicit: &[u8],
    aead_alg: &'static aead::Algorithm,
) -> Box<dyn MessageEncrypter> {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    let enc_key = aead::LessSafeKey::new(aead::UnboundKey::new(aead_alg, enc_key).unwrap());

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = Iv(Default::default());
    iv.0[..4].copy_from_slice(write_iv);
    iv.0[4..].copy_from_slice(explicit);

    Box::new(GcmMessageEncrypter { enc_key, iv })
}

pub(crate) struct Aes128Gcm;

impl Tls12AeadAlgorithm for Aes128Gcm {
    fn decrypter(&self, dec_key: &[u8], dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_aesgcm_decrypter(dec_key, dec_iv, &aead::AES_128_GCM)
    }

    fn encrypter(
        &self,
        enc_key: &[u8],
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        make_aesgcm_encrypter(enc_key, write_iv, explicit, &aead::AES_128_GCM)
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 16];
            k.copy_from_slice(key);
            k
        };

        let salt = {
            let mut s = [0u8; 4];
            s.copy_from_slice(iv);
            s
        };

        let iv = {
            let mut i = [0u8; 8];
            i.copy_from_slice(&explicit[..8]);
            i
        };

        ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv }
    }
}

pub(crate) struct Aes256Gcm;

impl Tls12AeadAlgorithm for Aes256Gcm {
    fn decrypter(&self, dec_key: &[u8], dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_aesgcm_decrypter(dec_key, dec_iv, &aead::AES_256_GCM)
    }

    fn encrypter(
        &self,
        enc_key: &[u8],
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        make_aesgcm_encrypter(enc_key, write_iv, explicit, &aead::AES_256_GCM)
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            k
        };

        let salt = {
            let mut s = [0u8; 4];
            s.copy_from_slice(iv);
            s
        };

        let iv = {
            let mut i = [0u8; 8];
            i.copy_from_slice(&explicit[..8]);
            i
        };

        ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv }
    }
}

pub(crate) struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn decrypter(&self, dec_key: &[u8], iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, dec_key).unwrap(),
        );
        Box::new(ChaCha20Poly1305MessageDecrypter {
            dec_key,
            dec_offset: Iv::copy(iv),
        })
    }

    fn encrypter(&self, enc_key: &[u8], enc_iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, enc_key).unwrap(),
        );
        Box::new(ChaCha20Poly1305MessageEncrypter {
            enc_key,
            enc_offset: Iv::copy(enc_iv),
        })
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], _explicit: &[u8]) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            k
        };

        let iv = {
            let mut i = [0u8; 12];
            i.copy_from_slice(iv);
            i
        };

        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmMessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.dec_salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload.len() - GCM_OVERHEAD);

        let plain_len = self
            .dec_key
            .open_within(nonce, aad, payload, GCM_EXPLICIT_NONCE_LEN..)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.iv, seq));
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + total_len);
        payload.extend_from_slice(&nonce.as_ref()[4..]);
        payload.extend_from_slice(msg.payload);

        self.enc_key
            .seal_in_place_separate_tag(nonce, aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..])
            .map(|tag| payload.extend(tag.as_ref()))
            .map_err(|_| Error::EncryptError)?;

        Ok(OpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::new(payload),
        })
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
struct ChaCha20Poly1305MessageEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
struct ChaCha20Poly1305MessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;

        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.dec_offset, seq));
        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.enc_offset, seq));
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let total_len = msg.payload.len() + self.enc_key.algorithm().tag_len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(msg.payload);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| Error::EncryptError)?;

        Ok(OpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload: Payload::new(buf),
        })
    }
}
