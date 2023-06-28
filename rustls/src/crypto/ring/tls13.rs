use crate::crypto;
use crate::crypto::cipher::{make_nonce, AeadKey, Iv, MessageDecrypter, MessageEncrypter};
use crate::enums::CipherSuite;
use crate::enums::ContentType;
use crate::enums::ProtocolVersion;
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};
use crate::tls13::Tls13AeadAlgorithm;
use crate::tls13::Tls13CipherSuite;
#[cfg(feature = "quic")]
use crate::{hkdf, quic};

use ring::aead;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &crypto::ring::hash::SHA256,
    },
    hmac_provider: &crypto::ring::hmac::HMAC_SHA256,
    aead_alg: &AeadChacha20Poly1305(RingAeadFactory(&ring::aead::CHACHA20_POLY1305)),
    #[cfg(feature = "quic")]
    confidentiality_limit: u64::MAX,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 36,
    #[cfg(feature = "quic")]
    quic: &RingQuicFactory(&ring::aead::CHACHA20_POLY1305, &ring::aead::quic::CHACHA20),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &crypto::ring::hash::SHA384,
        },
        hmac_provider: &crypto::ring::hmac::HMAC_SHA384,
        aead_alg: &AeadAes256Gcm(RingAeadFactory(&ring::aead::AES_256_GCM)),
        #[cfg(feature = "quic")]
        confidentiality_limit: 1 << 23,
        #[cfg(feature = "quic")]
        integrity_limit: 1 << 52,
        #[cfg(feature = "quic")]
        quic: &RingQuicFactory(&ring::aead::AES_256_GCM, &aead::quic::AES_256),
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &crypto::ring::hash::SHA256,
    },
    hmac_provider: &crypto::ring::hmac::HMAC_SHA256,
    aead_alg: &AeadAes128Gcm(RingAeadFactory(&ring::aead::AES_128_GCM)),
    #[cfg(feature = "quic")]
    confidentiality_limit: 1 << 23,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 52,
    #[cfg(feature = "quic")]
    quic: &RingQuicFactory(&ring::aead::AES_128_GCM, &aead::quic::AES_128),
};

struct Tls13MessageEncrypter {
    enc_key: ring::aead::LessSafeKey,
    iv: Iv,
}

struct Tls13MessageDecrypter {
    dec_key: ring::aead::LessSafeKey,
    iv: Iv,
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE: usize = 1 + 2 + 2;

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.iv, seq));
        let aad = make_tls13_aad(total_len);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        })
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error> {
        let payload = &mut msg.payload.0;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(make_nonce(&self.iv, seq));
        let aad = make_tls13_aad(payload.len());
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(payload);
        if msg.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.version = ProtocolVersion::TLSv1_3;
        Ok(msg.into_plain_message())
    }
}

struct RingAeadFactory(&'static ring::aead::Algorithm);

impl RingAeadFactory {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct AeadChacha20Poly1305(RingAeadFactory);

impl Tls13AeadAlgorithm for AeadChacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 32];
            k.copy_from_slice(key.as_ref());
            k
        };

        let iv = {
            let mut i = [0u8; 12];
            i.copy_from_slice(&iv.0);
            i
        };

        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

struct AeadAes128Gcm(RingAeadFactory);

impl Tls13AeadAlgorithm for AeadAes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 16];
            k.copy_from_slice(key.as_ref());
            k
        };

        let salt = {
            let mut s = [0u8; 4];
            s.copy_from_slice(&iv.0[..4]);
            s
        };

        let iv = {
            let mut i = [0u8; 8];
            i.copy_from_slice(&iv.0[4..]);
            i
        };

        ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv }
    }
}

struct AeadAes256Gcm(RingAeadFactory);

impl Tls13AeadAlgorithm for AeadAes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        let key = {
            let mut k = [0u8; 32];
            k.copy_from_slice(key.as_ref());
            k
        };

        let salt = {
            let mut s = [0u8; 4];
            s.copy_from_slice(&iv.0[..4]);
            s
        };

        let iv = {
            let mut i = [0u8; 8];
            i.copy_from_slice(&iv.0[4..]);
            i
        };

        ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv }
    }
}

#[cfg(feature = "quic")]
struct RingQuicFactory(&'static aead::Algorithm, &'static aead::quic::Algorithm);

#[cfg(feature = "quic")]
impl quic::Algorithm for RingQuicFactory {
    fn packet_key(
        &self,
        suite: &'static Tls13CipherSuite,
        expander: &hkdf::Expander,
        version: quic::Version,
    ) -> Box<dyn quic::PacketKey> {
        Box::new(super::quic::PacketKey::new(
            suite, expander, version, self.0,
        ))
    }

    fn header_protection_key(
        &self,
        expander: &hkdf::Expander,
        version: quic::Version,
    ) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(super::quic::HeaderProtectionKey::new(
            expander, version, self.1,
        ))
    }
}
