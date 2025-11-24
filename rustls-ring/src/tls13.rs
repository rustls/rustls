use alloc::boxed::Box;

use ring::hkdf::{self, KeyType};
use ring::{aead, hmac};
use rustls::crypto::CipherSuite;
use rustls::crypto::cipher::{
    AeadKey, EncodedMessage, InboundOpaque, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaque, OutboundPlainMessage, Payload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::error::Error;
use rustls::version::TLS13_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls13CipherSuite, crypto};

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        // ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &RingHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Chacha20Poly1305Aead(AeadAlgorithm(&aead::CHACHA20_POLY1305)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::CHACHA20_POLY1305,
        header_alg: &aead::quic::CHACHA20,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        confidentiality_limit: u64::MAX,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &RingHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
    aead_alg: &Aes256GcmAead(AeadAlgorithm(&aead::AES_256_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_256_GCM,
        header_alg: &aead::quic::AES_256,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &RingHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Aes128GcmAead(AeadAlgorithm(&aead::AES_128_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_128_GCM,
        header_alg: &aead::quic::AES_128,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> bool {
        false // chacha20poly1305 not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct Tls13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = OutboundOpaque::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).to_array()?);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(EncodedMessage {
            typ: ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            version: ProtocolVersion::TLSv1_2,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<Payload<'a>>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).to_array()?);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

struct RingHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for RingHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct RingHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for RingHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .unwrap();
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use rustls::crypto::tls13::{HkdfUsingHmac, expand};

    use super::Hkdf;
    use crate::hmac;

    struct ByteArray<const N: usize>([u8; N]);

    impl<const N: usize> From<[u8; N]> for ByteArray<N> {
        fn from(array: [u8; N]) -> Self {
            Self(array)
        }
    }

    /// Test cases from appendix A in the RFC, minus cases requiring SHA1.

    #[test]
    fn test_case_1() {
        let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
        let ikm = &[0x0b; 22];
        let salt = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: &[&[u8]] = &[
            &[0xf0, 0xf1, 0xf2],
            &[0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        ];

        let output: ByteArray<42> = expand(
            hkdf.extract_from_secret(Some(salt), ikm)
                .as_ref(),
            info,
        );

        assert_eq!(
            &output.0,
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
    }

    #[test]
    fn test_case_2() {
        let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();

        let output: ByteArray<82> = expand(
            hkdf.extract_from_secret(Some(&salt), &ikm)
                .as_ref(),
            &[&info],
        );

        assert_eq!(
            &output.0,
            &[
                0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
                0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
                0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
                0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
                0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87
            ]
        );
    }

    #[test]
    fn test_case_3() {
        let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
        let ikm = &[0x0b; 22];
        let salt = &[];
        let info = &[];

        let output: ByteArray<42> = expand(
            hkdf.extract_from_secret(Some(salt), ikm)
                .as_ref(),
            info,
        );

        assert_eq!(
            &output.0,
            &[
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8
            ]
        );
    }

    #[test]
    fn test_salt_not_provided() {
        // can't use test case 7, because we don't have (or want) SHA1.
        //
        // this output is generated with cryptography.io:
        //
        // >>> hkdf.HKDF(algorithm=hashes.SHA384(), length=96, salt=None, info=b"hello").derive(b"\x0b" * 40)

        let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA384);
        let ikm = &[0x0b; 40];
        let info = &[&b"hell"[..], &b"o"[..]];

        let output: ByteArray<96> = expand(
            hkdf.extract_from_secret(None, ikm)
                .as_ref(),
            info,
        );

        assert_eq!(
            &output.0,
            &[
                0xd5, 0x45, 0xdd, 0x3a, 0xff, 0x5b, 0x19, 0x46, 0xd4, 0x86, 0xfd, 0xb8, 0xd8, 0x88,
                0x2e, 0xe0, 0x1c, 0xc1, 0xa5, 0x48, 0xb6, 0x05, 0x75, 0xe4, 0xd7, 0x5d, 0x0f, 0x5f,
                0x23, 0x40, 0xee, 0x6c, 0x9e, 0x7c, 0x65, 0xd0, 0xee, 0x79, 0xdb, 0xb2, 0x07, 0x1d,
                0x66, 0xa5, 0x50, 0xc4, 0x8a, 0xa3, 0x93, 0x86, 0x8b, 0x7c, 0x69, 0x41, 0x6b, 0x3e,
                0x61, 0x44, 0x98, 0xb8, 0xc2, 0xfc, 0x82, 0x82, 0xae, 0xcd, 0x46, 0xcf, 0xb1, 0x47,
                0xdc, 0xd0, 0x69, 0x0d, 0x19, 0xad, 0xe6, 0x6c, 0x70, 0xfe, 0x87, 0x92, 0x04, 0xb6,
                0x82, 0x2d, 0x97, 0x7e, 0x46, 0x80, 0x4c, 0xe5, 0x76, 0x72, 0xb4, 0xb8
            ]
        );
    }

    #[test]
    fn test_output_length_bounds() {
        let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
        let ikm = &[];
        let info = &[];

        let mut output = [0u8; 32 * 255 + 1];
        assert!(
            hkdf.extract_from_secret(None, ikm)
                .expand_slice(info, &mut output)
                .is_err()
        );
    }
}
