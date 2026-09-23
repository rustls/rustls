use alloc::boxed::Box;
use core::cell::RefCell;

use aws_lc_rs::aead::{LessSafeKey, TlsRecordOpeningKey, TlsRecordSealingKey};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::{aead, hkdf, hmac};
use pki_types::FipsStatus;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaque, Iv, Nonce, OutboundPlain, Record, RecordDecrypter, RecordEncrypter,
    Tls13AeadAlgorithm, UnsupportedOperationError, decrypt_record, encrypt_record,
    encrypted_payload_len,
};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::crypto::{self, CipherSuite};
use rustls::error::Error;
use rustls::version::TLS13_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls13CipherSuite};

/// The TLS1.3 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS13_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS13_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.3 cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        // ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
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
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
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
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
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
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Encrypter {
            seal_key: SealingKey::LessSafe(LessSafeKey::new(
                aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap(),
            )),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Decrypter {
            open_key: OpeningKey::LessSafe(LessSafeKey::new(
                aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap(),
            )),
            iv,
        })
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

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated // not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
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

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
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

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    // using aead::TlsRecordSealingKey
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(Encrypter {
            seal_key: SealingKey::TlsRecordSealing(
                TlsRecordSealingKey::new(self.0, aead::TlsProtocolId::TLS13, key.as_ref()).unwrap(),
            ),
            iv,
        })
    }

    // using aead::TlsRecordOpeningKey
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(Decrypter {
            open_key: OpeningKey::TlsRecordOpening(
                TlsRecordOpeningKey::new(self.0, aead::TlsProtocolId::TLS13, key.as_ref()).unwrap(),
            ),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

pub(crate) struct Decrypter {
    pub(crate) open_key: OpeningKey,
    pub(crate) iv: Iv,
}

impl RecordDecrypter for Decrypter {
    fn decrypt<'a>(
        &mut self,
        record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        let tag_len = self.open_key.algorithm().tag_len();
        decrypt_record(
            |nonce, aad, payload| {
                self.open_key
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload,
                    )
                    .map(|plaintext| plaintext.len())
                    .map_err(|_| Error::DecryptError)
            },
            tag_len,
            record,
            seq,
            &self.iv,
        )
    }
}

pub(crate) struct Encrypter {
    pub(crate) seal_key: SealingKey,
    pub(crate) iv: Iv,
}

impl RecordEncrypter for Encrypter {
    fn encrypt<'a>(
        &mut self,
        msg: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());

        // Use a RefCell so both closures can borrow seal_key mutably
        let seal_key = RefCell::new(&mut self.seal_key);

        encrypt_record(
            |nonce, aad, payload| {
                seal_key
                    .borrow_mut()
                    .seal_in_place_separate_tag(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload.as_mut(),
                    )
                    .map(|t| t.as_ref().into())
                    .map_err(|_| Error::EncryptError)
            },
            Some(
                |nonce: Nonce,
                 aad,
                 plaintext: &[u8],
                 ciphertext: &mut [u8],
                 extra_plain: &[u8],
                 extra_out_and_tag: &mut [u8]| {
                    seal_key
                        .borrow_mut()
                        .seal_out_of_place_scatter(
                            aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                            aead::Aad::from(aad),
                            plaintext,
                            ciphertext,
                            extra_plain,
                            extra_out_and_tag,
                        )
                        .map_err(|_| Error::EncryptError)
                },
            ),
            msg,
            seq,
            &self.iv,
            total_len,
            out,
        )
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        encrypted_payload_len(payload_len, self.seal_key.algorithm().tag_len())
    }
}

/// Key that can be used for opening TLS records.
///
/// This abstracts over different key types in aws-lc-rs so that we can use a single `Decrypter`
/// implementation for both AES-GCM and ChaCha20Poly1305.
pub(crate) enum OpeningKey {
    LessSafe(LessSafeKey),
    TlsRecordOpening(TlsRecordOpeningKey),
}

impl OpeningKey {
    fn open_in_place<'in_out, A>(
        &mut self,
        nonce: aead::Nonce,
        aad: aead::Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        match self {
            Self::LessSafe(k) => k.open_in_place(nonce, aad, in_out),
            Self::TlsRecordOpening(k) => k.open_in_place(nonce, aad, in_out),
        }
    }

    fn algorithm(&self) -> &'static aead::Algorithm {
        match self {
            Self::LessSafe(k) => k.algorithm(),
            Self::TlsRecordOpening(k) => k.algorithm(),
        }
    }
}

/// Key that can be used for sealing TLS records.
///
/// This abstracts over different key types in aws-lc-rs so that we can use a single `Encrypter`
/// implementation for both AES-GCM and ChaCha20Poly1305.
pub(crate) enum SealingKey {
    LessSafe(LessSafeKey),
    TlsRecordSealing(TlsRecordSealingKey),
}

impl SealingKey {
    fn seal_in_place_separate_tag<A>(
        &mut self,
        nonce: aead::Nonce,
        aad: aead::Aad<A>,
        in_out: &mut [u8],
    ) -> Result<aead::Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        match self {
            Self::LessSafe(k) => k.seal_in_place_separate_tag(nonce, aad, in_out),
            Self::TlsRecordSealing(k) => k.seal_in_place_separate_tag(nonce, aad, in_out),
        }
    }

    fn seal_out_of_place_scatter<A>(
        &mut self,
        nonce: aead::Nonce,
        aad: aead::Aad<A>,
        in_plaintext: &[u8],
        out_ciphertext: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        match self {
            Self::LessSafe(k) => k.seal_out_of_place_scatter(
                nonce,
                aad,
                in_plaintext,
                out_ciphertext,
                extra_in,
                extra_out_and_tag,
            ),
            Self::TlsRecordSealing(k) => k.seal_out_of_place_scatter(
                nonce,
                aad,
                in_plaintext,
                out_ciphertext,
                extra_in,
                extra_out_and_tag,
            ),
        }
    }

    fn algorithm(&self) -> &'static aead::Algorithm {
        match self {
            Self::LessSafe(k) => k.algorithm(),
            Self::TlsRecordSealing(k) => k.algorithm(),
        }
    }
}

struct AwsLcHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for AwsLcHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
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
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

struct AwsLcHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for AwsLcHkdfExpander {
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
    use std::vec;
    use std::vec::Vec;

    use rustls::crypto::cipher::{EncodableVersion, InboundOpaque};
    use rustls::enums::{ContentType, ProtocolVersion};

    use super::*;

    /// Test that contiguous plaintext and fragmented plaintext are handled identically.
    #[test]
    fn out_of_place_sealing_matches_in_place() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let chunks = [&plain[..3], &plain[3..27], &plain[27..]];

        for suite in ALL_TLS13_CIPHER_SUITES {
            // Different `fill` values prove both paths write every output byte.
            let contiguous = seal(suite, OutboundPlain::from(plain), 0x00);
            let fragmented = seal(suite, OutboundPlain::new(&chunks), 0xff);
            assert_eq!(contiguous, fragmented, "{:?}", suite.common.suite);
        }
    }

    /// Sealed records must open through the corresponding decrypter.
    #[test]
    fn sealed_records_open() {
        for suite in ALL_TLS13_CIPHER_SUITES {
            for plain in [&b""[..], b"hello"] {
                let mut sealed = seal(suite, OutboundPlain::from(plain), 0x00);
                let record = Record::new(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                    InboundOpaque(&mut sealed),
                );
                let mut decrypter = suite
                    .aead_alg
                    .decrypter(test_key(suite.aead_alg.key_len()), Iv::from(TEST_IV));
                let opened = decrypter
                    .decrypt(record, TEST_SEQ)
                    .unwrap();
                assert_eq!(opened.typ, ContentType::ApplicationData);
                assert_eq!(opened.payload, plain, "{:?}", suite.common.suite);
            }
        }
    }

    fn seal(suite: &Tls13CipherSuite, payload: OutboundPlain<'_>, fill: u8) -> Vec<u8> {
        let mut encrypter = suite
            .aead_alg
            .encrypter(test_key(suite.aead_alg.key_len()), Iv::from(TEST_IV));
        let record = Record::new(
            ContentType::ApplicationData,
            EncodableVersion::Legacy(ProtocolVersion::TLSv1_3),
            payload,
        );
        let mut out = vec![fill; encrypter.encrypted_payload_len(record.payload.len())];
        encrypter
            .encrypt(record, TEST_SEQ, &mut out)
            .unwrap()
            .payload
            .to_vec()
    }

    fn test_key(len: usize) -> AeadKey {
        match len {
            16 => AeadKey::from([0x22; 16]),
            _ => AeadKey::from([0x22; 32]),
        }
    }

    const TEST_IV: [u8; 12] = [0x55; 12];
    const TEST_SEQ: u64 = 7;
}
