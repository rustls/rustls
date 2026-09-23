use alloc::boxed::Box;

use pki_types::FipsStatus;
use ring::aead;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaque, Iv, KeyBlockShape, Nonce, OutboundPlain, Record, RecordDecrypter,
    RecordEncrypter, Tls12AeadAlgorithm, UnsupportedOperationError,
    chacha20poly1305_decrypt_record, chacha20poly1305_encrypt_record,
    chacha20poly1305_encrypted_payload_len, gcm_decrypt_record, gcm_encrypt_record,
    gcm_encrypted_payload_len, gcm_iv,
};
use rustls::crypto::kx::KeyExchangeAlgorithm;
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::{CipherSuite, SignatureScheme};
use rustls::error::Error;
use rustls::version::TLS12_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls12CipherSuite};

/// The TLS1.2 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS12_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = ALL_TLS12_CIPHER_SUITES;

/// A list of all the TLS1.2 cipher suites supported by the rustls *ring* provider.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES128_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES256_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA384),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES128_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA256),
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES256_GCM,
    prf_provider: &PrfUsingHmac(&super::hmac::HMAC_SHA384),
};

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

pub(crate) static AES128_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_128_GCM);
pub(crate) static AES256_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_256_GCM);

pub(crate) struct GcmAlgorithm(&'static aead::Algorithm);

impl Tls12AeadAlgorithm for GcmAlgorithm {
    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn RecordDecrypter> {
        let dec_key =
            aead::LessSafeKey::new(aead::UnboundKey::new(self.0, dec_key.as_ref()).unwrap());

        let mut ret = GcmRecordDecrypter {
            dec_key,
            dec_salt: [0u8; 4],
        };

        debug_assert_eq!(dec_iv.len(), 4);
        ret.dec_salt.copy_from_slice(dec_iv);
        Box::new(ret)
    }

    fn encrypter(
        &self,
        enc_key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn RecordEncrypter> {
        let enc_key =
            aead::LessSafeKey::new(aead::UnboundKey::new(self.0, enc_key.as_ref()).unwrap());
        let iv = gcm_iv(write_iv, explicit);
        Box::new(GcmRecordEncrypter { enc_key, iv })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0.key_len(),
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = gcm_iv(write_iv, explicit);
        Ok(match self.0.key_len() {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => unreachable!(),
        })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

pub(crate) struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn decrypter(&self, dec_key: AeadKey, iv: &[u8]) -> Box<dyn RecordDecrypter> {
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, dec_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305RecordDecrypter {
            dec_key,
            dec_offset: Iv::new(iv).expect("IV length validated by key_block_shape"),
        })
    }

    fn encrypter(&self, enc_key: AeadKey, enc_iv: &[u8], _: &[u8]) -> Box<dyn RecordEncrypter> {
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, enc_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305RecordEncrypter {
            enc_key,
            enc_offset: Iv::new(enc_iv).expect("IV length validated by key_block_shape"),
        })
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
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(aead::NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv).expect("IV length validated by key_block_shape"),
        })
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated // not fips approved
    }
}

/// A `RecordEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmRecordEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

/// A `RecordDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmRecordDecrypter {
    dec_key: aead::LessSafeKey,
    dec_salt: [u8; 4],
}

impl RecordDecrypter for GcmRecordDecrypter {
    fn decrypt<'a>(
        &mut self,
        record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        gcm_decrypt_record(
            |nonce, aad, payload, ciphertext_position| {
                self.dec_key
                    .open_within(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload,
                        ciphertext_position..,
                    )
                    .map(|plaintext| 0..plaintext.len())
                    .map_err(|_| Error::DecryptError)
            },
            record,
            seq,
            self.dec_salt,
        )
    }
}

impl RecordEncrypter for GcmRecordEncrypter {
    fn encrypt<'a>(
        &mut self,
        msg: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());

        gcm_encrypt_record(
            |nonce, aad, payload| {
                self.enc_key
                    .seal_in_place_separate_tag(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload.as_mut(),
                    )
                    .map(|t| t.as_ref().into())
                    .map_err(|_| Error::EncryptError)
            },
            None::<fn(Nonce, [u8; _], &[u8], &mut [u8], &mut [u8]) -> Result<(), Error>>,
            msg,
            seq,
            &self.iv,
            total_len,
            out,
        )
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        gcm_encrypted_payload_len(payload_len, self.enc_key.algorithm().tag_len())
    }
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `Tls13RecordEncrypter`.
struct ChaCha20Poly1305RecordEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `Tls13RecordDecrypter`.
struct ChaCha20Poly1305RecordDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

impl RecordDecrypter for ChaCha20Poly1305RecordDecrypter {
    fn decrypt<'a>(
        &mut self,
        record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        chacha20poly1305_decrypt_record(
            |nonce, aad, payload| {
                self.dec_key
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload,
                    )
                    .map(|plaintext| plaintext.len())
                    .map_err(|_| Error::DecryptError)
            },
            record,
            seq,
            &self.dec_offset,
        )
    }
}

impl RecordEncrypter for ChaCha20Poly1305RecordEncrypter {
    fn encrypt<'a>(
        &mut self,
        msg: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());

        chacha20poly1305_encrypt_record(
            |nonce, aad, payload| {
                self.enc_key
                    .seal_in_place_separate_tag(
                        aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                        aead::Aad::from(aad),
                        payload.as_mut(),
                    )
                    .map(|t| t.as_ref().into())
                    .map_err(|_| Error::EncryptError)
            },
            None::<fn(Nonce, [u8; _], &[u8], &mut [u8], &mut [u8]) -> Result<(), Error>>,
            msg,
            seq,
            &self.enc_offset,
            total_len,
            out,
        )
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        chacha20poly1305_encrypted_payload_len(payload_len, self.enc_key.algorithm().tag_len())
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hmac::Hmac;
    use rustls::crypto::tls12::prf;

    use crate::hmac;

    // Below known answer tests come from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/

    #[test]
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect = include_bytes!("test-data/prf-result.1.bin");
        let mut output = [0u8; 100];

        prf(
            &mut output,
            &*hmac::HMAC_SHA256.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha512() {
        let secret = b"\xb0\x32\x35\x23\xc1\x85\x35\x99\x58\x4d\x88\x56\x8b\xbb\x05\xeb";
        let seed = b"\xd4\x64\x0e\x12\xe4\xbc\xdb\xfb\x43\x7f\x03\xe6\xae\x41\x8e\xe5";
        let label = b"test label";
        let expect = include_bytes!("test-data/prf-result.2.bin");
        let mut output = [0u8; 196];

        prf(
            &mut output,
            &*hmac::HMAC_SHA512.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha384() {
        let secret = b"\xb8\x0b\x73\x3d\x6c\xee\xfc\xdc\x71\x56\x6e\xa4\x8e\x55\x67\xdf";
        let seed = b"\xcd\x66\x5c\xf6\xa8\x44\x7d\xd6\xff\x8b\x27\x55\x5e\xdb\x74\x65";
        let label = b"test label";
        let expect = include_bytes!("test-data/prf-result.3.bin");
        let mut output = [0u8; 148];

        prf(
            &mut output,
            &*hmac::HMAC_SHA384.with_key(secret),
            label,
            seed,
        );
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }
}

#[cfg(all(test, bench))]
mod benchmarks {
    use rustls::crypto::hmac::Hmac;
    use rustls::crypto::tls12::prf;

    use crate::hmac;

    #[bench]
    fn bench_sha256(b: &mut test::Bencher) {
        let label = &b"extended master secret"[..];
        let seed = [0u8; 32];
        let key = &b"secret"[..];

        b.iter(|| {
            let mut out = [0u8; 48];
            prf(&mut out, &*hmac::HMAC_SHA256.with_key(key), &label, &seed);
            test::black_box(out);
        });
    }
}
