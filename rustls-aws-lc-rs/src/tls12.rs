use alloc::boxed::Box;

use aws_lc_rs::{aead, tls_prf};
use pki_types::FipsStatus;
use rustls::crypto::cipher::{
    AeadKey, EncodedMessage, EncryptBuffer, InboundOpaque, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, NONCE_LEN, Nonce, OutboundPlain, Tls12AeadAlgorithm,
    UnsupportedOperationError, make_tls12_aad,
};
use rustls::crypto::kx::{ActiveKeyExchange, KeyExchangeAlgorithm, SharedSecret};
use rustls::crypto::tls12::{Prf, PrfSecret};
use rustls::crypto::{CipherSuite, SignatureScheme};
use rustls::enums::ProtocolVersion;
use rustls::error::Error;
use rustls::version::TLS12_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls12CipherSuite};
use zeroize::Zeroizing;

use crate::{MAX_FRAGMENT_LEN, record_region};

/// The TLS1.2 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS12_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.2 cipher suites supported by the rustls aws-lc-rs provider.
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
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES128_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES256_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES128_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES256_GCM,
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
    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // safety: see `encrypter()`.
        let dec_key =
            aead::TlsRecordOpeningKey::new(self.0, aead::TlsProtocolId::TLS12, dec_key.as_ref())
                .unwrap();

        let mut ret = GcmMessageDecrypter {
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
    ) -> Box<dyn MessageEncrypter> {
        // safety: `TlsRecordSealingKey::new` fails if
        // - `enc_key`'s length is wrong for `algorithm`.  But the length is defined by
        //   `algorithm.key_len()` in `key_block_shape()`, below.
        // - `algorithm` is not supported: but `AES_128_GCM` and `AES_256_GCM` is.
        // thus, this `unwrap()` is unreachable.
        //
        // `TlsProtocolId::TLS13` is deliberate: we reuse the nonce construction from
        // RFC 7905 and TLS13: a random starting point, XOR'd with the sequence number.  This means
        // `TlsProtocolId::TLS12` (which wants to see a plain sequence number) is unsuitable.
        //
        // The most important property is that nonce is unique per key, which is satisfied by
        // this construction, even if the nonce is not monotonically increasing.
        let enc_key =
            aead::TlsRecordSealingKey::new(self.0, aead::TlsProtocolId::TLS13, enc_key.as_ref())
                .unwrap();
        let iv = gcm_iv(write_iv, explicit);
        Box::new(GcmMessageEncrypter { enc_key, iv })
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
    fn decrypter(&self, dec_key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, dec_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305MessageDecrypter {
            dec_key,
            dec_offset: Iv::new(iv).expect("IV length validated by key_block_shape"),
        })
    }

    fn encrypter(&self, enc_key: AeadKey, enc_iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, enc_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305MessageEncrypter {
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
        FipsStatus::Unvalidated // not FIPS approved
    }
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmMessageEncrypter {
    enc_key: aead::TlsRecordSealingKey,
    iv: Iv,
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmMessageDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let payload = &msg.payload;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.dec_salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version.version(),
            payload.len() - GCM_OVERHEAD,
        ));

        let payload = &mut msg.payload;
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..])
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        Ok(
            msg.into_plain_message_range(
                GCM_EXPLICIT_NONCE_LEN..GCM_EXPLICIT_NONCE_LEN + plain_len,
            ),
        )
    }
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt<'a>(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).to_array()?);
        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version.encode(),
            msg.payload.len(),
        ));

        let payload = match msg.payload.single_chunk() {
            // Contiguous plaintext is sealed out-of-place, straight from the
            // borrowed input.
            Some(plain) => {
                let record = record_region(out, total_len)?;
                let (explicit_nonce, sealed) = record.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
                explicit_nonce.copy_from_slice(&nonce.as_ref()[4..]);
                let (ciphertext, tag) = sealed.split_at_mut(plain.len());
                self.enc_key
                    .seal_out_of_place_scatter(nonce, aad, plain, ciphertext, &[], tag)
                    .map_err(|_| Error::EncryptError)?;
                &*record
            }
            // Fragmented plaintext is gathered into `out` and then sealed in place.
            // We can't use the out-of-place seal as it requires contiguous input.
            None => {
                let mut payload = EncryptBuffer::new(out, total_len)?;
                payload.extend_from_slice(&nonce.as_ref()[4..]);
                payload.extend_from_chunks(&msg.payload);

                match self.enc_key.seal_in_place_separate_tag(
                    nonce,
                    aad,
                    &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..],
                ) {
                    Ok(tag) => payload.extend_from_slice(tag.as_ref()),
                    Err(_) => return Err(Error::EncryptError),
                }

                payload.into_written()
            }
        };

        Ok(EncodedMessage {
            typ: msg.typ,
            version: msg.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + self.enc_key.algorithm().tag_len()
    }
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
struct ChaCha20Poly1305MessageEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
struct ChaCha20Poly1305MessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let payload = &msg.payload;

        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce =
            aead::Nonce::assume_unique_for_key(Nonce::new(&self.dec_offset, seq).to_array()?);

        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version.version(),
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        ));

        let payload = &mut msg.payload;
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
    fn encrypt<'a>(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());

        let nonce =
            aead::Nonce::assume_unique_for_key(Nonce::new(&self.enc_offset, seq).to_array()?);
        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version.encode(),
            msg.payload.len(),
        ));

        let payload = match msg.payload.single_chunk() {
            // Contiguous plaintext is sealed out-of-place, straight from the
            // borrowed input.
            Some(plain) => {
                let record = record_region(out, total_len)?;
                let (ciphertext, tag) = record.split_at_mut(plain.len());
                self.enc_key
                    .seal_out_of_place_scatter(nonce, aad, plain, ciphertext, &[], tag)
                    .map_err(|_| Error::EncryptError)?;
                &*record
            }
            // Fragmented plaintext is gathered into `out` and then sealed in place.
            // We can't use the out-of-place seal as it requires contiguous input.
            None => {
                let mut payload = EncryptBuffer::new(out, total_len)?;
                payload.extend_from_chunks(&msg.payload);

                match self
                    .enc_key
                    .seal_in_place_separate_tag(nonce, aad, payload.as_mut())
                {
                    Ok(tag) => payload.extend_from_slice(tag.as_ref()),
                    Err(_) => return Err(Error::EncryptError),
                }

                payload.into_written()
            }
        };

        Ok(EncodedMessage {
            typ: msg.typ,
            version: msg.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + self.enc_key.algorithm().tag_len()
    }
}

fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);

    Iv::new(&iv).expect("IV length is NONCE_LEN, which is within MAX_LEN")
}

struct Tls12Prf(&'static tls_prf::Algorithm);

impl Prf for Tls12Prf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        Tls12PrfSecret {
            alg: self.0,
            secret: Secret::KeyExchange(
                kx.complete_for_tls_version(peer_pub_key, ProtocolVersion::TLSv1_2)?,
            ),
        }
        .prf(output, label, seed);
        Ok(())
    }

    fn new_secret(&self, secret: &[u8; 48]) -> Box<dyn PrfSecret> {
        Box::new(Tls12PrfSecret {
            alg: self.0,
            secret: Secret::Master(Zeroizing::new(*secret)),
        })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

// nb: we can't put a `tls_prf::Secret` in here because it is
// consumed by `tls_prf::Secret::derive()`
struct Tls12PrfSecret {
    alg: &'static tls_prf::Algorithm,
    secret: Secret,
}

impl PrfSecret for Tls12PrfSecret {
    fn prf(&self, output: &mut [u8], label: &[u8], seed: &[u8]) {
        // safety:
        // - [1] is safe because our caller guarantees `secret` is non-empty; this is
        //   the only documented error case.
        // - [2] is safe in practice because the only failure from `derive()` is due
        //   to zero `output.len()`; this is outlawed at higher levels
        let derived = tls_prf::Secret::new(self.alg, self.secret.as_ref())
            .unwrap() // [1]
            .derive(label, seed, output.len())
            .unwrap(); // [2]
        output.copy_from_slice(derived.as_ref());
    }
}

enum Secret {
    Master(Zeroizing<[u8; 48]>),
    KeyExchange(SharedSecret),
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Master(ms) => ms.as_ref(),
            Self::KeyExchange(kx) => kx.secret_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use rustls::crypto::cipher::{EncodableVersion, InboundOpaque};
    use rustls::enums::ContentType;

    use super::*;

    /// Test that contiguous plaintext and fragmented plaintext are handled identically.
    #[test]
    fn out_of_place_sealing_matches_in_place() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let chunks = [&plain[..3], &plain[3..27], &plain[27..]];

        for suite in ALL_TLS12_CIPHER_SUITES {
            // Different `fill` values prove both paths write every output byte.
            let contiguous = seal(suite, OutboundPlain::from(plain), 0x00);
            let fragmented = seal(suite, OutboundPlain::new(&chunks), 0xff);
            assert_eq!(contiguous, fragmented, "{:?}", suite.common.suite);
        }
    }

    /// Sealed records must open through the corresponding decrypter.
    #[test]
    fn sealed_records_open() {
        for suite in ALL_TLS12_CIPHER_SUITES {
            for plain in [&b""[..], b"hello"] {
                let mut sealed = seal(suite, OutboundPlain::from(plain), 0x00);
                let msg = EncodedMessage::new(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                    InboundOpaque(&mut sealed),
                );
                let shape = suite.aead_alg.key_block_shape();
                let mut decrypter = suite
                    .aead_alg
                    .decrypter(test_key(shape.enc_key_len), &TEST_IV[..shape.fixed_iv_len]);
                let opened = decrypter
                    .decrypt(msg, TEST_SEQ)
                    .unwrap();
                assert_eq!(opened.payload, plain, "{:?}", suite.common.suite);
            }
        }
    }

    fn seal(suite: &Tls12CipherSuite, payload: OutboundPlain<'_>, fill: u8) -> Vec<u8> {
        let shape = suite.aead_alg.key_block_shape();
        let mut encrypter = suite.aead_alg.encrypter(
            test_key(shape.enc_key_len),
            &TEST_IV[..shape.fixed_iv_len],
            &TEST_EXPLICIT[..shape.explicit_nonce_len],
        );
        let msg = EncodedMessage::new(
            ContentType::ApplicationData,
            EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
            payload,
        );
        let mut out = vec![fill; encrypter.encrypted_payload_len(msg.payload.len())];
        encrypter
            .encrypt(msg, TEST_SEQ, &mut out)
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

    const TEST_IV: [u8; NONCE_LEN] = [0x55; NONCE_LEN];
    const TEST_EXPLICIT: [u8; GCM_EXPLICIT_NONCE_LEN] = [0x66; GCM_EXPLICIT_NONCE_LEN];
    const TEST_SEQ: u64 = 7;
}
