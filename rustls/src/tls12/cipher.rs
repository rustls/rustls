use crate::crypto::cipher::{make_tls12_aad, Iv, MessageDecrypter, MessageEncrypter, Nonce};
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;

use ring::aead;

pub(crate) static AES128_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_128_GCM);
pub(crate) static AES256_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_256_GCM);

pub(crate) struct GcmAlgorithm(&'static aead::Algorithm);

impl Tls12AeadAlgorithm for GcmAlgorithm {
    fn decrypter(&self, dec_key: &[u8], dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let dec_key = aead::LessSafeKey::new(aead::UnboundKey::new(self.0, dec_key).unwrap());

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
        enc_key: &[u8],
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        debug_assert_eq!(write_iv.len(), 4);
        debug_assert_eq!(explicit.len(), 8);

        let enc_key = aead::LessSafeKey::new(aead::UnboundKey::new(self.0, enc_key).unwrap());

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

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0.key_len(),
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets {
        match key.len() {
            16 => {
                // nb. "fixed IV" becomes the GCM nonce "salt"
                let (key, salt, iv) = slices_to_arrays(key, iv, explicit);
                ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv }
            }
            32 => {
                // nb. "fixed IV" becomes the GCM nonce "salt"
                let (key, salt, iv) = slices_to_arrays(key, iv, explicit);
                ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv }
            }
            _ => unreachable!(),
        }
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

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], _explicit: &[u8]) -> ConnectionTrafficSecrets {
        let (key, iv) = (slice_to_array(key), slice_to_array(iv));
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

        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - GCM_OVERHEAD,
        ));

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
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));

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

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.dec_offset, seq).0);
        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        ));

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
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.enc_offset, seq).0);
        let aad = aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));

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

pub(crate) trait Tls12AeadAlgorithm: Send + Sync + 'static {
    fn decrypter(&self, key: &[u8], iv: &[u8]) -> Box<dyn MessageDecrypter>;
    fn encrypter(&self, key: &[u8], iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;
    fn key_block_shape(&self) -> KeyBlockShape;
    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: &[u8], iv: &[u8], explicit: &[u8]) -> ConnectionTrafficSecrets;
}

/// How a TLS1.2 `key_block` is partitioned.
///
/// nb. ciphersuites with non-zero `mac_key_length` not currently supported
pub(crate) struct KeyBlockShape {
    /// How long keys are.
    ///
    /// `enc_key_len` terminology is from the standard.
    pub(crate) enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub(crate) fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub(crate) explicit_nonce_len: usize,
}

#[cfg(feature = "secret_extraction")]
fn slices_to_arrays<const NK: usize, const NS: usize, const NI: usize>(
    k: &[u8],
    s: &[u8],
    i: &[u8],
) -> ([u8; NK], [u8; NS], [u8; NI]) {
    (slice_to_array(k), slice_to_array(s), slice_to_array(i))
}

#[cfg(feature = "secret_extraction")]
fn slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    // this is guaranteed true because `ConnectionTrafficSecrets` items and
    // `key_block_shape()` are in agreement.
    debug_assert_eq!(N, slice.len());
    slice.try_into().unwrap()
}
