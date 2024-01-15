use alloc::boxed::Box;
use alloc::vec::Vec;

use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher::{self, AeadKey, Iv, UnsupportedOperationError, NONCE_LEN};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

pub struct Chacha20Poly1305;

impl cipher::Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl cipher::Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(
        &self,
        key: cipher::AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            cipher::Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: &[u8]) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            cipher::Iv::copy(iv),
        ))
    }

    fn key_block_shape(&self) -> cipher::KeyBlockShape {
        cipher::KeyBlockShape {
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
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, cipher::Iv);

impl cipher::MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        // construct a TLSInnerPlaintext
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);
        payload.push(m.typ.get_u8());

        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);
        let aad = cipher::make_tls13_aad(total_len);

        self.0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| {
                cipher::OpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl cipher::MessageDecrypter for Tls13Cipher {
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = m.payload_mut();
        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);
        let aad = cipher::make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, cipher::Iv);

impl cipher::MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);

        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);
        let aad = cipher::make_tls12_aad(seq, m.typ, m.version, payload.len());

        self.0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| cipher::OpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl cipher::MessageDecrypter for Tls12Cipher {
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = m.payload();
        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);
        let aad = cipher::make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let payload = m.payload_mut();
        self.0
            .decrypt_in_place(&nonce, &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
