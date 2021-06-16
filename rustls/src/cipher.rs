use crate::error::Error;
use crate::key_schedule::{derive_traffic_iv, derive_traffic_key};
use crate::msgs::base::Payload;
use crate::msgs::codec;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
use crate::suites::Tls13CipherSuite;

use ring::{aead, hkdf};

/// Objects with this trait can decrypt TLS messages.
pub(crate) trait MessageDecrypter: Send + Sync {
    fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

/// Objects with this trait can encrypt TLS messages.
pub(crate) trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub(crate) fn new_tls13_read(
    scs: &'static Tls13CipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageDecrypter> {
    let key = derive_traffic_key(secret, scs.common.aead_algorithm);
    let iv = derive_traffic_iv(secret);

    Box::new(Tls13MessageDecrypter::new(key, iv))
}

pub(crate) fn new_tls13_write(
    scs: &'static Tls13CipherSuite,
    secret: &hkdf::Prk,
) -> Box<dyn MessageEncrypter> {
    let key = derive_traffic_key(secret, scs.common.aead_algorithm);
    let iv = derive_traffic_iv(secret);

    Box::new(Tls13MessageEncrypter::new(key, iv))
}

/// A TLS 1.3 write or read IV.
#[allow(unreachable_pub)] // Only exposed as part of `crate::quic`
#[derive(Default)]
pub struct Iv(pub(crate) [u8; ring::aead::NONCE_LEN]);

impl Iv {
    pub(crate) fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    /// Compute the nonce to use for encrypting or decrypting `packet_number`
    #[cfg(feature = "quic")]
    pub fn nonce_for(&self, packet_number: u64) -> ring::aead::Nonce {
        let mut out = [0; aead::NONCE_LEN];
        out[4..].copy_from_slice(&packet_number.to_be_bytes());
        for (out, inp) in out.iter_mut().zip(self.0.iter()) {
            *out ^= inp;
        }
        aead::Nonce::assume_unique_for_key(out)
    }

    pub(crate) fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), ring::aead::NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
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

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

pub(crate) fn make_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce
        .iter_mut()
        .zip(iv.0.iter())
        .for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

    aead::Nonce::assume_unique_for_key(nonce)
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE: usize = 1 + 2 + 2;
fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error> {
        let total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(msg.payload);
        msg.typ.encode(&mut payload);

        let nonce = make_nonce(&self.iv, seq);
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
        let mut payload = &mut msg.payload.0;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_nonce(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(&mut payload);
        if msg.typ == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(Error::PeerMisbehavedError(msg));
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.version = ProtocolVersion::TLSv1_3;
        Ok(msg.into_plain_message())
    }
}

impl Tls13MessageEncrypter {
    fn new(key: aead::UnboundKey, enc_iv: Iv) -> Self {
        Self {
            enc_key: aead::LessSafeKey::new(key),
            iv: enc_iv,
        }
    }
}

impl Tls13MessageDecrypter {
    fn new(key: aead::UnboundKey, dec_iv: Iv) -> Self {
        Self {
            dec_key: aead::LessSafeKey::new(key),
            iv: dec_iv,
        }
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowedPlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }
}
