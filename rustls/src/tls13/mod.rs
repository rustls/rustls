use crate::cipher::{make_nonce, Iv, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ContentType, ProtocolVersion};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};
use crate::suites::Tls13CipherSuite;

use ring::{aead, hkdf};

pub(crate) mod key_schedule;
use key_schedule::{derive_traffic_iv, derive_traffic_key};

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
