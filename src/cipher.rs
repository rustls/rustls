use ring;
use std::io::Write;
use msgs::codec;
use msgs::codec::Codec;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::message::{Message, MessagePayload};
use msgs::fragmenter::MAX_FRAGMENT_LEN;
use error::TLSError;
use session::SessionSecrets;
use suites::{SupportedCipherSuite, BulkAlgorithm};
use key_schedule::hkdf_expand_label;

// accum[i] ^= offset[i] for all i in 0..len(accum)
fn xor(accum: &mut [u8], offset: &[u8]) {
    for i in 0..accum.len() {
        accum[i] ^= offset[i];
    }
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter {
    fn decrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter {
    fn encrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

impl MessageEncrypter {
    pub fn invalid() -> Box<MessageEncrypter + Send + Sync> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl MessageDecrypter {
    pub fn invalid() -> Box<MessageDecrypter + Send + Sync> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub type MessageCipherPair = (Box<MessageDecrypter + Send + Sync>,
                              Box<MessageEncrypter + Send + Sync>);

/// Make a MessageCipherPair based on the given supported ciphersuite `scs`,
/// and the session's `secrets`.
pub fn new_tls12(scs: &'static SupportedCipherSuite,
                 secrets: &SessionSecrets)
                 -> MessageCipherPair {
    // Make a key block, and chop it up.
    // nb. we don't implement any ciphersuites with nonzero mac_key_len.
    let key_block = secrets.make_key_block(scs.key_block_len());

    let mut offs = 0;
    let client_write_key = &key_block[offs..offs + scs.enc_key_len];
    offs += scs.enc_key_len;
    let server_write_key = &key_block[offs..offs + scs.enc_key_len];
    offs += scs.enc_key_len;
    let client_write_iv = &key_block[offs..offs + scs.fixed_iv_len];
    offs += scs.fixed_iv_len;
    let server_write_iv = &key_block[offs..offs + scs.fixed_iv_len];
    offs += scs.fixed_iv_len;
    let explicit_nonce_offs = &key_block[offs..offs + scs.explicit_nonce_len];

    let (write_key, write_iv) = if secrets.randoms.we_are_client {
        (client_write_key, client_write_iv)
    } else {
        (server_write_key, server_write_iv)
    };

    let (read_key, read_iv) = if secrets.randoms.we_are_client {
        (server_write_key, server_write_iv)
    } else {
        (client_write_key, client_write_iv)
    };

    let aead_alg = scs.get_aead_alg();

    match scs.bulk {
        BulkAlgorithm::AES_128_GCM |
        BulkAlgorithm::AES_256_GCM => {
            (Box::new(GCMMessageDecrypter::new(aead_alg,
                                               read_key,
                                               read_iv)),
             Box::new(GCMMessageEncrypter::new(aead_alg,
                                               write_key,
                                               write_iv,
                                               explicit_nonce_offs)))
        }

        BulkAlgorithm::CHACHA20_POLY1305 => {
            (Box::new(ChaCha20Poly1305MessageDecrypter::new(aead_alg,
                                                            read_key,
                                                            read_iv)),
             Box::new(ChaCha20Poly1305MessageEncrypter::new(aead_alg,
                                                            write_key,
                                                            write_iv)))
        }
    }
}

pub fn new_tls13_read(scs: &'static SupportedCipherSuite,
                      secret: &[u8]) -> Box<MessageDecrypter + Send + Sync> {
    let hash = scs.get_hash();
    let key = hkdf_expand_label(hash, secret, b"key", &[], scs.enc_key_len as u16);
    let iv = hkdf_expand_label(hash, secret, b"iv", &[], scs.fixed_iv_len as u16);
    let aead_alg = scs.get_aead_alg();

    Box::new(TLS13MessageDecrypter::new(aead_alg, &key, &iv))
}

pub fn new_tls13_write(scs: &'static SupportedCipherSuite,
                       secret: &[u8]) -> Box<MessageEncrypter + Send + Sync> {
    let hash = scs.get_hash();
    let key = hkdf_expand_label(hash, secret, b"key", &[], scs.enc_key_len as u16);
    let iv = hkdf_expand_label(hash, secret, b"iv", &[], scs.fixed_iv_len as u16);
    let aead_alg = scs.get_aead_alg();

    Box::new(TLS13MessageEncrypter::new(aead_alg, &key, &iv))
}

/// A MessageEncrypter for AES-GCM AEAD ciphersuites. TLS 1.2 only.
pub struct GCMMessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_salt: [u8; 4],
    nonce_offset: [u8; 8],
}

/// A MessageDecrypter for AES-GCM AEAD ciphersuites.  TLS1.2 only.
pub struct GCMMessageDecrypter {
    dec_key: ring::aead::OpeningKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GCMMessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = try!(msg.take_opaque_payload().ok_or(TLSError::DecryptError));
        let mut buf = payload.0;

        if buf.len() < GCM_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        let mut nonce = [0u8; 12];
        nonce.as_mut().write(&self.dec_salt).unwrap();
        nonce[4..].as_mut().write(&buf).unwrap();

        let mut aad = Vec::new();
        codec::encode_u64(seq, &mut aad);
        msg.typ.encode(&mut aad);
        msg.version.encode(&mut aad);
        codec::encode_u16((buf.len() - GCM_OVERHEAD) as u16, &mut aad);

        let plain_len = try!(ring::aead::open_in_place(&self.dec_key,
                                                       &nonce,
                                                       GCM_EXPLICIT_NONCE_LEN,
                                                       &mut buf,
                                                       &aad)
            .map_err(|_| TLSError::DecryptError));

        if plain_len > MAX_FRAGMENT_LEN {
            let msg = "peer sent oversized fragment".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::opaque_take(buf),
        })
    }
}

impl MessageEncrypter for GCMMessageEncrypter {
    fn encrypt(&self, msg: Message, seq: u64) -> Result<Message, TLSError> {
        // The GCM nonce is constructed from a 32-bit 'salt' derived
        // from the master-secret, and a 64-bit explicit part,
        // with no specified construction.  Thanks for that.
        //
        // We use the same construction as TLS1.3/ChaCha20Poly1305:
        // a starting point extracted from the key block, xored with
        // the sequence number.
        //
        let mut nonce = [0u8; 12];
        nonce.as_mut().write(&self.enc_salt).unwrap();
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce[4..], &self.nonce_offset);

        let typ = msg.typ;
        let version = msg.version;
        let mut buf = msg.take_payload();
        let payload_len = buf.len();

        // make room for tag
        let tag_len = self.alg.max_overhead_len();
        let want_len = buf.len() + tag_len;
        buf.resize(want_len, 0u8);

        let mut aad = Vec::new();
        codec::encode_u64(seq, &mut aad);
        typ.encode(&mut aad);
        version.encode(&mut aad);
        codec::encode_u16(payload_len as u16, &mut aad);

        try!(ring::aead::seal_in_place(&self.enc_key, &nonce, &mut buf, tag_len, &aad)
            .map_err(|_| TLSError::General("encrypt failed".to_string())));

        let mut result = Vec::new();
        result.extend_from_slice(&nonce[4..]);
        result.extend_from_slice(&buf);

        Ok(Message {
            typ: typ,
            version: version,
            payload: MessagePayload::opaque_take(result),
        })
    }
}

impl GCMMessageEncrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           enc_key: &[u8],
           enc_iv: &[u8],
           nonce_offset: &[u8])
           -> GCMMessageEncrypter {
        let mut ret = GCMMessageEncrypter {
            alg: alg,
            enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
            enc_salt: [0u8; 4],
            nonce_offset: [0u8; 8],
        };

        debug_assert_eq!(enc_iv.len(), 4);
        debug_assert_eq!(nonce_offset.len(), 8);

        ret.enc_salt.as_mut().write(enc_iv).unwrap();
        ret.nonce_offset.as_mut().write(nonce_offset).unwrap();
        ret
    }
}

impl GCMMessageDecrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           dec_key: &[u8],
           dec_iv: &[u8]) -> GCMMessageDecrypter {
        let mut ret = GCMMessageDecrypter {
            dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
            dec_salt: [0u8; 4],
        };

        debug_assert_eq!(dec_iv.len(), 4);
        ret.dec_salt.as_mut().write(dec_iv).unwrap();
        ret
    }
}

struct TLS13MessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_offset: [u8; 12],
}

struct TLS13MessageDecrypter {
    alg: &'static ring::aead::Algorithm,
    dec_key: ring::aead::OpeningKey,
    dec_offset: [u8; 12],
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}

            Some(content_type) => return ContentType::read_bytes(&[content_type]).unwrap(),

            None => return ContentType::Unknown(0),
        }
    }
}

impl MessageEncrypter for TLS13MessageEncrypter {
    fn encrypt(&self, msg: Message, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.enc_offset);

        let typ = msg.typ;
        let mut buf = msg.take_payload();
        typ.encode(&mut buf);

        // make room for tag
        let tag_len = self.alg.max_overhead_len();
        let want_len = buf.len() + tag_len;
        buf.resize(want_len, 0u8);

        try!(ring::aead::seal_in_place(&self.enc_key, &nonce, &mut buf, tag_len, &[])
            .map_err(|_| TLSError::General("encrypt failed".to_string())));

        Ok(Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_0,
            payload: MessagePayload::opaque_take(buf),
        })
    }
}

impl MessageDecrypter for TLS13MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.dec_offset);

        let payload = try!(msg.take_opaque_payload().ok_or(TLSError::DecryptError));
        let mut buf = payload.0;

        if buf.len() < self.alg.max_overhead_len() {
            return Err(TLSError::DecryptError);
        }

        let plain_len = try!(ring::aead::open_in_place(&self.dec_key, &nonce, 0, &mut buf, &[])
            .map_err(|_| TLSError::DecryptError));

        buf.truncate(plain_len);

        let content_type = unpad_tls13(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        if buf.len() > MAX_FRAGMENT_LEN {
            let msg = "peer sent oversized fragment".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        Ok(Message {
            typ: content_type,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::opaque_take(buf),
        })
    }
}

impl TLS13MessageEncrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           enc_key: &[u8],
           enc_iv: &[u8]) -> TLS13MessageEncrypter {
        let mut ret = TLS13MessageEncrypter {
            alg: alg,
            enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
            enc_offset: [0u8; 12],
        };

        ret.enc_offset.as_mut().write(enc_iv).unwrap();
        ret
    }
}

impl TLS13MessageDecrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           dec_key: &[u8],
           dec_iv: &[u8]) -> TLS13MessageDecrypter {
        let mut ret = TLS13MessageDecrypter {
            alg: alg,
            dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
            dec_offset: [0u8; 12],
        };

        ret.dec_offset.as_mut().write(dec_iv).unwrap();
        ret
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses TLS13MessageEncrypter.
pub struct ChaCha20Poly1305MessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_offset: [u8; 12],
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses TLS13MessageDecrypter.
pub struct ChaCha20Poly1305MessageDecrypter {
    dec_key: ring::aead::OpeningKey,
    dec_offset: [u8; 12],
}

impl ChaCha20Poly1305MessageEncrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           enc_key: &[u8],
           enc_iv: &[u8]) -> ChaCha20Poly1305MessageEncrypter {
        let mut ret = ChaCha20Poly1305MessageEncrypter {
            alg: alg,
            enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
            enc_offset: [0u8; 12],
        };

        ret.enc_offset.as_mut().write(enc_iv).unwrap();
        ret
    }
}

impl ChaCha20Poly1305MessageDecrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           dec_key: &[u8],
           dec_iv: &[u8]) -> ChaCha20Poly1305MessageDecrypter {
        let mut ret = ChaCha20Poly1305MessageDecrypter {
            dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
            dec_offset: [0u8; 12],
        };

        ret.dec_offset.as_mut().write(dec_iv).unwrap();
        ret
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = try!(msg.take_opaque_payload().ok_or(TLSError::DecryptError));
        let mut buf = payload.0;

        if buf.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        // Nonce is offset_96 ^ (0_32 || seq_64)
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.dec_offset);

        let mut aad = Vec::new();
        codec::encode_u64(seq, &mut aad);
        msg.typ.encode(&mut aad);
        msg.version.encode(&mut aad);
        codec::encode_u16((buf.len() - CHACHAPOLY1305_OVERHEAD) as u16, &mut aad);

        let plain_len = try!(ring::aead::open_in_place(&self.dec_key, &nonce, 0, &mut buf, &aad)
            .map_err(|_| TLSError::DecryptError));

        if plain_len > MAX_FRAGMENT_LEN {
            let err_msg = "peer sent oversized fragment".to_string();
            return Err(TLSError::PeerMisbehavedError(err_msg));
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::opaque_take(buf),
        })
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&self, msg: Message, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.enc_offset);

        let typ = msg.typ;
        let version = msg.version;

        let mut buf = msg.take_payload();
        let payload_len = buf.len();

        // make room for tag
        let tag_len = self.alg.max_overhead_len();
        let want_len = buf.len() + tag_len;
        buf.resize(want_len, 0u8);

        let mut aad = Vec::new();
        codec::encode_u64(seq, &mut aad);
        typ.encode(&mut aad);
        version.encode(&mut aad);
        codec::encode_u16(payload_len as u16, &mut aad);

        try!(ring::aead::seal_in_place(&self.enc_key, &nonce, &mut buf, tag_len, &aad)
            .map_err(|_| TLSError::General("encrypt failed".to_string())));

        Ok(Message {
            typ: typ,
            version: version,
            payload: MessagePayload::opaque_take(buf),
        })
    }
}

/// A MessageEncrypter which doesn't work.
pub struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::General("encrypt not yet available".to_string()))
    }
}

/// A MessageDecrypter which doesn't work.
pub struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::DecryptError)
    }
}
