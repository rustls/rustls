use ring;
use std::io::Write;
use msgs::codec;
use msgs::codec::Codec;
use msgs::enums::{ContentType, ProtocolVersion};
use msgs::message::{BorrowMessage, Message, MessagePayload};
use msgs::fragmenter::MAX_FRAGMENT_LEN;
use error::TLSError;
use session::SessionSecrets;
use suites::{SupportedCipherSuite, BulkAlgorithm};
use key_schedule::{derive_traffic_key, derive_traffic_iv};

// accum[i] ^= offset[i] for all i in 0..len(accum)
fn xor(accum: &mut [u8], offset: &[u8]) {
    for i in 0..accum.len() {
        accum[i] ^= offset[i];
    }
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter : Send + Sync {
    fn decrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter : Send + Sync {
    fn encrypt(&self, m: BorrowMessage, seq: u64) -> Result<Message, TLSError>;
}

impl MessageEncrypter {
    pub fn invalid() -> Box<MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl MessageDecrypter {
    pub fn invalid() -> Box<MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

pub type MessageCipherPair = (Box<MessageDecrypter>, Box<MessageEncrypter>);

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;
fn make_tls12_aad(seq: u64,
                  typ: ContentType,
                  vers: ProtocolVersion,
                  len: usize,
                  out: &mut [u8]) {
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.get_u8();
    codec::put_u16(vers.get_u16(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
}

/// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
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
                      secret: &[u8]) -> Box<MessageDecrypter> {
    let hash = scs.get_hash();
    let key = derive_traffic_key(hash, secret, scs.enc_key_len);
    let iv = derive_traffic_iv(hash, secret, scs.fixed_iv_len);
    let aead_alg = scs.get_aead_alg();

    Box::new(TLS13MessageDecrypter::new(aead_alg, &key, &iv))
}

pub fn new_tls13_write(scs: &'static SupportedCipherSuite,
                       secret: &[u8]) -> Box<MessageEncrypter> {
    let hash = scs.get_hash();
    let key = derive_traffic_key(hash, secret, scs.enc_key_len);
    let iv = derive_traffic_iv(hash, secret, scs.fixed_iv_len);
    let aead_alg = scs.get_aead_alg();

    Box::new(TLS13MessageEncrypter::new(aead_alg, &key, &iv))
}

/// A `MessageEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
pub struct GCMMessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_salt: [u8; 4],
    nonce_offset: [u8; 8],
}

/// A `MessageDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
pub struct GCMMessageDecrypter {
    dec_key: ring::aead::OpeningKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GCMMessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload()
            .ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < GCM_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        let mut nonce = [0u8; 12];
        nonce.as_mut().write_all(&self.dec_salt).unwrap();
        nonce[4..].as_mut().write_all(&buf[..8]).unwrap();

        let mut aad = [0u8; TLS12_AAD_SIZE];
        make_tls12_aad(seq, msg.typ, msg.version, buf.len() - GCM_OVERHEAD, &mut aad);

        let plain_len = ring::aead::open_in_place(&self.dec_key,
                                                  &nonce,
                                                  &aad,
                                                  GCM_EXPLICIT_NONCE_LEN,
                                                  &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageEncrypter for GCMMessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        // The GCM nonce is constructed from a 32-bit 'salt' derived
        // from the master-secret, and a 64-bit explicit part,
        // with no specified construction.  Thanks for that.
        //
        // We use the same construction as TLS1.3/ChaCha20Poly1305:
        // a starting point extracted from the key block, xored with
        // the sequence number.
        //
        let mut nonce = [0u8; 12];
        nonce.as_mut().write_all(&self.enc_salt).unwrap();
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce[4..], &self.nonce_offset);

        // make output buffer with room for nonce/tag
        let tag_len = self.alg.tag_len();
        let total_len = 8 + msg.payload.len() + tag_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&nonce[4..]);
        buf.extend_from_slice(msg.payload);
        buf.resize(total_len, 0u8);

        let mut aad = [0u8; TLS12_AAD_SIZE];
        make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len(), &mut aad);

        ring::aead::seal_in_place(&self.enc_key, &nonce, &aad, &mut buf[8..], tag_len)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
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

        ret.enc_salt.as_mut().write_all(enc_iv).unwrap();
        ret.nonce_offset.as_mut().write_all(nonce_offset).unwrap();
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
        ret.dec_salt.as_mut().write_all(dec_iv).unwrap();
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

const TLS13_AAD_SIZE: usize = 1 + 2 + 2;
fn make_tls13_aad(len: usize, out: &mut [u8]) {
    out[0] = 0x17; // ContentType::ApplicationData
    out[1] = 0x3; // ProtocolVersion (major)
    out[2] = 0x3; // ProtocolVersion (minor)
    out[3] = (len >> 8) as u8;
    out[4] = len as u8;
}

impl MessageEncrypter for TLS13MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.enc_offset);

        // make output buffer with room for content type and tag
        let tag_len = self.alg.tag_len();
        let total_len = msg.payload.len() + 1 + tag_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(msg.payload);
        msg.typ.encode(&mut buf);
        buf.resize(total_len, 0u8);
        let mut aad = [0u8; TLS13_AAD_SIZE];
        make_tls13_aad(total_len, &mut aad);

        ring::aead::seal_in_place(&self.enc_key, &nonce, &aad, &mut buf, tag_len)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageDecrypter for TLS13MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.dec_offset);

        let payload = msg.take_opaque_payload()
            .ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < self.alg.tag_len() {
            return Err(TLSError::DecryptError);
        }

        let mut aad = [0u8; TLS13_AAD_SIZE];
        make_tls13_aad(buf.len(), &mut aad);
        let plain_len = ring::aead::open_in_place(&self.dec_key, &nonce, &aad, 0, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        buf.truncate(plain_len);

        if buf.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        let content_type = unpad_tls13(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        if buf.len() > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        Ok(Message {
            typ: content_type,
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::new_opaque(buf),
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

        ret.enc_offset.as_mut().write_all(enc_iv).unwrap();
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

        ret.dec_offset.as_mut().write_all(dec_iv).unwrap();
        ret
    }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageEncrypter`.
pub struct ChaCha20Poly1305MessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_offset: [u8; 12],
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `TLS13MessageDecrypter`.
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

        ret.enc_offset.as_mut().write_all(enc_iv).unwrap();
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

        ret.dec_offset.as_mut().write_all(dec_iv).unwrap();
        ret
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
        let payload = msg.take_opaque_payload()
            .ok_or(TLSError::DecryptError)?;
        let mut buf = payload.0;

        if buf.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(TLSError::DecryptError);
        }

        // Nonce is offset_96 ^ (0_32 || seq_64)
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.dec_offset);

        let mut aad = [0u8; TLS12_AAD_SIZE];
        make_tls12_aad(seq, msg.typ, msg.version, buf.len() - CHACHAPOLY1305_OVERHEAD, &mut aad);

        let plain_len = ring::aead::open_in_place(&self.dec_key, &nonce, &aad, 0, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        buf.truncate(plain_len);

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(&self, msg: BorrowMessage, seq: u64) -> Result<Message, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.enc_offset);

        let mut aad = [0u8; TLS12_AAD_SIZE];
        make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len(), &mut aad);

        // make result buffer with room for tag, etc.
        let tag_len = self.alg.tag_len();
        let total_len = msg.payload.len() + tag_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(msg.payload);
        buf.resize(total_len, 0u8);

        ring::aead::seal_in_place(&self.enc_key, &nonce, &aad, &mut buf, tag_len)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(Message {
            typ: msg.typ,
            version: msg.version,
            payload: MessagePayload::new_opaque(buf),
        })
    }
}

/// A `MessageEncrypter` which doesn't work.
pub struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowMessage, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
pub struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
        Err(TLSError::DecryptError)
    }
}
