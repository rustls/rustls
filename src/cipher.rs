use ring;
use std::io::Write;
use msgs::codec;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};
use msgs::fragmenter::MAX_FRAGMENT_LEN;
use error::TLSError;
use session::SessionSecrets;
use suites::{SupportedCipherSuite, BulkAlgorithm};

// accum[i] ^= offset[i] for all i in 0..len(accum)
fn xor(accum: &mut [u8], offset: &[u8]) {
  for i in 0..accum.len() {
    accum[i] ^= offset[i];
  }
}

/// Objects with this trait can encrypt and decrypt TLS messages.
pub trait MessageCipher {
  fn decrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
  fn encrypt(&self, m: Message, seq: u64) -> Result<Message, TLSError>;
}

impl MessageCipher {
  /// Make a MessageCipher that doesn't work.
  pub fn invalid() -> Box<MessageCipher + Send + Sync> {
    Box::new(InvalidMessageCipher {})
  }

  /// Make a MessageCipher based on the given supported ciphersuite `scs`,
  /// and the session's `secrets`.
  pub fn new(scs: &'static SupportedCipherSuite, secrets: &SessionSecrets) -> Box<MessageCipher + Send + Sync> {
    /* Make a key block, and chop it up. */
    let key_block = secrets.make_key_block(scs.key_block_len());

    let mut offs = 0;
    let client_write_mac_key = &key_block[offs..offs+scs.mac_key_len]; offs += scs.mac_key_len;
    let server_write_mac_key = &key_block[offs..offs+scs.mac_key_len]; offs += scs.mac_key_len;
    let client_write_key = &key_block[offs..offs+scs.enc_key_len]; offs += scs.enc_key_len;
    let server_write_key = &key_block[offs..offs+scs.enc_key_len]; offs += scs.enc_key_len;
    let client_write_iv = &key_block[offs..offs+scs.fixed_iv_len]; offs += scs.fixed_iv_len;
    let server_write_iv = &key_block[offs..offs+scs.fixed_iv_len]; offs += scs.fixed_iv_len;
    let explicit_nonce_offs = &key_block[offs..offs+scs.explicit_nonce_len];

    let (write_mac_key, write_key, write_iv) = if secrets.randoms.we_are_client {
      (client_write_mac_key, client_write_key, client_write_iv)
    } else {
      (server_write_mac_key, server_write_key, server_write_iv)
    };

    let (read_mac_key, read_key, read_iv) = if secrets.randoms.we_are_client {
      (server_write_mac_key, server_write_key, server_write_iv)
    } else {
      (client_write_mac_key, client_write_key, client_write_iv)
    };

    let aead_alg = scs.get_aead_alg();

    if scs.bulk == BulkAlgorithm::CHACHA20_POLY1305 {
      Box::new(ChaCha20Poly1305MessageCipher::new(aead_alg,
                                                  write_mac_key, write_key, write_iv,
                                                  read_mac_key, read_key, read_iv))
    } else {
      Box::new(GCMMessageCipher::new(aead_alg,
                                     write_mac_key, write_key, write_iv,
                                     read_mac_key, read_key, read_iv,
                                     explicit_nonce_offs))
    }
  }
}

/// A MessageCipher for AES-GCM AEAD ciphersuites.
pub struct GCMMessageCipher {
  alg: &'static ring::aead::Algorithm,
  enc_key: ring::aead::SealingKey,
  enc_salt: [u8; 4],
  dec_key: ring::aead::OpeningKey,
  dec_salt: [u8; 4],
  nonce_offset: [u8; 8]
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageCipher for GCMMessageCipher {
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

    let plain_len = try!(
      ring::aead::open_in_place(&self.dec_key,
                                &nonce,
                                GCM_EXPLICIT_NONCE_LEN,
                                &mut buf,
                                &aad)
        .map_err(|_| TLSError::DecryptError)
    );

    if plain_len > MAX_FRAGMENT_LEN {
      let msg = "peer sent oversized fragment".to_string();
      return Err(TLSError::PeerMisbehavedError(msg));
    }

    buf.truncate(plain_len);

    Ok(
      Message {
        typ: msg.typ,
        version: msg.version,
        payload: MessagePayload::opaque(buf.as_slice())
      }
    )
  }

  fn encrypt(&self, msg: Message, seq: u64) -> Result<Message, TLSError> {
    /* The GCM nonce is constructed from a 32-bit 'salt' derived
     * from the master-secret, and a 64-bit explicit part,
     * with no specified construction.  Thanks for that.
     *
     * We use the same construction as TLS1.3/ChaCha20Poly1305:
     * a starting point extracted from the key block, xored with
     * the sequence number.
     */
    let mut nonce = [0u8; 12];
    nonce.as_mut().write(&self.enc_salt).unwrap();
    codec::put_u64(seq, &mut nonce[4..]);
    xor(&mut nonce[4..], &self.nonce_offset);

    let typ = msg.typ;
    let version = msg.version;
    let mut buf = msg.take_payload();
    let payload_len = buf.len();

    /* make room for tag */
    let tag_len = self.alg.max_overhead_len();
    let want_len = buf.len() + tag_len;
    buf.resize(want_len, 0u8);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    typ.encode(&mut aad);
    version.encode(&mut aad);
    codec::encode_u16(payload_len as u16, &mut aad);

    try!(
      ring::aead::seal_in_place(&self.enc_key,
                                &nonce,
                                &mut buf,
                                tag_len,
                                &aad)
        .map_err(|_| TLSError::General("encrypt failed".to_string()))
    );

    let mut result = Vec::new();
    result.extend_from_slice(&nonce[4..]);
    result.extend_from_slice(&buf);

    Ok(Message {
      typ: typ,
      version: version,
      payload: MessagePayload::opaque(result.as_slice())
    })
  }
}

impl GCMMessageCipher {
  fn new(alg: &'static ring::aead::Algorithm,
         _enc_mac_key: &[u8], enc_key: &[u8], enc_iv: &[u8],
         _dec_mac_key: &[u8], dec_key: &[u8], dec_iv: &[u8],
         nonce_offset: &[u8]) -> GCMMessageCipher {
    let mut ret = GCMMessageCipher {
      alg: alg,
      enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
      enc_salt: [0u8; 4],
      dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
      dec_salt: [0u8; 4],
      nonce_offset: [0u8; 8]
    };

    debug_assert_eq!(enc_iv.len(), 4);
    debug_assert_eq!(dec_iv.len(), 4);
    debug_assert_eq!(nonce_offset.len(), 8);

    ret.enc_salt.as_mut().write(enc_iv).unwrap();
    ret.dec_salt.as_mut().write(dec_iv).unwrap();
    ret.nonce_offset.as_mut().write(nonce_offset).unwrap();
    ret
  }
}

/// The RFC7905/RFC7539 ChaCha20Poly1305 construction
pub struct ChaCha20Poly1305MessageCipher {
  alg: &'static ring::aead::Algorithm,
  enc_key: ring::aead::SealingKey,
  enc_offset: [u8; 12],
  dec_key: ring::aead::OpeningKey,
  dec_offset: [u8; 12]
}

impl ChaCha20Poly1305MessageCipher {
  fn new(alg: &'static ring::aead::Algorithm,
         _enc_mac_key: &[u8], enc_key: &[u8], enc_iv: &[u8],
         _dec_mac_key: &[u8], dec_key: &[u8], dec_iv: &[u8]) -> ChaCha20Poly1305MessageCipher {
    let mut ret = ChaCha20Poly1305MessageCipher {
      alg: alg,
      enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
      enc_offset: [0u8; 12],
      dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
      dec_offset: [0u8; 12]
    };

    ret.enc_offset.as_mut().write(enc_iv).unwrap();
    ret.dec_offset.as_mut().write(dec_iv).unwrap();
    ret
  }
}

const CP_OVERHEAD: usize = 16;

impl MessageCipher for ChaCha20Poly1305MessageCipher {
  fn decrypt(&self, mut msg: Message, seq: u64) -> Result<Message, TLSError> {
    let payload = try!(msg.take_opaque_payload().ok_or(TLSError::DecryptError));
    let mut buf = payload.0;

    if buf.len() < CP_OVERHEAD {
      return Err(TLSError::DecryptError);
    }

    /* Nonce is offset_96 ^ (0_32 || seq_64) */
    let mut nonce = [0u8; 12];
    codec::put_u64(seq, &mut nonce[4..]);
    xor(&mut nonce, &self.dec_offset);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    msg.typ.encode(&mut aad);
    msg.version.encode(&mut aad);
    codec::encode_u16((buf.len() - CP_OVERHEAD) as u16, &mut aad);

    let plain_len = try!(
      ring::aead::open_in_place(&self.dec_key,
                                &nonce,
                                0,
                                &mut buf,
                                &aad)
        .map_err(|_| TLSError::DecryptError)
    );

    if plain_len > MAX_FRAGMENT_LEN {
      let err_msg = "peer sent oversized fragment".to_string();
      return Err(TLSError::PeerMisbehavedError(err_msg));
    }

    buf.truncate(plain_len);

    Ok(
      Message {
        typ: msg.typ,
        version: msg.version,
        payload: MessagePayload::opaque(buf.as_slice())
      }
    )
  }

  fn encrypt(&self, msg: Message, seq: u64) -> Result<Message, TLSError> {
    let mut nonce = [0u8; 12];
    codec::put_u64(seq, &mut nonce[4..]);
    xor(&mut nonce, &self.enc_offset);

    let typ = msg.typ;
    let version = msg.version;

    let mut buf = msg.take_payload();
    let payload_len = buf.len();

    /* make room for tag */
    let tag_len = self.alg.max_overhead_len();
    let want_len = buf.len() + tag_len;
    buf.resize(want_len, 0u8);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    typ.encode(&mut aad);
    version.encode(&mut aad);
    codec::encode_u16(payload_len as u16, &mut aad);

    try!(
      ring::aead::seal_in_place(&self.enc_key,
                                &nonce,
                                &mut buf,
                                tag_len,
                                &aad)
        .map_err(|_| TLSError::General("encrypt failed".to_string()))
    );

    Ok(Message {
      typ: typ,
      version: version,
      payload: MessagePayload::opaque(buf.as_slice())
    })
  }
}

/// A MessageCipher which doesn't work.
pub struct InvalidMessageCipher {}

impl MessageCipher for InvalidMessageCipher {
  /* Neither of these errors should ever occur */
  fn decrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
    Err(TLSError::DecryptError)
  }

  fn encrypt(&self, _m: Message, _seq: u64) -> Result<Message, TLSError> {
    Err(TLSError::General("encrypt not yet available".to_string()))
  }
}

