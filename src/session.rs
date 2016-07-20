extern crate ring;
use prf;
use std::io::{Read, Write};
use msgs::codec;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};
use msgs::deframer::MessageDeframer;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::hsjoiner::HandshakeJoiner;
use msgs::base::Payload;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use error::TLSError;
use suites::{SupportedCipherSuite, BulkAlgorithm};

use std::io;
use std::mem;
use std::collections::VecDeque;

pub trait Session : Read + Write {
  /// Read TLS content from `rd`.  This method does internal
  /// buffering, so `rd` can supply TLS messages in arbitrary-
  /// sized chunks (like a socket or pipe might).
  ///
  /// You should call `process_new_packets` each time a call to
  /// this function succeeds.
  ///
  /// The returned error only relates to IO on `rd`.  TLS-level
  /// errors are emitted from `process_new_packets`.
  fn read_tls(&mut self, rd: &mut Read) -> Result<usize, io::Error>;

  /// Writes TLS messages to `wr`.
  fn write_tls(&mut self, wr: &mut Write) -> Result<(), io::Error>;

  /// Processes any new packets read by a previous call to `read_tls`.
  /// Errors from this function relate to TLS protocol errors, and
  /// are generally fatal to the session.
  ///
  /// Success from this function can mean new plaintext is available:
  /// obtain it using `read`.
  fn process_new_packets(&mut self) -> Result<(), TLSError>;

  /// Returns true if the caller should call `read_tls` as soon
  /// as possible.
  fn wants_read(&self) -> bool;

  /// Returns true if the caller should call `write_tls` as soon
  /// as possible.
  fn wants_write(&self) -> bool;

  /// Queues a close_notify fatal alert to be sent in the next
  /// `write_tls` call.  This informs the peer that the
  /// connection is being closed.
  fn send_close_notify(&mut self);
}

pub struct SessionSecrets {
  pub we_are_client: bool,
  pub client_random: [u8; 32],
  pub server_random: [u8; 32],
  hash: Option<&'static ring::digest::Algorithm>,
  master_secret: [u8; 48]
}

fn join_randoms(first: &[u8], second: &[u8]) -> [u8; 64] {
  let mut randoms = [0u8; 64];
  randoms.as_mut().write(first).unwrap();
  randoms[32..].as_mut().write(second).unwrap();
  randoms
}


impl SessionSecrets {
  pub fn for_server() -> SessionSecrets {
    SessionSecrets {
      we_are_client: false,
      hash: None,
      client_random: [0u8; 32],
      server_random: [0u8; 32],
      master_secret: [0u8; 48]
    }
  }

  pub fn for_client() -> SessionSecrets {
    let mut ret = SessionSecrets::for_server();
    ret.we_are_client = true;
    ret
  }

  pub fn get_master_secret(&self) -> Vec<u8> {
    let mut ret = Vec::new();
    ret.extend_from_slice(&self.master_secret);
    ret
  }

  pub fn init(&mut self,
              hs_rands: &SessionSecrets,
              hashalg: &'static ring::digest::Algorithm,
              pms: &[u8]) {
    /* Copy in randoms. */
    self.client_random.as_mut().write(&hs_rands.client_random).unwrap();
    self.server_random.as_mut().write(&hs_rands.server_random).unwrap();

    self.hash = Some(hashalg);

    let randoms = join_randoms(&self.client_random, &self.server_random);
    prf::prf(&mut self.master_secret,
             hashalg,
             pms,
             b"master secret",
             &randoms);
  }

  pub fn init_resume(&mut self,
                     hs_rands: &SessionSecrets,
                     hashalg: &'static ring::digest::Algorithm,
                     master_secret: &[u8]) {
    self.client_random.as_mut().write(&hs_rands.client_random).unwrap();
    self.server_random.as_mut().write(&hs_rands.server_random).unwrap();
    self.hash = Some(hashalg);
    self.master_secret.as_mut().write(master_secret).unwrap();
  }

  pub fn make_key_block(&self, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(len, 0u8);

    /* NOTE: opposite order to above for no good reason.
     * Don't design security protocols on drugs, kids. */
    let randoms = join_randoms(&self.server_random, &self.client_random);
    prf::prf(&mut out,
             self.hash.unwrap(),
             &self.master_secret,
             b"key expansion",
             &randoms);

    out
  }

  pub fn make_verify_data(&self, handshake_hash: &Vec<u8>, label: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(12, 0u8);

    prf::prf(&mut out,
             self.hash.unwrap(),
             &self.master_secret,
             label,
             &handshake_hash);
    out
  }

  pub fn client_verify_data(&self, handshake_hash: &Vec<u8>) -> Vec<u8> {
    self.make_verify_data(handshake_hash, b"client finished")
  }

  pub fn server_verify_data(&self, handshake_hash: &Vec<u8>) -> Vec<u8> {
    self.make_verify_data(handshake_hash, b"server finished")
  }
}


pub trait MessageCipher {
  fn decrypt(&self, m: &Message, seq: u64) -> Result<Message, ()>;
  fn encrypt(&self, m: &Message, seq: u64) -> Result<Message, ()>;
}

impl MessageCipher {
  pub fn invalid() -> Box<MessageCipher + Send + Sync> {
    Box::new(InvalidMessageCipher {})
  }

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

    let (write_mac_key, write_key, write_iv) = if secrets.we_are_client {
      (client_write_mac_key, client_write_key, client_write_iv)
    } else {
      (server_write_mac_key, server_write_key, server_write_iv)
    };

    let (read_mac_key, read_key, read_iv) = if secrets.we_are_client {
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

/*
 * AES-GCM
 */
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
  fn decrypt(&self, msg: &Message, seq: u64) -> Result<Message, ()> {
    let payload = try!(msg.get_opaque_payload().ok_or(()));
    let mut buf = payload.body.to_vec();

    if buf.len() < GCM_OVERHEAD {
      return Err(());
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
                                                   &aad));

    buf.truncate(plain_len);

    Ok(
      Message {
        typ: msg.typ.clone(),
        version: msg.version.clone(),
        payload: MessagePayload::opaque(buf)
      }
    )
  }

  fn encrypt(&self, msg: &Message, seq: u64) -> Result<Message, ()> {
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

    let mut buf = Vec::new();
    buf.resize(GCM_EXPLICIT_NONCE_LEN, 0u8);
    msg.payload.encode(&mut buf);
    let payload_len = buf.len() - GCM_EXPLICIT_NONCE_LEN;

    /* make room for tag */
    let tag_len = self.alg.max_overhead_len();
    let want_len = buf.len() + tag_len;
    buf.resize(want_len, 0u8);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    msg.typ.encode(&mut aad);
    msg.version.encode(&mut aad);
    codec::encode_u16(payload_len as u16, &mut aad);

    try!(ring::aead::seal_in_place(&self.enc_key,
                                   &nonce,
                                   &mut buf[GCM_EXPLICIT_NONCE_LEN..],
                                   tag_len,
                                   &aad));

    buf[0..8].as_mut().write(&nonce[4..]).unwrap();

    Ok(Message {
      typ: msg.typ.clone(),
      version: msg.version.clone(),
      payload: MessagePayload::opaque(buf)
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

    assert_eq!(enc_iv.len(), 4);
    assert_eq!(dec_iv.len(), 4);
    assert_eq!(nonce_offset.len(), 8);

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

fn xor(accum: &mut [u8], offset: &[u8]) {
  for i in 0..accum.len() {
    accum[i] ^= offset[i];
  }
}

const CP_OVERHEAD: usize = 16;

impl MessageCipher for ChaCha20Poly1305MessageCipher {
  fn decrypt(&self, msg: &Message, seq: u64) -> Result<Message, ()> {
    let payload = try!(msg.get_opaque_payload().ok_or(()));
    let mut buf = payload.body.to_vec();

    if buf.len() < CP_OVERHEAD {
      return Err(());
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

    let plain_len = try!(ring::aead::open_in_place(&self.dec_key,
                                                   &nonce,
                                                   0,
                                                   &mut buf,
                                                   &aad));

    buf.truncate(plain_len);

    Ok(
      Message {
        typ: msg.typ.clone(),
        version: msg.version.clone(),
        payload: MessagePayload::opaque(buf)
      }
    )
  }

  fn encrypt(&self, msg: &Message, seq: u64) -> Result<Message, ()> {
    let mut nonce = [0u8; 12];
    codec::put_u64(seq, &mut nonce[4..]);
    xor(&mut nonce, &self.enc_offset);

    let mut buf = Vec::new();
    msg.payload.encode(&mut buf);
    let payload_len = buf.len();

    /* make room for tag */
    let tag_len = self.alg.max_overhead_len();
    let want_len = buf.len() + tag_len;
    buf.resize(want_len, 0u8);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    msg.typ.encode(&mut aad);
    msg.version.encode(&mut aad);
    codec::encode_u16(payload_len as u16, &mut aad);

    try!(ring::aead::seal_in_place(&self.enc_key,
                                   &nonce,
                                   &mut buf,
                                   tag_len,
                                   &aad));

    Ok(Message {
      typ: msg.typ.clone(),
      version: msg.version.clone(),
      payload: MessagePayload::opaque(buf)
    })
  }
}

/* A MessageCipher which doesn't work. */
pub struct InvalidMessageCipher {}

impl MessageCipher for InvalidMessageCipher {
  fn decrypt(&self, _m: &Message, _seq: u64) -> Result<Message, ()> {
    Err(())
  }

  fn encrypt(&self, _m: &Message, _seq: u64) -> Result<Message, ()> {
    Err(())
  }
}

/* --- Common (to client and server) session functions --- */
pub struct SessionCommon {
  message_cipher: Box<MessageCipher + Send + Sync>,
  write_seq: u64,
  read_seq: u64,
  peer_eof: bool,
  pub peer_encrypting: bool,
  pub traffic: bool,
  pub message_deframer: MessageDeframer,
  pub handshake_joiner: HandshakeJoiner,
  pub message_fragmenter: MessageFragmenter,
  received_plaintext: Vec<u8>,
  sendable_plaintext: Vec<u8>,
  pub tls_queue: VecDeque<Message>
}

impl SessionCommon {
  pub fn new(mtu: Option<usize>) -> SessionCommon {
    SessionCommon {
      message_cipher: MessageCipher::invalid(),
      write_seq: 0,
      read_seq: 0,
      peer_eof: false,
      peer_encrypting: false,
      traffic: false,
      message_deframer: MessageDeframer::new(),
      handshake_joiner: HandshakeJoiner::new(),
      message_fragmenter: MessageFragmenter::new(mtu.unwrap_or(MAX_FRAGMENT_LEN)),
      received_plaintext: Vec::new(),
      sendable_plaintext: Vec::new(),
      tls_queue: VecDeque::new()
    }
  }

  pub fn encrypt_outgoing(&mut self, plain: &Message) -> Message {
    let seq = self.write_seq;
    self.write_seq += 1;
    assert!(self.write_seq != 0);
    self.message_cipher.encrypt(plain, seq).unwrap()
  }

  pub fn decrypt_incoming(&mut self, plain: &Message) -> Option<Message> {
    let seq = self.read_seq;
    self.read_seq += 1;
    assert!(self.read_seq != 0);
    self.message_cipher.decrypt(plain, seq).ok()
  }

  pub fn process_alert(&mut self, msg: &mut Message) -> Result<(), TLSError> {
    if let MessagePayload::Alert(ref alert) = msg.payload {
      /* If we get a CloseNotify, make a note to declare EOF to our
       * caller. */
      if alert.description == AlertDescription::CloseNotify {
        self.peer_eof = true;
        return Ok(())
      }

      /* Warnings are nonfatal. */
      if alert.level == AlertLevel::Warning {
        warn!("TLS alert warning received: {:#?}", msg);
        return Ok(())
      }

      error!("TLS alert received: {:#?}", msg);
      return Err(TLSError::AlertReceived(alert.description.clone()));
    } else {
      unreachable!();
    }
  }

  /// Fragment `m`, encrypt the fragments, and then queue
  /// the encrypted fragments for sending.
  pub fn send_msg_encrypt(&mut self, m: &Message) {
    let mut plain_messages = VecDeque::new();
    self.message_fragmenter.fragment(m, &mut plain_messages);

    for m in plain_messages {
      let em = self.encrypt_outgoing(&m);
      self.tls_queue.push_back(em);
    }
  }

  /// Are we done? ie, have we processed all received messages,
  /// and received a close_notify to indicate that no new messages
  /// will arrive?
  pub fn connection_at_eof(&self) -> bool {
    self.peer_eof && !self.message_deframer.has_pending()
  }

  /// Read TLS content from `rd`.  This method does internal
  /// buffering, so `rd` can supply TLS messages in arbitrary-
  /// sized chunks (like a socket or pipe might).
  pub fn read_tls(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    self.message_deframer.read(rd)
  }

  pub fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<()> {
    let msg_maybe = self.tls_queue.pop_front();
    if msg_maybe.is_none() {
      return Ok(());
    }

    let mut data = Vec::new();
    let msg = msg_maybe.unwrap();
    msg.encode(&mut data);

    wr.write_all(&data)
  }

  /// Send plaintext application data, fragmenting and
  /// encrypting it as it goes out.
  pub fn send_plain(&mut self, data: &[u8]) {
    if !self.traffic {
      /* If we haven't completed handshaking, buffer
       * plaintext to send once we do. */
      self.sendable_plaintext.extend_from_slice(data);
      return;
    }

    assert!(self.peer_encrypting);

    /* Make one giant message, then have the fragmenter chop
     * it into bits.  Then encrypt and queue those bits. */
    let m = Message {
      typ: ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(data.to_vec())
    };

    self.send_msg_encrypt(&m);
  }

  pub fn start_traffic(&mut self) {
    self.traffic = true;
    self.flush_plaintext();
  }

  /// Send any buffered plaintext.  Plaintext is buffered if
  /// written during handshake.
  pub fn flush_plaintext(&mut self) {
    if !self.traffic {
      return;
    }

    let buf = mem::replace(&mut self.sendable_plaintext, Vec::new());
    self.send_plain(&buf);
  }

  /// Send a raw TLS message, fragmenting it if needed.
  pub fn send_msg(&mut self, m: &Message, must_encrypt: bool) {
    if !must_encrypt {
      self.message_fragmenter.fragment(m, &mut self.tls_queue);
    } else {
      self.send_msg_encrypt(m);
    }
  }

  pub fn take_received_plaintext(&mut self, bytes: Payload) {
    self.received_plaintext.extend_from_slice(&bytes.body);
  }

  pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    use std::io::Read;
    let len = try!(self.received_plaintext.as_slice().read(buf));
    self.received_plaintext.drain(0..len);

    if len == 0 && self.connection_at_eof() && self.received_plaintext.len() == 0 {
      return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "CloseNotify alert received"));
    }

    Ok(len)
  }

  pub fn start_encryption(&mut self, suite: &'static SupportedCipherSuite, secrets: &SessionSecrets) {
    self.message_cipher = MessageCipher::new(suite, secrets);
  }

  pub fn peer_now_encrypting(&mut self) {
    self.peer_encrypting = true;
  }

  pub fn send_warning_alert(&mut self, desc: AlertDescription) {
    let m = Message::build_alert(AlertLevel::Warning, desc);
    let enc = self.peer_encrypting;
    self.send_msg(&m, enc);
  }

  pub fn send_fatal_alert(&mut self, desc: AlertDescription) {
    let m = Message::build_alert(AlertLevel::Fatal, desc);
    let enc = self.peer_encrypting;
    self.send_msg(&m, enc);
  }
}
