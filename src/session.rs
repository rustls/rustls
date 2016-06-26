extern crate ring;
use prf;
use std::io::Write;
use msgs::codec;
use msgs::codec::Codec;
use msgs::message::{Message, MessagePayload};
use msgs::deframer::MessageDeframer;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::hsjoiner::HandshakeJoiner;
use msgs::base::Payload;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use error::TLSError;
use suites::SupportedCipherSuite;

use std::io;
use std::mem;
use std::collections::VecDeque;

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
    dumphex("clientrand", &self.client_random);
    dumphex("serverrand", &self.server_random);
    dumphex("premaster", pms);
    prf::prf(&mut self.master_secret,
             hashalg,
             pms,
             b"master secret",
             &randoms);
    dumphex("master", &self.master_secret);
  }

  pub fn init_resume(&mut self,
                     hs_rands: &SessionSecrets,
                     hashalg: &'static ring::digest::Algorithm,
                     master_secret: &[u8]) {
    self.client_random.as_mut().write(&hs_rands.client_random).unwrap();
    self.server_random.as_mut().write(&hs_rands.server_random).unwrap();
    self.hash = Some(hashalg);
    self.master_secret.as_mut().write(master_secret).unwrap();

    dumphex("client_random", &self.client_random);
    dumphex("server_random", &self.server_random);
    dumphex("master_secret", &self.master_secret);
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

    dumphex("key block", &out);
    out
  }

  pub fn make_verify_data(&self, handshake_hash: &Vec<u8>, label: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(12, 0u8);

    dumphex("label", label);
    dumphex("master secret", &self.master_secret);
    dumphex("handshake hash", &handshake_hash);

    prf::prf(&mut out,
             self.hash.unwrap(),
             &self.master_secret,
             label,
             &handshake_hash);
    dumphex("fin", &out);
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
  pub fn invalid() -> Box<MessageCipher> {
    Box::new(InvalidMessageCipher {})
  }

  pub fn new(scs: &'static SupportedCipherSuite, secrets: &SessionSecrets) -> Box<MessageCipher> {
    /* Make a key block, and chop it up. */
    let key_block = secrets.make_key_block(scs.key_block_len());

    let mut offs = 0;
    let client_write_mac_key = &key_block[offs..offs+scs.mac_key_len]; offs += scs.mac_key_len;
    let server_write_mac_key = &key_block[offs..offs+scs.mac_key_len]; offs += scs.mac_key_len;
    let client_write_key = &key_block[offs..offs+scs.enc_key_len]; offs += scs.enc_key_len;
    let server_write_key = &key_block[offs..offs+scs.enc_key_len]; offs += scs.enc_key_len;
    let client_write_iv = &key_block[offs..offs+scs.fixed_iv_len]; offs += scs.fixed_iv_len;
    let server_write_iv = &key_block[offs..offs+scs.fixed_iv_len];

    let aead_alg = scs.get_aead_alg();

    if secrets.we_are_client {
      Box::new(GCMMessageCipher::new(aead_alg,
                                     client_write_mac_key, client_write_key, client_write_iv,
                                     server_write_mac_key, server_write_key, server_write_iv))
    } else {
      Box::new(GCMMessageCipher::new(aead_alg,
                                     server_write_mac_key, server_write_key, server_write_iv,
                                     client_write_mac_key, client_write_key, client_write_iv))
    }
  }
}

pub struct GCMMessageCipher {
  alg: &'static ring::aead::Algorithm,
  enc_key: ring::aead::SealingKey,
  enc_salt: [u8; 4],
  dec_key: ring::aead::OpeningKey,
  dec_salt: [u8; 4]
}

const EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = EXPLICIT_NONCE_LEN + 16;

fn dumphex(_why: &str, _buf: &[u8]) {
  /*
  print!("{}: ", _why);

  for b in _buf {
    print!("{:02x}", b);
  }
  println!("");
  */
}

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
                                                   EXPLICIT_NONCE_LEN,
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
     * We use the sequence number, which is the only safe-
     * by-construction option. */
    let mut nonce = [0u8; 12];
    nonce.as_mut().write(&self.enc_salt).unwrap();
    codec::put_u64(seq, &mut nonce[4..]);

    let mut buf = Vec::new();
    buf.resize(EXPLICIT_NONCE_LEN, 0u8);
    msg.payload.encode(&mut buf);
    let payload_len = buf.len() - EXPLICIT_NONCE_LEN;

    /* make room for tag */
    let tag_len = self.alg.max_overhead_len();
    let want_len = buf.len() + tag_len;
    buf.resize(want_len, 0u8);

    let mut aad = Vec::new();
    codec::encode_u64(seq, &mut aad);
    msg.typ.encode(&mut aad);
    msg.version.encode(&mut aad);
    codec::encode_u16(payload_len as u16, &mut aad);

    dumphex("plain", &buf[EXPLICIT_NONCE_LEN..want_len - tag_len]);
    dumphex("aad", &aad);

    try!(ring::aead::seal_in_place(&self.enc_key,
                                   &nonce,
                                   &mut buf[EXPLICIT_NONCE_LEN..],
                                   tag_len,
                                   &aad));

    buf[0..8].as_mut().write(&nonce[4..]).unwrap();
    dumphex("outgoing", &buf);

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
         _dec_mac_key: &[u8], dec_key: &[u8], dec_iv: &[u8]) -> GCMMessageCipher {
    let mut ret = GCMMessageCipher {
      alg: alg,
      enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
      enc_salt: [0u8; 4],
      dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
      dec_salt: [0u8; 4]
    };

    dumphex("enc_key", enc_key);
    dumphex("enc_iv ", enc_iv);
    dumphex("dec_key", dec_key);
    dumphex("dec_iv ", dec_iv);

    ret.enc_salt.as_mut().write(enc_iv).unwrap();
    ret.dec_salt.as_mut().write(dec_iv).unwrap();
    ret
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
  message_cipher: Box<MessageCipher>,
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
    println!("decrypt {:?}", plain);
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
}
