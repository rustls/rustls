extern crate ring;
use prf;
use std::io::{Read, Write};
use msgs::message::{Message, MessagePayload};
use msgs::deframer::MessageDeframer;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::hsjoiner::HandshakeJoiner;
use msgs::base::Payload;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use error::TLSError;
use suites::SupportedCipherSuite;
use cipher::MessageCipher;

use std::io;
use std::mem;
use std::collections::VecDeque;

/// Generalises ClientSession and ServerSession
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
  fn write_tls(&mut self, wr: &mut Write) -> Result<usize, io::Error>;

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

  /// Returns true if the session is currently perform the TLS
  /// handshake.  During this time plaintext written to the
  /// session is buffered in memory.
  fn is_handshaking(&self) -> bool;

  /// Queues a close_notify fatal alert to be sent in the next
  /// `write_tls` call.  This informs the peer that the
  /// connection is being closed.
  fn send_close_notify(&mut self);

  /// Retrieves the certificate chain used by the peer to authenticate.
  ///
  /// For clients, this is the certificate chain of the server.
  ///
  /// For servers, this is the certificate chain of the client,
  /// if client authentication was completed.
  ///
  /// The return value is None until this value is available.
  fn get_peer_certificates(&self) -> Option<Vec<Vec<u8>>>;
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

/* --- Common (to client and server) session functions --- */
pub struct SessionCommon {
  message_cipher: Box<MessageCipher + Send + Sync>,
  write_seq: u64,
  read_seq: u64,
  peer_eof: bool,
  pub peer_encrypting: bool,
  pub we_encrypting: bool,
  pub traffic: bool,
  pub message_deframer: MessageDeframer,
  pub handshake_joiner: HandshakeJoiner,
  pub message_fragmenter: MessageFragmenter,
  received_plaintext: Vec<u8>,
  sendable_plaintext: Vec<u8>,
  pub sendable_tls: Vec<u8>
}

impl SessionCommon {
  pub fn new(mtu: Option<usize>) -> SessionCommon {
    SessionCommon {
      message_cipher: MessageCipher::invalid(),
      write_seq: 0,
      read_seq: 0,
      peer_eof: false,
      peer_encrypting: false,
      we_encrypting: false,
      traffic: false,
      message_deframer: MessageDeframer::new(),
      handshake_joiner: HandshakeJoiner::new(),
      message_fragmenter: MessageFragmenter::new(mtu.unwrap_or(MAX_FRAGMENT_LEN)),
      received_plaintext: Vec::new(),
      sendable_plaintext: Vec::new(),
      sendable_tls: Vec::new(),
    }
  }

  pub fn has_readable_plaintext(&self) -> bool {
    !self.received_plaintext.is_empty()
  }

  pub fn encrypt_outgoing(&mut self, plain: &Message) -> Message {
    let seq = self.write_seq;
    self.write_seq += 1;
    assert!(self.write_seq != 0);
    self.message_cipher.encrypt(plain, seq).unwrap()
  }

  pub fn decrypt_incoming(&mut self, plain: &Message) -> Result<Message, TLSError> {
    let seq = self.read_seq;
    self.read_seq += 1;
    assert!(self.read_seq != 0);
    self.message_cipher.decrypt(plain, seq)
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
      Err(TLSError::AlertReceived(alert.description))
    } else {
      Err(TLSError::CorruptMessagePayload(ContentType::Alert))
    }
  }

  /// Fragment `m`, encrypt the fragments, and then queue
  /// the encrypted fragments for sending.
  pub fn send_msg_encrypt(&mut self, m: &Message) {
    let mut plain_messages = VecDeque::new();
    self.message_fragmenter.fragment(m, &mut plain_messages);

    for m in plain_messages {
      let mut buf = Vec::new();
      m.encode(&mut buf);
      let em = self.encrypt_outgoing(&m);
      self.queue_tls_message(em);
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

  pub fn write_tls(&mut self, wr: &mut io::Write) -> io::Result<usize> {
    let written = try!(wr.write(&self.sendable_tls));
    self.sendable_tls = self.sendable_tls.split_off(written);
    Ok(written)
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

    assert!(self.we_encrypting);

    if data.len() == 0 {
      /* Don't send empty fragments. */
      return;
    }

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

  // Put m into sendable_tls for writing.
  fn queue_tls_message(&mut self, m: Message) {
    m.encode(&mut self.sendable_tls);
  }

  /// Send a raw TLS message, fragmenting it if needed.
  pub fn send_msg(&mut self, m: &Message, must_encrypt: bool) {
    if !must_encrypt {
      let mut to_send = VecDeque::new();
      self.message_fragmenter.fragment(m, &mut to_send);
      for m in to_send {
        self.queue_tls_message(m);
      }
    } else {
      self.send_msg_encrypt(m);
    }
  }

  pub fn take_received_plaintext(&mut self, bytes: Payload) {
    self.received_plaintext.extend_from_slice(&bytes.0);
  }

  pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    use std::io::Read;
    let len = try!(self.received_plaintext.as_slice().read(buf));
    self.received_plaintext = self.received_plaintext.split_off(len);

    if len == 0 && self.connection_at_eof() && self.received_plaintext.is_empty() {
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

  pub fn we_now_encrypting(&mut self) {
    self.we_encrypting = true;
  }

  pub fn send_warning_alert(&mut self, desc: AlertDescription) {
    warn!("Sending warning alert {:?}", desc);
    let m = Message::build_alert(AlertLevel::Warning, desc);
    let enc = self.we_encrypting;
    self.send_msg(&m, enc);
  }

  pub fn send_fatal_alert(&mut self, desc: AlertDescription) {
    warn!("Sending fatal alert {:?}", desc);
    let m = Message::build_alert(AlertLevel::Fatal, desc);
    let enc = self.we_encrypting;
    self.send_msg(&m, enc);
  }
}
