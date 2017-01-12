use ring;
use std::io::{Read, Write};
use msgs::message::{Message, MessagePayload};
use msgs::deframer::MessageDeframer;
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::hsjoiner::HandshakeJoiner;
use msgs::base::Payload;
use msgs::codec::Codec;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use msgs::enums::KeyUpdateRequest;
use error::TLSError;
use suites::SupportedCipherSuite;
use cipher::MessageCipher;
use vecbuf::ChunkVecBuffer;
use key;
use key_schedule::{SecretKind, KeySchedule};
use prf;
use rand;

use std::io;
use std::collections::VecDeque;

/// Generalises ClientSession and ServerSession
pub trait Session: Read + Write + Send {
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
    fn get_peer_certificates(&self) -> Option<Vec<key::Certificate>>;

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of None after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    fn get_alpn_protocol(&self) -> Option<String>;

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns None until the version is agreed.
    fn get_protocol_version(&self) -> Option<ProtocolVersion>;
}

#[derive(Clone, Debug)]
pub struct SessionRandoms {
    pub we_are_client: bool,
    pub client: [u8; 32],
    pub server: [u8; 32],
}

impl SessionRandoms {
    pub fn for_server() -> SessionRandoms {
        let mut ret = SessionRandoms {
            we_are_client: false,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.server);
        ret
    }

    pub fn for_client() -> SessionRandoms {
        let mut ret = SessionRandoms {
            we_are_client: true,
            client: [0u8; 32],
            server: [0u8; 32],
        };

        rand::fill_random(&mut ret.client);
        ret
    }
}

fn join_randoms(first: &[u8], second: &[u8]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms.as_mut().write(first).unwrap();
    randoms[32..].as_mut().write(second).unwrap();
    randoms
}

pub struct SessionSecrets {
    pub randoms: SessionRandoms,
    hash: &'static ring::digest::Algorithm,
    master_secret: [u8; 48],
}

impl SessionSecrets {
    pub fn new(randoms: &SessionRandoms,
               hashalg: &'static ring::digest::Algorithm,
               pms: &[u8])
               -> SessionSecrets {
        let mut ret = SessionSecrets {
            randoms: randoms.clone(),
            hash: hashalg,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf(&mut ret.master_secret,
                 ret.hash,
                 pms,
                 b"master secret",
                 &randoms);
        ret
    }

    pub fn new_resume(randoms: &SessionRandoms,
                      hashalg: &'static ring::digest::Algorithm,
                      master_secret: &[u8])
                      -> SessionSecrets {
        let mut ret = SessionSecrets {
            randoms: randoms.clone(),
            hash: hashalg,
            master_secret: [0u8; 48],
        };
        ret.master_secret.as_mut().write(master_secret).unwrap();
        ret
    }

    pub fn make_key_block(&self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        prf::prf(&mut out,
                 self.hash,
                 &self.master_secret,
                 b"key expansion",
                 &randoms);

        out
    }

    pub fn get_master_secret(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.master_secret);
        ret
    }

    pub fn make_verify_data(&self, handshake_hash: &Vec<u8>, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        prf::prf(&mut out,
                 self.hash,
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

// --- Common (to client and server) session functions ---
static SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
static SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

pub enum MessageCipherChange {
    BothNew,
    WriteNew,
    ReadNew,
}

pub struct SessionCommon {
    pub is_tls13: bool,
    pub is_client: bool,
    message_cipher: Box<MessageCipher + Send + Sync>,
    key_schedule: Option<KeySchedule>,
    suite: Option<&'static SupportedCipherSuite>,
    write_seq: u64,
    read_seq: u64,
    peer_eof: bool,
    pub peer_encrypting: bool,
    pub we_encrypting: bool,
    pub traffic: bool,
    pub want_write_key_update: bool,
    pub message_deframer: MessageDeframer,
    pub handshake_joiner: HandshakeJoiner,
    pub message_fragmenter: MessageFragmenter,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub sendable_tls: ChunkVecBuffer,
}

impl SessionCommon {
    pub fn new(mtu: Option<usize>, client: bool) -> SessionCommon {
        SessionCommon {
            is_tls13: false,
            is_client: client,
            suite: None,
            message_cipher: MessageCipher::invalid(),
            key_schedule: None,
            write_seq: 0,
            read_seq: 0,
            peer_eof: false,
            peer_encrypting: false,
            we_encrypting: false,
            traffic: false,
            want_write_key_update: false,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
            message_fragmenter: MessageFragmenter::new(mtu.unwrap_or(MAX_FRAGMENT_LEN)),
            received_plaintext: ChunkVecBuffer::new(),
            sendable_plaintext: ChunkVecBuffer::new(),
            sendable_tls: ChunkVecBuffer::new(),
        }
    }

    pub fn get_suite(&self) -> &'static SupportedCipherSuite {
        self.suite.as_ref().unwrap()
    }

    pub fn set_suite(&mut self, suite: &'static SupportedCipherSuite) {
        self.suite = Some(suite);
    }

    pub fn get_mut_key_schedule(&mut self) -> &mut KeySchedule {
        self.key_schedule.as_mut().unwrap()
    }

    pub fn get_key_schedule(&self) -> &KeySchedule {
        self.key_schedule.as_ref().unwrap()
    }

    pub fn set_key_schedule(&mut self, ks: KeySchedule) {
        self.key_schedule = Some(ks);
    }

    pub fn set_message_cipher(&mut self,
                              cipher: Box<MessageCipher + Send + Sync>,
                              why: MessageCipherChange) {
        self.message_cipher = cipher;

        match why {
            MessageCipherChange::BothNew => {
                self.write_seq = 0;
                self.read_seq = 0;
                self.peer_encrypting = true;
                self.we_encrypting = true;
            }

            MessageCipherChange::ReadNew => {
                self.read_seq = 0;
            }

            MessageCipherChange::WriteNew => {
                self.write_seq = 0;
            }
        }
    }

    pub fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
    }

    pub fn encrypt_outgoing(&mut self, plain: Message) -> Message {
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_cipher.encrypt(plain, seq).unwrap()
    }

    pub fn decrypt_incoming(&mut self, encr: Message) -> Result<Message, TLSError> {
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        if self.read_seq == SEQ_SOFT_LIMIT {
            self.send_close_notify();
        }

        let seq = self.read_seq;
        self.read_seq += 1;
        self.message_cipher.decrypt(encr, seq)
    }

    pub fn process_alert(&mut self, msg: Message) -> Result<(), TLSError> {
        if let MessagePayload::Alert(ref alert) = msg.payload {
            // If we get a CloseNotify, make a note to declare EOF to our
            // caller.
            if alert.description == AlertDescription::CloseNotify {
                self.peer_eof = true;
                return Ok(());
            }

            // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3.
            if alert.level == AlertLevel::Warning {
                if self.is_tls13 {
                    self.send_fatal_alert(AlertDescription::DecodeError);
                } else {
                    warn!("TLS alert warning received: {:#?}", msg);
                    return Ok(());
                }
            }

            error!("TLS alert received: {:#?}", msg);
            Err(TLSError::AlertReceived(alert.description))
        } else {
            Err(TLSError::CorruptMessagePayload(ContentType::Alert))
        }
    }

    fn do_write_key_update(&mut self) {
        // TLS1.3 putting key update triggering here breaks layering
        // between the handshake and record layer.

        let kind = if self.is_client {
            SecretKind::ClientApplicationTrafficSecret
        } else {
            SecretKind::ServerApplicationTrafficSecret
        };

        let write_key = self.get_key_schedule().derive_next(kind);

        let cipher = {
            let read_key = if self.is_client {
                &self.get_key_schedule().current_server_traffic_secret
            } else {
                &self.get_key_schedule().current_client_traffic_secret
            };

            MessageCipher::new_tls13(self.get_suite(), &write_key, &read_key)
        };

        self.set_message_cipher(cipher, MessageCipherChange::WriteNew);

        if self.is_client {
            self.get_mut_key_schedule().current_client_traffic_secret = write_key;
        } else {
            self.get_mut_key_schedule().current_server_traffic_secret = write_key;
        }

        self.want_write_key_update = false;
        self.send_msg_encrypt(Message::build_key_update_notify());
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub fn send_msg_encrypt(&mut self, m: Message) {
        if self.want_write_key_update {
            self.do_write_key_update();
        }

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            // Close connection once we start to run out of
            // sequence space.
            if self.write_seq == SEQ_SOFT_LIMIT {
                self.send_close_notify();
            }

            // Refuse to wrap counter at all costs.  This
            // is basically untestable unfortunately.
            if self.write_seq >= SEQ_HARD_LIMIT {
                return;
            }

            let em = self.encrypt_outgoing(m);
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
        self.sendable_tls.write_to(wr)
    }

    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    pub fn send_plain(&mut self, data: Vec<u8>) {
        if !self.traffic {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            self.sendable_plaintext.append(data);
            return;
        }

        debug_assert!(self.we_encrypting);

        if data.len() == 0 {
            // Don't send empty fragments.
            return;
        }

        // Make one giant message, then have the fragmenter chop
        // it into bits.  Then encrypt and queue those bits.
        let m = Message {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::opaque(data.as_slice()),
        };

        self.send_msg_encrypt(m);
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

        while !self.sendable_plaintext.is_empty() {
            let buf = self.sendable_plaintext.take_one();
            self.send_plain(buf);
        }
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: Message) {
        self.sendable_tls.append(m.get_encoding());
    }

    /// Send a raw TLS message, fragmenting it if needed.
    pub fn send_msg(&mut self, m: Message, must_encrypt: bool) {
        if !must_encrypt {
            let mut to_send = VecDeque::new();
            self.message_fragmenter.fragment(m, &mut to_send);
            for mm in to_send {
                self.queue_tls_message(mm);
            }
        } else {
            self.send_msg_encrypt(m);
        }
    }

    pub fn take_received_plaintext(&mut self, bytes: Payload) {
        self.received_plaintext.append(bytes.0);
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = try!(self.received_plaintext.read(buf));

        if len == 0 && self.connection_at_eof() && self.received_plaintext.is_empty() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                                      "CloseNotify alert received"));
        }

        Ok(len)
    }

    pub fn start_encryption_tls12(&mut self, secrets: &SessionSecrets) {
        self.message_cipher = MessageCipher::new_tls12(self.get_suite(), secrets);
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
        self.send_msg(m, enc);
    }

    pub fn send_fatal_alert(&mut self, desc: AlertDescription) {
        warn!("Sending fatal alert {:?}", desc);
        let m = Message::build_alert(AlertLevel::Fatal, desc);
        let enc = self.we_encrypting;
        self.send_msg(m, enc);
    }

    pub fn send_close_notify(&mut self) {
        self.send_warning_alert(AlertDescription::CloseNotify)
    }

    pub fn process_key_update(&mut self,
                              kur: &KeyUpdateRequest,
                              read_kind: SecretKind)
                              -> Result<(), TLSError> {
        // Mustn't be interleaved with other handshake messages.
        if !self.handshake_joiner.is_empty() {
            let msg = "KeyUpdate received at wrong time".to_string();
            warn!("{}", msg);
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        match *kur {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                self.want_write_key_update = true;
            }
            _ => {
                self.send_fatal_alert(AlertDescription::IllegalParameter);
                return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
            }
        }

        // Update our read-side keys.
        let new_read_key = self.get_key_schedule()
            .derive_next(read_kind);

        let suite = self.get_suite();
        let write_key = if read_kind == SecretKind::ServerApplicationTrafficSecret {
            self.get_key_schedule().current_client_traffic_secret.clone()
        } else {
            self.get_key_schedule().current_server_traffic_secret.clone()
        };
        self.set_message_cipher(MessageCipher::new_tls13(suite, &write_key, &new_read_key),
                                MessageCipherChange::ReadNew);

        if read_kind == SecretKind::ServerApplicationTrafficSecret {
            self.get_mut_key_schedule().current_server_traffic_secret = new_read_key;
        } else {
            self.get_mut_key_schedule().current_client_traffic_secret = new_read_key;
        }

        Ok(())
    }
}
