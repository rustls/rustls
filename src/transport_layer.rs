use std::io;
use std::collections::VecDeque;

use msgs::codec::Codec;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use msgs::enums::KeyUpdateRequest;
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload};
use msgs::tls_message::{BorrowMessage, TLSMessage, TLSMessagePayload};
use msgs::fragmenter::{MessageFragmenter, MAX_FRAGMENT_LEN};
use msgs::hsjoiner::HandshakeJoiner;
use msgs::deframer::MessageDeframer;
use msgs::base::Payload;
use cipher::{MessageDecrypter, MessageEncrypter, self};
use vecbuf::ChunkVecBuffer;
use key_schedule::{SecretKind, KeySchedule};
use error::TLSError;
use session::SessionSecrets;
use suites::SupportedCipherSuite;
use msgs::ccs::ChangeCipherSpecPayload;
use hash_hs;
use client_hs;

static SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
static SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

pub enum MessageSecrecy {
    MayBeUnencrypted,
    MustEncrypt,
}

pub struct StreamTransport {
    pub negotiated_version: Option<ProtocolVersion>,
    pub is_client: bool,
    message_encrypter: Box<MessageEncrypter>,
    message_decrypter: Box<MessageDecrypter>,
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
    pub message_fragmenter: MessageFragmenter,
    pub handshake_joiner: HandshakeJoiner,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub sendable_tls: ChunkVecBuffer,
}

pub trait TransportLayer {
    fn new(client: bool, mtu: Option<usize>) -> Self;
    fn send_handshake_msg_v10(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);
    fn send_handshake_msg_v12(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);
    fn send_handshake_msg_v13(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);
}

impl StreamTransport {
    fn handshake_into_msg(msg_version: ProtocolVersion,
                          transcript: &hash_hs::HandshakeHash,
                          payload: HandshakePayload) -> TLSMessage
    {
        let fill_in_binder = match payload {
            HandshakePayload::ClientHello(ref p) => {
                p.get_psk().is_some()
            },
            _ => false,
        };

        let mut msg_payload = HandshakeMessagePayload {
            typ: payload.handshake_type(),
            payload: payload,
        };

        if fill_in_binder {
            client_hs::fill_in_psk_binder(transcript, &mut msg_payload);
        }

        TLSMessage {
            typ: ContentType::Handshake,
            version: msg_version,
            payload: TLSMessagePayload::Handshake(msg_payload),
        }
    }

    /// Send a raw TLS message, fragmenting it if needed.
    pub fn send_msg(&mut self, m: TLSMessage, secrecy: MessageSecrecy) {
        match secrecy {
            MessageSecrecy::MustEncrypt => {
                self.send_msg_encrypt(m)
            },
            MessageSecrecy::MayBeUnencrypted if self.we_encrypting => {
                // This can happen for CloseNotify
                self.send_msg_encrypt(m)
            },
            MessageSecrecy::MayBeUnencrypted => {
                let mut to_send = VecDeque::new();
                self.message_fragmenter.fragment(m, &mut to_send);
                for mm in to_send {
                    self.queue_tls_message(mm);
                }
            },
        }
    }

    pub fn send_change_cipher_spec_v12(&mut self, secrecy: MessageSecrecy) {
        let ccs = TLSMessage {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::TLSv1_2,
            payload: TLSMessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };

        self.send_msg(ccs, secrecy)
    }


    pub fn is_tls13(&self) -> bool {
      match self.negotiated_version {
        Some(ProtocolVersion::TLSv1_3) => true,
        _ => false
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

    pub fn set_message_encrypter(&mut self,
                                 cipher: Box<MessageEncrypter>) {
        self.message_encrypter = cipher;
        self.write_seq = 0;
        self.we_encrypting = true;
    }

    pub fn set_message_decrypter(&mut self,
                                 cipher: Box<MessageDecrypter>) {
        self.message_decrypter = cipher;
        self.read_seq = 0;
        self.peer_encrypting = true;
    }

    pub fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
    }

    pub fn encrypt_outgoing(&mut self, plain: BorrowMessage) -> TLSMessage {
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter.encrypt(plain, seq).unwrap()
    }

    pub fn decrypt_incoming(&mut self, encr: TLSMessage) -> Result<TLSMessage, TLSError> {
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        if self.read_seq == SEQ_SOFT_LIMIT {
            self.send_close_notify();
        }

        let seq = self.read_seq;
        self.read_seq += 1;
        self.message_decrypter.decrypt(encr, seq)
    }

    pub fn process_alert(&mut self, msg: TLSMessage) -> Result<(), TLSError> {
        if let TLSMessagePayload::Alert(ref alert) = msg.payload {
            // If we get a CloseNotify, make a note to declare EOF to our
            // caller.
            if alert.description == AlertDescription::CloseNotify {
                self.peer_eof = true;
                return Ok(());
            }

            // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3.
            if alert.level == AlertLevel::Warning {
                if self.is_tls13() {
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

    pub fn do_write_key_update(&mut self) {
        // TLS1.3 putting key update triggering here breaks layering
        // between the handshake and record layer.

        let kind = if self.is_client {
            SecretKind::ClientApplicationTrafficSecret
        } else {
            SecretKind::ServerApplicationTrafficSecret
        };

        let write_key = self.get_key_schedule().derive_next(kind);
        let scs = self.get_suite();
        self.set_message_encrypter(cipher::new_tls13_write(scs, &write_key));

        if self.is_client {
            self.get_mut_key_schedule().current_client_traffic_secret = write_key;
        } else {
            self.get_mut_key_schedule().current_server_traffic_secret = write_key;
        }

        self.want_write_key_update = false;
        self.send_msg_encrypt(TLSMessage::build_key_update_notify());
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub fn send_msg_encrypt(&mut self, m: TLSMessage) {
        if self.want_write_key_update {
            self.do_write_key_update();
        }

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m.into_borrowed());
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self,
                            payload: &[u8]) {
        if self.want_write_key_update {
            self.do_write_key_update();
        }

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment_borrow(ContentType::ApplicationData,
                                                ProtocolVersion::TLSv1_2,
                                                payload,
                                                &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m);
        }
    }

    pub fn send_single_fragment(&mut self, m: BorrowMessage) {
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
    pub fn send_plain(&mut self, data: &[u8]) {
        if !self.traffic {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            self.sendable_plaintext.append(data.to_vec());
            return;
        }

        debug_assert!(self.we_encrypting);

        if data.len() == 0 {
            // Don't send empty fragments.
            return;
        }

        self.send_appdata_encrypt(data);
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
            self.send_plain(&buf);
        }
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: TLSMessage) {
        self.sendable_tls.append(m.get_encoding());
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
        let (dec, enc) = cipher::new_tls12(self.get_suite(), secrets);
        self.message_encrypter = enc;
        self.message_decrypter = dec;
    }

    pub fn peer_now_encrypting(&mut self) {
        self.peer_encrypting = true;
    }

    pub fn we_now_encrypting(&mut self) {
        self.we_encrypting = true;
    }

    pub fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {:?}", desc);
        let m = TLSMessage::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, MessageSecrecy::MayBeUnencrypted);
    }

    pub fn send_fatal_alert(&mut self, desc: AlertDescription) {
        warn!("Sending fatal alert {:?}", desc);
        let m = TLSMessage::build_alert(AlertLevel::Fatal, desc);
        self.send_msg(m, MessageSecrecy::MayBeUnencrypted);
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
        self.set_message_decrypter(cipher::new_tls13_read(suite, &new_read_key));

        if read_kind == SecretKind::ServerApplicationTrafficSecret {
            self.get_mut_key_schedule().current_server_traffic_secret = new_read_key;
        } else {
            self.get_mut_key_schedule().current_client_traffic_secret = new_read_key;
        }

        Ok(())
    }
}

impl TransportLayer for StreamTransport {
    fn new(client: bool, mtu: Option<usize>) -> Self {
        StreamTransport {
            negotiated_version: None,
            is_client: client,
            suite: None,
            message_encrypter: MessageEncrypter::invalid(),
            message_decrypter: MessageDecrypter::invalid(),
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

    fn send_handshake_msg_v10(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_0, transcript, payload);
        transcript.add_message(&msg);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v12(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_2, transcript, payload);
        transcript.add_message(&msg);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v13(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_3, transcript, payload);
        transcript.add_message(&msg);
        self.send_msg(msg, secrecy);
    }
}

