use std::io;
use std::collections::VecDeque;

use msgs::codec::Codec;
use msgs::enums::{ContentType, ProtocolVersion, AlertDescription, AlertLevel};
use msgs::enums::KeyUpdateRequest;
use msgs::handshake::{HandshakePayload, HandshakeMessagePayload};
use msgs::tls_message::{BorrowMessage, TLSMessage, TLSMessagePayload};
#[cfg(feature="dtls")]
use msgs::dtls_message::{DTLSMessage, DTLSMessagePayload, DTLSHandshakeFragment};
#[cfg(feature="dtls")]
use msgs::hsjoiner::dtls::HandshakeJoiner as DTLSHandshakeJoiner;
#[cfg(feature="dtls")]
use msgs::alert::AlertMessagePayload;
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

pub struct TransportCommon {
    pub negotiated_version: Option<ProtocolVersion>,
    pub is_client: bool,
    message_encrypter: Box<MessageEncrypter>,
    message_decrypter: Box<MessageDecrypter>,
    key_schedule: Option<KeySchedule>,
    suite: Option<&'static SupportedCipherSuite>,
    write_seq: u64,
    read_seq: u64,
    pub peer_encrypting: bool,
    pub we_encrypting: bool,
    pub traffic: bool,
    pub want_write_key_update: bool,
}

pub struct StreamTransport {
    common: TransportCommon,
    peer_eof: bool,
    pub message_deframer: MessageDeframer,
    pub message_fragmenter: MessageFragmenter,
    pub handshake_joiner: HandshakeJoiner,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub sendable_tls: ChunkVecBuffer,
}

#[cfg(feature="dtls")]
pub struct DatagramTransport {
    common: TransportCommon,
    pub handshake_joiner: DTLSHandshakeJoiner,
    received_plaintext: ChunkVecBuffer,
    sendable_plaintext: ChunkVecBuffer,
    pub sendable_dtls: ChunkVecBuffer,
    read_seq_bitmask: u64,
    in_transmission: Vec<DTLSMessage>,
    epoch: u16,
    seq_number: u64,
    hs_seq_number: u16,
}

pub trait TransportLayer {
    fn new(client: bool, mtu: Option<usize>) -> Self;
    fn send_handshake_msg_v10(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);
    fn send_handshake_msg_v12(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);
    fn send_handshake_msg_v13(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy);

    fn common(&self) -> &TransportCommon;
    fn mut_common(&mut self) -> &mut TransportCommon;

    fn traffic(&self) -> bool {
        self.common().traffic
    }

    fn negotiated_version(&self) -> Option<ProtocolVersion> {
        self.common().negotiated_version
    }
    fn set_negotiated_version(&mut self, version: ProtocolVersion) {
        self.mut_common().negotiated_version = Some(version);
    }

    fn we_encrypting(&self) -> bool {
        self.common().we_encrypting
    }
    fn we_now_encrypting(&mut self) {
        self.mut_common().we_encrypting = true;
    }

    fn peer_encrypting(&self) -> bool {
        self.common().peer_encrypting
    }
    fn peer_now_encrypting(&mut self) {
        self.mut_common().peer_encrypting = true;
    }

    fn get_suite(&self) -> &'static SupportedCipherSuite {
        self.common().suite.as_ref().unwrap()
    }
    fn set_suite(&mut self, suite: &'static SupportedCipherSuite) {
        self.mut_common().suite = Some(suite);
    }

    fn get_mut_key_schedule(&mut self) -> &mut KeySchedule {
        self.mut_common().key_schedule.as_mut().unwrap()
    }

    fn get_key_schedule(&self) -> &KeySchedule {
        self.common().key_schedule.as_ref().unwrap()
    }

    fn set_key_schedule(&mut self, ks: KeySchedule) {
        self.mut_common().key_schedule = Some(ks);
    }

    fn has_readable_plaintext(&self) -> bool;

    fn set_message_decrypter(&mut self,
                             cipher: Box<MessageDecrypter>) {
        self.mut_common().message_decrypter = cipher;
        self.mut_common().read_seq = 0;
        self.mut_common().peer_encrypting = true;
    }

    fn encrypt_outgoing(&mut self, plain: BorrowMessage) -> TLSMessage {
        let seq = self.common().write_seq;
        self.mut_common().write_seq += 1;
        self.mut_common().message_encrypter.encrypt(plain, seq).unwrap()
    }

    fn set_message_encrypter(&mut self,
                             cipher: Box<MessageEncrypter>) {
        self.mut_common().message_encrypter = cipher;
        self.mut_common().write_seq = 0;
        self.mut_common().we_encrypting = true;
    }

    fn decrypt_incoming(&mut self, encr: TLSMessage) -> Result<TLSMessage, TLSError> {
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        if self.common().read_seq == SEQ_SOFT_LIMIT {
            self.send_close_notify();
        }

        let seq = self.common().read_seq;
        self.mut_common().read_seq += 1;
        self.common().message_decrypter.decrypt(encr, seq)
    }

    fn is_client(&self) -> bool {
        self.common().is_client
    }

    fn start_encryption_v12(&mut self, secrets: &SessionSecrets) {
        let (dec, enc) = cipher::new_tls12(self.get_suite(), secrets);
        self.mut_common().message_encrypter = enc;
        self.mut_common().message_decrypter = dec;
    }


    fn send_warning_alert(&mut self, desc: AlertDescription);
    fn send_fatal_alert(&mut self, desc: AlertDescription);

    fn send_close_notify(&mut self) {
        self.send_warning_alert(AlertDescription::CloseNotify)
    }

    fn send_change_cipher_spec_v12(&mut self, secrecy: MessageSecrecy);
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
            MessageSecrecy::MayBeUnencrypted if self.we_encrypting() => {
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

    pub fn is_tls13(&self) -> bool {
      match self.negotiated_version() {
        Some(ProtocolVersion::TLSv1_3) => true,
        _ => false
      }
    }

    pub fn do_write_key_update(&mut self) {
        // TLS1.3 putting key update triggering here breaks layering
        // between the handshake and record layer.

        let kind = if self.is_client() {
            SecretKind::ClientApplicationTrafficSecret
        } else {
            SecretKind::ServerApplicationTrafficSecret
        };

        let write_key = self.get_key_schedule().derive_next(kind);
        let scs = self.get_suite();
        self.set_message_encrypter(cipher::new_tls13_write(scs, &write_key));

        if self.is_client() {
            self.get_mut_key_schedule().current_client_traffic_secret = write_key;
        } else {
            self.get_mut_key_schedule().current_server_traffic_secret = write_key;
        }

        self.mut_common().want_write_key_update = false;
        self.send_msg_encrypt(TLSMessage::build_key_update_notify());
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub fn send_msg_encrypt(&mut self, m: TLSMessage) {
        if self.common().want_write_key_update {
            self.do_write_key_update();
        }

        let mut plain_messages = VecDeque::new();
        self.message_fragmenter.fragment(m, &mut plain_messages);

        for m in plain_messages {
            self.send_single_fragment(m.to_borrowed());
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self,
                            payload: &[u8]) {
        if self.common().want_write_key_update {
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
        if self.common().write_seq == SEQ_SOFT_LIMIT {
            self.send_close_notify();
        }

        // Refuse to wrap counter at all costs.  This
        // is basically untestable unfortunately.
        if self.common().write_seq >= SEQ_HARD_LIMIT {
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
        if !self.traffic() {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            self.sendable_plaintext.append(data.to_vec());
            return;
        }

        debug_assert!(self.we_encrypting());

        if data.len() == 0 {
            // Don't send empty fragments.
            return;
        }

        self.send_appdata_encrypt(data);
    }

    pub fn start_traffic(&mut self) {
        self.mut_common().traffic = true;
        self.flush_plaintext();
    }

    /// Send any buffered plaintext.  Plaintext is buffered if
    /// written during handshake.
    pub fn flush_plaintext(&mut self) {
        if !self.traffic() {
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
                self.mut_common().want_write_key_update = true;
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
}

impl TransportCommon {
    fn new(client: bool) -> TransportCommon {
        TransportCommon {
            is_client: client,
            key_schedule: None,
            message_encrypter: MessageEncrypter::invalid(),
            message_decrypter: MessageDecrypter::invalid(),
            negotiated_version: None,
            write_seq: 0,
            read_seq: 0,
            peer_encrypting: false,
            we_encrypting: false,
            traffic: false,
            suite: None,
            want_write_key_update: false,
        }
    }
}

impl TransportLayer for StreamTransport {
    fn new(client: bool, mtu: Option<usize>) -> Self {
        StreamTransport {
            peer_eof: false,
            message_deframer: MessageDeframer::new(),
            handshake_joiner: HandshakeJoiner::new(),
            message_fragmenter: MessageFragmenter::new(mtu.unwrap_or(MAX_FRAGMENT_LEN)),
            received_plaintext: ChunkVecBuffer::new(),
            sendable_plaintext: ChunkVecBuffer::new(),
            sendable_tls: ChunkVecBuffer::new(),
            common: TransportCommon::new(client),
        }
    }

    fn send_handshake_msg_v10(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_0, transcript, payload);
        transcript.add_message(&msg.payload);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v12(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_2, transcript, payload);
        transcript.add_message(&msg.payload);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v13(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = Self::handshake_into_msg(ProtocolVersion::TLSv1_3, transcript, payload);
        transcript.add_message(&msg.payload);
        self.send_msg(msg, secrecy);
    }

    fn common(&self) -> &TransportCommon {
        &self.common
    }

    fn mut_common(&mut self) -> &mut TransportCommon {
        &mut self.common
    }

    fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
    }

    fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {:?}", desc);
        let m = TLSMessage::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, MessageSecrecy::MayBeUnencrypted);
    }

    fn send_fatal_alert(&mut self, desc: AlertDescription) {
        warn!("Sending fatal alert {:?}", desc);
        let m = TLSMessage::build_alert(AlertLevel::Fatal, desc);
        self.send_msg(m, MessageSecrecy::MayBeUnencrypted);
    }

    fn send_change_cipher_spec_v12(&mut self, secrecy: MessageSecrecy) {
        let ccs = TLSMessage {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::TLSv1_2,
            payload: TLSMessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };

        self.send_msg(ccs, secrecy)
    }
}

#[cfg(feature="dtls")]
impl DatagramTransport {
    /// Verifies that `common.read_seq <= num < 64` and `num`
    /// has not been used before
    fn check_seq_number(&mut self, num: u64) -> bool {
        let i = num.saturating_sub(self.common.read_seq);
        if i > 63 {
            return false;
        }

        let bit = 1 << i;
        if self.read_seq_bitmask & bit != 0 {
            return false;
        }
        self.read_seq_bitmask |= bit;

        while self.read_seq_bitmask & 1 == 1 {
            self.read_seq_bitmask = self.read_seq_bitmask >> 1;

            if let Some(i) = self.common.read_seq.checked_add(1) {
                self.common.read_seq = i;
            } else {
                // max sequence number reached
                // TODO: re-negotiate? fatal alert?
                return false;
            }
        }

        true
    }

    pub fn do_write_key_update(&mut self) {
        unimplemented!()
    }

    /// Encrypt a message, and then queue
    /// the encrypted message for sending.
    pub fn send_msg_encrypt(&mut self, m: DTLSMessage) {
        unimplemented!();
        if self.common().want_write_key_update {
            self.do_write_key_update();
        }

//        let mut plain_messages = VecDeque::new();
  //      self.message_fragmenter.fragment(m, &mut plain_messages);

    //    for m in plain_messages {
      //      self.send_single_fragment(m.into_borrowed());
        //}
    }

    /// Send a raw DTLS message.
    pub fn send_msg(&mut self, m: DTLSMessage, secrecy: MessageSecrecy) {
        match secrecy {
            MessageSecrecy::MustEncrypt => {
                self.send_msg_encrypt(m)
            },
            MessageSecrecy::MayBeUnencrypted if self.we_encrypting() => {
                // This can happen for CloseNotify
                self.send_msg_encrypt(m)
            },
            MessageSecrecy::MayBeUnencrypted => {
                /*let mut to_send = VecDeque::new();
                self.message_fragmenter.fragment(m, &mut to_send);
                for mm in to_send {
                    self.queue_tls_message(mm);
                }*/
                unimplemented!()
            },
        }
    }

    fn handshake_into_msg(&self,
                          msg_version: ProtocolVersion,
                          transcript: &hash_hs::HandshakeHash,
                          payload: HandshakePayload) -> DTLSMessage
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

        let frag = DTLSHandshakeFragment::Complete {
            message_seq: self.hs_seq_number,
            payload: msg_payload,
        };
        DTLSMessage {
            typ: ContentType::Handshake,
            version: msg_version,
            epoch: self.epoch,
            sequence: self.seq_number,
            payload: DTLSMessagePayload::Handshake(frag),
        }
    }
}

#[cfg(feature="dtls")]
impl TransportLayer for DatagramTransport {
    fn new(client: bool, mtu: Option<usize>) -> Self {
        DatagramTransport {
            common: TransportCommon::new(client),
            read_seq_bitmask: 0,
            received_plaintext: ChunkVecBuffer::new(),
            sendable_plaintext: ChunkVecBuffer::new(),
            sendable_dtls: ChunkVecBuffer::new(),
            handshake_joiner: DTLSHandshakeJoiner::new(),
            in_transmission: Vec::new(),
            epoch: 0,
            seq_number: 0,
            hs_seq_number: 0,
        }
    }

    fn send_handshake_msg_v10(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = self.handshake_into_msg(ProtocolVersion::DTLSv1_0, transcript, payload);
        transcript.add_message(&msg.payload);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v12(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        let msg = self.handshake_into_msg(ProtocolVersion::DTLSv1_2, transcript, payload);
        transcript.add_message(&msg.payload);
        self.send_msg(msg, secrecy);
    }

    fn send_handshake_msg_v13(&mut self, transcript: &mut hash_hs::HandshakeHash, payload: HandshakePayload, secrecy: MessageSecrecy) {
        unimplemented!()
    }

    fn common(&self) -> &TransportCommon {
        &self.common
    }

    fn mut_common(&mut self) -> &mut TransportCommon {
        &mut self.common
    }

    fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
    }

    fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {:?}", desc);
        let msg = DTLSMessage {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::DTLSv1_2,
            epoch: self.epoch,
            sequence: self.seq_number,
            payload: DTLSMessagePayload::Alert(AlertMessagePayload {
                level: AlertLevel::Warning,
                description: desc,
            }),
        };
        self.send_msg(msg, MessageSecrecy::MayBeUnencrypted);
    }

    fn send_fatal_alert(&mut self, desc: AlertDescription) {
        warn!("Sending fatal alert {:?}", desc);
        let msg = DTLSMessage {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::DTLSv1_2,
            epoch: self.epoch,
            sequence: self.seq_number,
            payload: DTLSMessagePayload::Alert(AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: desc,
            }),
        };
        self.send_msg(msg, MessageSecrecy::MayBeUnencrypted);
    }

    fn send_change_cipher_spec_v12(&mut self, secrecy: MessageSecrecy) {
        let ccs = DTLSMessage {
            typ: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::DTLSv1_2,
            epoch: self.epoch,
            sequence: self.seq_number,
            payload: DTLSMessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
        };

        self.send_msg(ccs, secrecy)
    }
}

#[cfg(feature="dtls")]
#[cfg(test)]
mod tests {
    use super::TransportLayer;
    use super::DatagramTransport;

    #[test]
    fn test_check_seq_number() {
        let mut transport = DatagramTransport::new(true, None);

        // check for exceeding 64 bit window
        assert_eq!(false, transport.check_seq_number(64));
        assert_eq!(false, transport.check_seq_number((1 << 48) - 1));
        assert_eq!(false, transport.check_seq_number(0xffffffffffffffff));

        assert!(transport.check_seq_number(0));

        // check for wrapping
        assert_eq!(false, transport.check_seq_number(0xffffffffffffffff));

        // check for reuse
        for num in 1..128 {
            assert!(transport.check_seq_number(num));
        }
        for num in 0..128 {
            assert_eq!(false, transport.check_seq_number(num));
        }

        // check for unordered packet
        assert!(transport.check_seq_number(128 + 63));
        for num in 128..(128 + 63) {
            assert!(transport.check_seq_number(num));
        }
        assert_eq!(false, transport.check_seq_number(128 + 63));

        // check for overflow
        transport.common.read_seq = 0xffffffffffffffff;
        transport.read_seq_bitmask = 0;
        assert_eq!(false, transport.check_seq_number(0xffffffffffffffff));
        assert_eq!(false, transport.check_seq_number(0));
        assert_eq!(false, transport.check_seq_number(1));
    }
}

