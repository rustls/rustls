use msgs::handshake::SessionID;
use msgs::enums::{CipherSuite, ProtocolVersion};
use msgs::codec::{Reader, Codec};
use msgs::handshake::CertificatePayload;
use msgs::base::{PayloadU8, PayloadU16};
use msgs::codec;

use std::mem;
use std::cmp;

// These are the keys and values we store in session storage.

// --- Client types ---
/// Keys for session resumption and tickets.
/// Matching value is a `ClientSessionValue`.
#[derive(Debug)]
pub struct ClientSessionKey {
    kind: &'static [u8],
    dns_name: PayloadU8,
}

impl Codec for ClientSessionKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.kind);
        self.dns_name.encode(bytes);
    }

    // Don't need to read these.
    fn read(_r: &mut Reader) -> Option<ClientSessionKey> {
        None
    }
}

impl ClientSessionKey {
    pub fn session_for_dns_name(dns_name: &str) -> ClientSessionKey {
        ClientSessionKey {
            kind: b"session",
            dns_name: PayloadU8::new(dns_name.as_bytes().to_vec()),
        }
    }

    pub fn hint_for_dns_name(dns_name: &str) -> ClientSessionKey {
        ClientSessionKey {
            kind: b"kx-hint",
            dns_name: PayloadU8::new(dns_name.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug)]
pub struct ClientSessionValue {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub session_id: SessionID,
    pub ticket: PayloadU16,
    pub master_secret: PayloadU8,
    pub epoch: u64,
    pub lifetime: u32,
    pub age_add: u32
}

impl Codec for ClientSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.session_id.encode(bytes);
        self.ticket.encode(bytes);
        self.master_secret.encode(bytes);
        codec::encode_u64(self.epoch, bytes);
        codec::encode_u32(self.lifetime, bytes);
        codec::encode_u32(self.age_add, bytes);
    }

    fn read(r: &mut Reader) -> Option<ClientSessionValue> {
        let v = try_ret!(ProtocolVersion::read(r));
        let cs = try_ret!(CipherSuite::read(r));
        let sid = try_ret!(SessionID::read(r));
        let ticket = try_ret!(PayloadU16::read(r));
        let ms = try_ret!(PayloadU8::read(r));
        let epoch = try_ret!(codec::read_u64(r));
        let lifetime = try_ret!(codec::read_u32(r));
        let age_add = try_ret!(codec::read_u32(r));

        Some(ClientSessionValue {
            version: v,
            cipher_suite: cs,
            session_id: sid,
            ticket: ticket,
            master_secret: ms,
            epoch: epoch,
            lifetime: lifetime,
            age_add: age_add
        })
    }
}

static MAX_TICKET_LIFETIME: u32 = 7 * 24 * 60 * 60;

impl ClientSessionValue {
    pub fn new(v: ProtocolVersion,
               cs: CipherSuite,
               sessid: &SessionID,
               ticket: Vec<u8>,
               ms: Vec<u8>)
               -> ClientSessionValue {
        ClientSessionValue {
            version: v,
            cipher_suite: cs,
            session_id: sessid.clone(),
            ticket: PayloadU16::new(ticket),
            master_secret: PayloadU8::new(ms),
            epoch: 0,
            lifetime: 0,
            age_add: 0
        }
    }

    pub fn set_times(&mut self, receipt_time_secs: u64,
                     lifetime_secs: u32, age_add: u32) {
        self.epoch = receipt_time_secs;
        self.lifetime = cmp::min(lifetime_secs, MAX_TICKET_LIFETIME);
        self.age_add = age_add;
    }

    pub fn has_expired(&self, time_now: u64) -> bool {
        self.lifetime != 0 && self.epoch + (self.lifetime as u64) < time_now
    }

    pub fn get_obfuscated_ticket_age(&self, time_now: u64) -> u32 {
        let age_secs = time_now.saturating_sub(self.epoch);
        let age_millis = age_secs as u32 * 1000;
        age_millis.wrapping_sub(self.age_add)
    }

    pub fn take_ticket(&mut self) -> Vec<u8> {
        let new_ticket = PayloadU16::new(Vec::new());
        let old_ticket = mem::replace(&mut self.ticket, new_ticket);
        old_ticket.0
    }
}

// --- Server types ---
pub type ServerSessionKey = SessionID;

#[derive(Debug)]
pub struct ServerSessionValue {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub master_secret: PayloadU8,
    pub client_cert_chain: Option<CertificatePayload>,
}

impl Codec for ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.master_secret.encode(bytes);
        if self.client_cert_chain.is_some() {
            self.client_cert_chain.as_ref().unwrap().encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<ServerSessionValue> {
        let v = try_ret!(ProtocolVersion::read(r));
        let cs = try_ret!(CipherSuite::read(r));
        let ms = try_ret!(PayloadU8::read(r));
        let ccert = if r.any_left() {
            CertificatePayload::read(r)
        } else {
            None
        };

        Some(ServerSessionValue {
            version: v,
            cipher_suite: cs,
            master_secret: ms,
            client_cert_chain: ccert,
        })
    }
}

impl ServerSessionValue {
    pub fn new(v: ProtocolVersion,
               cs: CipherSuite,
               ms: Vec<u8>,
               cert_chain: &Option<CertificatePayload>)
               -> ServerSessionValue {
        ServerSessionValue {
            version: v,
            cipher_suite: cs,
            master_secret: PayloadU8::new(ms),
            client_cert_chain: cert_chain.clone(),
        }
    }
}
