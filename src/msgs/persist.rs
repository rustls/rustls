use msgs::handshake::SessionID;
use msgs::enums::{CipherSuite, ProtocolVersion};
use msgs::codec::{Reader, Codec};
use msgs::handshake::CertificatePayload;
use msgs::base::{PayloadU8, PayloadU16};

use webpki;
use untrusted;

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
    pub fn session_for_dns_name(dns_name: webpki::DNSNameRef) -> ClientSessionKey {
        let dns_name_str: &str = dns_name.into();
        ClientSessionKey {
            kind: b"session",
            dns_name: PayloadU8::new(dns_name_str.as_bytes().to_vec()),
        }
    }

    pub fn hint_for_dns_name(dns_name: webpki::DNSNameRef) -> ClientSessionKey {
        let dns_name_str: &str = dns_name.into();
        ClientSessionKey {
            kind: b"kx-hint",
            dns_name: PayloadU8::new(dns_name_str.as_bytes().to_vec()),
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
    pub age_add: u32,
    pub extended_ms: bool,
}

impl Codec for ClientSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.session_id.encode(bytes);
        self.ticket.encode(bytes);
        self.master_secret.encode(bytes);
        self.epoch.encode(bytes);
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        (if self.extended_ms { 1u8 } else { 0u8 }).encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<ClientSessionValue> {
        let v = ProtocolVersion::read(r)?;
        let cs = CipherSuite::read(r)?;
        let sid = SessionID::read(r)?;
        let ticket = PayloadU16::read(r)?;
        let ms = PayloadU8::read(r)?;
        let epoch = u64::read(r)?;
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let extended_ms = u8::read(r)?;

        Some(ClientSessionValue {
            version: v,
            cipher_suite: cs,
            session_id: sid,
            ticket,
            master_secret: ms,
            epoch,
            lifetime,
            age_add,
            extended_ms: extended_ms == 1u8,
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
            session_id: *sessid,
            ticket: PayloadU16::new(ticket),
            master_secret: PayloadU8::new(ms),
            epoch: 0,
            lifetime: 0,
            age_add: 0,
            extended_ms: false,
        }
    }

    pub fn set_extended_ms_used(&mut self) {
        self.extended_ms = true;
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
    pub sni: Option<webpki::DNSName>,
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub master_secret: PayloadU8,
    pub extended_ms: bool,
    pub client_cert_chain: Option<CertificatePayload>,
}

impl Codec for ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let &Some(ref sni) = &self.sni {
            1u8.encode(bytes);
            let sni_bytes: &str = sni.as_ref().into();
            PayloadU8::new(Vec::from(sni_bytes)).encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.master_secret.encode(bytes);
        (if self.extended_ms { 1u8 } else { 0u8 }).encode(bytes);
        if self.client_cert_chain.is_some() {
            self.client_cert_chain.as_ref().unwrap().encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<ServerSessionValue> {
        let has_sni = u8::read(r)?;
        let sni = if has_sni == 1 {
            let dns_name = PayloadU8::read(r)?;
            let dns_name = webpki::DNSNameRef::try_from_ascii(
                untrusted::Input::from(&dns_name.0)).ok()?;
            Some(dns_name.into())
        } else {
            None
        };
        let v = ProtocolVersion::read(r)?;
        let cs = CipherSuite::read(r)?;
        let ms = PayloadU8::read(r)?;
        let ems = u8::read(r)?;
        let ccert = if r.any_left() {
            CertificatePayload::read(r)
        } else {
            None
        };

        Some(ServerSessionValue {
            sni,
            version: v,
            cipher_suite: cs,
            master_secret: ms,
            extended_ms: ems == 1u8,
            client_cert_chain: ccert,
        })
    }
}

impl ServerSessionValue {
    pub fn new(sni: Option<&webpki::DNSName>,
               v: ProtocolVersion,
               cs: CipherSuite,
               ms: Vec<u8>,
               cert_chain: &Option<CertificatePayload>)
               -> ServerSessionValue {
        ServerSessionValue {
            sni: sni.map(|sni| sni.clone()),
            version: v,
            cipher_suite: cs,
            master_secret: PayloadU8::new(ms),
            extended_ms: false,
            client_cert_chain: cert_chain.clone(),
        }
    }

    pub fn set_extended_ms_used(&mut self) {
        self.extended_ms = true;
    }
}
