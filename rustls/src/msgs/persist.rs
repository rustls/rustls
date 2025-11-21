use alloc::vec::Vec;
use core::cmp;
use core::time::Duration;

use pki_types::{DnsName, UnixTime};
use zeroize::Zeroizing;

use crate::client::config::ClientCredentialResolver;
use crate::crypto::{CipherSuite, Identity};
use crate::enums::ProtocolVersion;
use crate::error::InvalidMessage;
use crate::msgs::base::{MaybeEmpty, PayloadU8, PayloadU16};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::{ProtocolName, SessionId};
use crate::sync::{Arc, Weak};
use crate::tls12::Tls12CipherSuite;
use crate::tls13::Tls13CipherSuite;
use crate::verify::ServerVerifier;

pub(crate) struct Retrieved<T> {
    pub(crate) value: T,
    retrieved_at: UnixTime,
}

impl<T> Retrieved<T> {
    pub(crate) fn new(value: T, retrieved_at: UnixTime) -> Self {
        Self {
            value,
            retrieved_at,
        }
    }

    pub(crate) fn map<M>(&self, f: impl FnOnce(&T) -> Option<&M>) -> Option<Retrieved<&M>> {
        Some(Retrieved {
            value: f(&self.value)?,
            retrieved_at: self.retrieved_at,
        })
    }
}

impl Retrieved<&Tls13ClientSessionValue> {
    pub(crate) fn obfuscated_ticket_age(&self) -> u32 {
        let age_secs = self
            .retrieved_at
            .as_secs()
            .saturating_sub(self.value.common.epoch);
        let age_millis = age_secs as u32 * 1000;
        age_millis.wrapping_add(self.value.age_add)
    }
}

impl<T: core::ops::Deref<Target = ClientSessionCommon>> Retrieved<T> {
    pub(crate) fn has_expired(&self) -> bool {
        let common = &*self.value;
        common.lifetime != Duration::ZERO
            && common
                .epoch
                .saturating_add(common.lifetime.as_secs())
                < self.retrieved_at.as_secs()
    }
}

impl<T> core::ops::Deref for Retrieved<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[derive(Debug)]
pub struct Tls13ClientSessionValue {
    suite: &'static Tls13CipherSuite,
    secret: Zeroizing<PayloadU8>,
    age_add: u32,
    max_early_data_size: u32,
    pub(crate) common: ClientSessionCommon,
    quic_params: PayloadU16,
}

impl Tls13ClientSessionValue {
    pub(crate) fn new(
        suite: &'static Tls13CipherSuite,
        ticket: Arc<PayloadU16>,
        secret: &[u8],
        peer_identity: Identity<'static>,
        server_cert_verifier: &Arc<dyn ServerVerifier>,
        client_creds: &Arc<dyn ClientCredentialResolver>,
        time_now: UnixTime,
        lifetime: Duration,
        age_add: u32,
        max_early_data_size: u32,
    ) -> Self {
        Self {
            suite,
            secret: Zeroizing::new(PayloadU8::new(secret.to_vec())),
            age_add,
            max_early_data_size,
            common: ClientSessionCommon::new(
                ticket,
                time_now,
                lifetime,
                peer_identity,
                server_cert_verifier,
                client_creds,
            ),
            quic_params: PayloadU16::new(Vec::new()),
        }
    }

    pub(crate) fn secret(&self) -> &[u8] {
        self.secret.0.as_ref()
    }

    pub fn max_early_data_size(&self) -> u32 {
        self.max_early_data_size
    }

    pub fn suite(&self) -> &'static Tls13CipherSuite {
        self.suite
    }

    /// Test only: rewind epoch by `delta` seconds.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch -= delta as u64;
    }

    /// Test only: replace `max_early_data_size` with `new`
    #[doc(hidden)]
    pub fn _private_set_max_early_data_size(&mut self, new: u32) {
        self.max_early_data_size = new;
    }

    pub fn set_quic_params(&mut self, quic_params: &[u8]) {
        self.quic_params = PayloadU16::new(quic_params.to_vec());
    }

    pub fn quic_params(&self) -> Vec<u8> {
        self.quic_params.0.clone()
    }
}

impl core::ops::Deref for Tls13ClientSessionValue {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug, Clone)]
pub struct Tls12ClientSessionValue {
    suite: &'static Tls12CipherSuite,
    pub(crate) session_id: SessionId,
    master_secret: Zeroizing<[u8; 48]>,
    extended_ms: bool,
    #[doc(hidden)]
    pub(crate) common: ClientSessionCommon,
}

impl Tls12ClientSessionValue {
    pub(crate) fn new(
        suite: &'static Tls12CipherSuite,
        session_id: SessionId,
        ticket: Arc<PayloadU16>,
        master_secret: &[u8; 48],
        peer_identity: Identity<'static>,
        server_cert_verifier: &Arc<dyn ServerVerifier>,
        client_creds: &Arc<dyn ClientCredentialResolver>,
        time_now: UnixTime,
        lifetime: Duration,
        extended_ms: bool,
    ) -> Self {
        Self {
            suite,
            session_id,
            master_secret: Zeroizing::new(*master_secret),
            extended_ms,
            common: ClientSessionCommon::new(
                ticket,
                time_now,
                lifetime,
                peer_identity,
                server_cert_verifier,
                client_creds,
            ),
        }
    }

    pub(crate) fn master_secret(&self) -> &[u8; 48] {
        &self.master_secret
    }

    pub(crate) fn ticket(&mut self) -> Arc<PayloadU16> {
        self.common.ticket.clone()
    }

    pub(crate) fn extended_ms(&self) -> bool {
        self.extended_ms
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    /// Test only: rewind epoch by `delta` seconds.
    #[doc(hidden)]
    pub fn rewind_epoch(&mut self, delta: u32) {
        self.common.epoch -= delta as u64;
    }
}

impl core::ops::Deref for Tls12ClientSessionValue {
    type Target = ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

#[derive(Debug, Clone)]
pub struct ClientSessionCommon {
    ticket: Arc<PayloadU16>,
    epoch: u64,
    lifetime: Duration,
    peer_identity: Arc<Identity<'static>>,
    server_cert_verifier: Weak<dyn ServerVerifier>,
    client_creds: Weak<dyn ClientCredentialResolver>,
}

impl ClientSessionCommon {
    fn new(
        ticket: Arc<PayloadU16>,
        time_now: UnixTime,
        lifetime: Duration,
        peer_identity: Identity<'static>,
        server_cert_verifier: &Arc<dyn ServerVerifier>,
        client_creds: &Arc<dyn ClientCredentialResolver>,
    ) -> Self {
        Self {
            ticket,
            epoch: time_now.as_secs(),
            lifetime: cmp::min(lifetime, MAX_TICKET_LIFETIME),
            peer_identity: Arc::new(peer_identity),
            server_cert_verifier: Arc::downgrade(server_cert_verifier),
            client_creds: Arc::downgrade(client_creds),
        }
    }

    pub(crate) fn compatible_config(
        &self,
        server_cert_verifier: &Arc<dyn ServerVerifier>,
        client_creds: &Arc<dyn ClientCredentialResolver>,
    ) -> bool {
        let same_verifier = Weak::ptr_eq(
            &Arc::downgrade(server_cert_verifier),
            &self.server_cert_verifier,
        );
        let same_creds = Weak::ptr_eq(&Arc::downgrade(client_creds), &self.client_creds);

        match (same_verifier, same_creds) {
            (true, true) => true,
            (false, _) => {
                crate::log::trace!("resumption not allowed between different ServerVerifiers");
                false
            }
            (_, _) => {
                crate::log::trace!(
                    "resumption not allowed between different ClientCredentialResolver values"
                );
                false
            }
        }
    }

    pub(crate) fn peer_identity(&self) -> &Identity<'static> {
        &self.peer_identity
    }

    pub(crate) fn ticket(&self) -> &[u8] {
        self.ticket.0.as_ref()
    }
}

static MAX_TICKET_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// This is the maximum allowed skew between server and client clocks, over
/// the maximum ticket lifetime period.  This encompasses TCP retransmission
/// times in case packet loss occurs when the client sends the ClientHello
/// or receives the NewSessionTicket, _and_ actual clock skew over this period.
static MAX_FRESHNESS_SKEW_MS: u32 = 60 * 1000;

// --- Server types ---
#[non_exhaustive]
#[derive(Debug)]
pub enum ServerSessionValue {
    Tls12(Tls12ServerSessionValue),
    Tls13(Tls13ServerSessionValue),
}

impl Codec<'_> for ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Tls12(value) => {
                ProtocolVersion::TLSv1_2.encode(bytes);
                value.encode(bytes);
            }
            Self::Tls13(value) => {
                ProtocolVersion::TLSv1_3.encode(bytes);
                value.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match ProtocolVersion::read(r)? {
            ProtocolVersion::TLSv1_2 => Ok(Self::Tls12(Tls12ServerSessionValue::read(r)?)),
            ProtocolVersion::TLSv1_3 => Ok(Self::Tls13(Tls13ServerSessionValue::read(r)?)),
            _ => Err(InvalidMessage::UnknownProtocolVersion),
        }
    }
}

#[derive(Debug)]
pub struct Tls12ServerSessionValue {
    #[doc(hidden)]
    pub common: CommonServerSessionValue,
    pub(crate) master_secret: Zeroizing<[u8; 48]>,
    pub(crate) extended_ms: bool,
}

impl Tls12ServerSessionValue {
    pub(crate) fn new(
        common: CommonServerSessionValue,
        master_secret: &[u8; 48],
        extended_ms: bool,
    ) -> Self {
        Self {
            common,
            master_secret: Zeroizing::new(*master_secret),
            extended_ms,
        }
    }
}

impl Codec<'_> for Tls12ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        bytes.extend_from_slice(self.master_secret.as_ref());
        (self.extended_ms as u8).encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            master_secret: Zeroizing::new(
                match r
                    .take(48)
                    .and_then(|slice| slice.try_into().ok())
                {
                    Some(array) => array,
                    None => return Err(InvalidMessage::MessageTooShort),
                },
            ),
            extended_ms: matches!(u8::read(r)?, 1),
        })
    }
}

impl From<Tls12ServerSessionValue> for ServerSessionValue {
    fn from(value: Tls12ServerSessionValue) -> Self {
        Self::Tls12(value)
    }
}

#[derive(Debug)]
pub struct Tls13ServerSessionValue {
    #[doc(hidden)]
    pub common: CommonServerSessionValue,
    pub(crate) secret: Zeroizing<PayloadU8>,
    pub(crate) age_obfuscation_offset: u32,

    // not encoded vv
    freshness: Option<bool>,
}

impl Tls13ServerSessionValue {
    pub(crate) fn new(
        common: CommonServerSessionValue,
        secret: &[u8],
        age_obfuscation_offset: u32,
    ) -> Self {
        Self {
            common,
            secret: Zeroizing::new(PayloadU8::new(secret.to_vec())),
            age_obfuscation_offset,
            freshness: None,
        }
    }

    pub(crate) fn set_freshness(
        mut self,
        obfuscated_client_age_ms: u32,
        time_now: UnixTime,
    ) -> Self {
        let client_age_ms = obfuscated_client_age_ms.wrapping_sub(self.age_obfuscation_offset);
        let server_age_ms = (time_now
            .as_secs()
            .saturating_sub(self.common.creation_time_sec) as u32)
            .saturating_mul(1000);

        let age_difference = server_age_ms.abs_diff(client_age_ms);

        self.freshness = Some(age_difference <= MAX_FRESHNESS_SKEW_MS);
        self
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.freshness.unwrap_or_default()
    }
}

impl Codec<'_> for Tls13ServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.common.encode(bytes);
        self.secret.encode(bytes);
        self.age_obfuscation_offset
            .encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            common: CommonServerSessionValue::read(r)?,
            secret: Zeroizing::new(PayloadU8::read(r)?),
            age_obfuscation_offset: u32::read(r)?,
            freshness: None,
        })
    }
}

impl From<Tls13ServerSessionValue> for ServerSessionValue {
    fn from(value: Tls13ServerSessionValue) -> Self {
        Self::Tls13(value)
    }
}

#[derive(Debug)]
pub struct CommonServerSessionValue {
    pub(crate) sni: Option<DnsName<'static>>,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) peer_identity: Option<Identity<'static>>,
    pub(crate) alpn: Option<ProtocolName>,
    pub(crate) application_data: PayloadU16,
    #[doc(hidden)]
    pub creation_time_sec: u64,
}

impl CommonServerSessionValue {
    pub(crate) fn new(
        sni: Option<&DnsName<'_>>,
        cipher_suite: CipherSuite,
        peer_identity: Option<Identity<'static>>,
        alpn: Option<ProtocolName>,
        application_data: Vec<u8>,
        creation_time: UnixTime,
    ) -> Self {
        Self {
            sni: sni.map(|s| s.to_owned()),
            cipher_suite,
            peer_identity,
            alpn,
            application_data: PayloadU16::new(application_data),
            creation_time_sec: creation_time.as_secs(),
        }
    }

    pub(crate) fn can_resume(&self, suite: CipherSuite, sni: &Option<DnsName<'_>>) -> bool {
        // The RFCs underspecify what happens if we try to resume to
        // an unoffered/varying suite.  We merely don't resume in weird cases.
        //
        // RFC 6066 says "A server that implements this extension MUST NOT accept
        // the request to resume the session if the server_name extension contains
        // a different name. Instead, it proceeds with a full handshake to
        // establish a new session."
        //
        // RFC 8446: "The server MUST ensure that it selects
        // a compatible PSK (if any) and cipher suite."
        self.cipher_suite == suite && &self.sni == sni
    }
}

impl Codec<'_> for CommonServerSessionValue {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let Some(sni) = &self.sni {
            1u8.encode(bytes);
            let sni_bytes: &str = sni.as_ref();
            PayloadU8::<MaybeEmpty>::encode_slice(sni_bytes.as_bytes(), bytes);
        } else {
            0u8.encode(bytes);
        }
        self.cipher_suite.encode(bytes);
        if let Some(identity) = &self.peer_identity {
            1u8.encode(bytes);
            identity.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        if let Some(alpn) = &self.alpn {
            1u8.encode(bytes);
            alpn.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        self.application_data.encode(bytes);
        self.creation_time_sec.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let sni = match u8::read(r)? {
            1 => {
                let dns_name = PayloadU8::<MaybeEmpty>::read(r)?;
                let dns_name = match DnsName::try_from(dns_name.0.as_slice()) {
                    Ok(dns_name) => dns_name.to_owned(),
                    Err(_) => return Err(InvalidMessage::InvalidServerName),
                };

                Some(dns_name)
            }
            _ => None,
        };

        Ok(Self {
            sni,
            cipher_suite: CipherSuite::read(r)?,
            peer_identity: match u8::read(r)? {
                1 => Some(Identity::read(r)?.into_owned()),
                _ => None,
            },
            alpn: match u8::read(r)? {
                1 => Some(ProtocolName::read(r)?),
                _ => None,
            },
            application_data: PayloadU16::read(r)?,
            creation_time_sec: u64::read(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use pki_types::CertificateDer;

    use super::*;
    use crate::crypto::CertificateIdentity;

    #[cfg(feature = "std")] // for UnixTime::now
    #[test]
    fn serversessionvalue_is_debug() {
        use std::{println, vec};
        let ssv = ServerSessionValue::Tls13(Tls13ServerSessionValue::new(
            CommonServerSessionValue::new(
                None,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                None,
                None,
                vec![4, 5, 6],
                UnixTime::now(),
            ),
            &[1, 2, 3],
            0x12345678,
        ));
        println!("{ssv:?}");
        println!("{:#04x?}", ssv.get_encoding());
    }

    #[test]
    fn serversessionvalue_no_sni() {
        let bytes = [
            0x03, 0x04, 0x00, 0x13, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x68, 0x6e, 0x94, 0x32, 0x03, 0x01, 0x02, 0x03, 0x12, 0x34, 0x56, 0x78,
        ];
        let mut rd = Reader::init(&bytes);
        let ssv = ServerSessionValue::read(&mut rd).unwrap();
        assert_eq!(ssv.get_encoding(), bytes);
    }

    #[test]
    fn serversessionvalue_with_cert() {
        std::eprintln!(
            "{:#04x?}",
            ServerSessionValue::Tls13(Tls13ServerSessionValue::new(
                CommonServerSessionValue::new(
                    None,
                    CipherSuite::TLS13_AES_128_GCM_SHA256,
                    Some(Identity::X509(CertificateIdentity {
                        end_entity: CertificateDer::from(&[10, 11, 12][..]),
                        intermediates: alloc::vec![],
                    })),
                    None,
                    alloc::vec![4, 5, 6],
                    UnixTime::now(),
                ),
                &[1, 2, 3],
                0x12345678,
            ))
            .get_encoding()
        );

        let bytes = [
            0x03, 0x04, 0x00, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x68, 0xc1,
            0x99, 0xac, 0x03, 0x01, 0x02, 0x03, 0x12, 0x34, 0x56, 0x78,
        ];
        let mut rd = Reader::init(&bytes);
        let ssv = ServerSessionValue::read(&mut rd).unwrap();
        assert_eq!(ssv.get_encoding(), bytes);
    }
}
