#![allow(non_camel_case_types)]

#[cfg(feature = "tls12")]
use crate::crypto::ActiveKeyExchange;
use crate::crypto::SecureRandom;
use crate::enums::{CipherSuite, HandshakeType, ProtocolVersion, SignatureScheme};
use crate::error::InvalidMessage;
#[cfg(feature = "logging")]
use crate::log::warn;
use crate::msgs::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use crate::msgs::codec::{self, Codec, LengthPrefixedBuffer, ListLength, Reader, TlsListElement};
use crate::msgs::enums::{
    CertificateStatusType, ClientCertificateType, Compression, ECCurveType, ECPointFormat,
    EchVersion, ExtensionType, HpkeAead, HpkeKdf, HpkeKem, KeyUpdateRequest, NamedGroup,
    PSKKeyExchangeMode, ServerNameType,
};
use crate::rand;
use crate::verify::DigitallySignedStruct;
use crate::x509::wrap_in_sequence;

use pki_types::{CertificateDer, DnsName};

use alloc::collections::BTreeSet;
#[cfg(feature = "logging")]
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// Create a newtype wrapper around a given type.
///
/// This is used to create newtypes for the various TLS message types which is used to wrap
/// the `PayloadU8` or `PayloadU16` types. This is typically used for types where we don't need
/// anything other than access to the underlying bytes.
macro_rules! wrapped_payload(
  ($(#[$comment:meta])* $vis:vis struct $name:ident, $inner:ident,) => {
    $(#[$comment])*
    #[derive(Clone, Debug)]
    $vis struct $name($inner);

    impl From<Vec<u8>> for $name {
        fn from(v: Vec<u8>) -> Self {
            Self($inner::new(v))
        }
    }

    impl AsRef<[u8]> for $name {
        fn as_ref(&self) -> &[u8] {
            self.0.0.as_slice()
        }
    }

    impl Codec for $name {
        fn encode(&self, bytes: &mut Vec<u8>) {
            self.0.encode(bytes);
        }

        fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
            Ok(Self($inner::read(r)?))
        }
    }
  }
);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Random(pub(crate) [u8; 32]);

impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, &self.0)
    }
}

static HELLO_RETRY_REQUEST_RANDOM: Random = Random([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

static ZERO_RANDOM: Random = Random([0u8; 32]);

impl Codec for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let bytes = match r.take(32) {
            Some(bytes) => bytes,
            None => return Err(InvalidMessage::MissingData("Random")),
        };

        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);
        Ok(Self(opaque))
    }
}

impl Random {
    pub(crate) fn new(secure_random: &dyn SecureRandom) -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        secure_random.fill(&mut data)?;
        Ok(Self(data))
    }
}

impl From<[u8; 32]> for Random {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Copy, Clone)]
pub struct SessionId {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, &self.data[..self.len])
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.data[i] ^ other.data[i];
        }

        diff == 0u8
    }
}

impl Codec for SessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        if len > 32 {
            return Err(InvalidMessage::TrailingData("SessionID"));
        }

        let bytes = match r.take(len) {
            Some(bytes) => bytes,
            None => return Err(InvalidMessage::MissingData("SessionID")),
        };

        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);
        Ok(Self { data: out, len })
    }
}

impl SessionId {
    pub fn random(secure_random: &dyn SecureRandom) -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        secure_random.fill(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    pub(crate) fn empty() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Debug)]
pub struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload,
}

impl UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut Reader) -> Self {
        let payload = Payload::read(r);
        Self { typ, payload }
    }
}

impl TlsListElement for ECPointFormat {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for NamedGroup {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for SignatureScheme {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub(crate) enum ServerNamePayload {
    HostName(DnsName<'static>),
    Unknown(Payload),
}

impl ServerNamePayload {
    pub(crate) fn new_hostname(hostname: DnsName<'static>) -> Self {
        Self::HostName(hostname)
    }

    fn read_hostname(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let raw = PayloadU16::read(r)?;

        match DnsName::try_from(raw.0.as_slice()) {
            Ok(dns_name) => Ok(Self::HostName(dns_name.to_owned())),
            Err(_) => {
                warn!(
                    "Illegal SNI hostname received {:?}",
                    String::from_utf8_lossy(&raw.0)
                );
                Err(InvalidMessage::InvalidServerName)
            }
        }
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::HostName(ref name) => {
                (name.as_ref().len() as u16).encode(bytes);
                bytes.extend_from_slice(name.as_ref().as_bytes());
            }
            Self::Unknown(ref r) => r.encode(bytes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerName {
    pub(crate) typ: ServerNameType,
    pub(crate) payload: ServerNamePayload,
}

impl Codec for ServerName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r)),
        };

        Ok(Self { typ, payload })
    }
}

impl TlsListElement for ServerName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait ConvertServerNameList {
    fn has_duplicate_names_for_type(&self) -> bool;
    fn get_single_hostname(&self) -> Option<DnsName<'_>>;
}

impl ConvertServerNameList for [ServerName] {
    /// RFC6066: "The ServerNameList MUST NOT contain more than one name of the same name_type."
    fn has_duplicate_names_for_type(&self) -> bool {
        let mut seen = BTreeSet::new();

        for name in self {
            if !seen.insert(name.typ.get_u8()) {
                return true;
            }
        }

        false
    }

    fn get_single_hostname(&self) -> Option<DnsName<'_>> {
        fn only_dns_hostnames(name: &ServerName) -> Option<DnsName<'_>> {
            if let ServerNamePayload::HostName(ref dns) = name.payload {
                Some(dns.borrow())
            } else {
                None
            }
        }

        self.iter()
            .filter_map(only_dns_hostnames)
            .next()
    }
}

wrapped_payload!(pub struct ProtocolName, PayloadU8,);

impl TlsListElement for ProtocolName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait ConvertProtocolNameList {
    fn from_slices(names: &[&[u8]]) -> Self;
    fn to_slices(&self) -> Vec<&[u8]>;
    fn as_single_slice(&self) -> Option<&[u8]>;
}

impl ConvertProtocolNameList for Vec<ProtocolName> {
    fn from_slices(names: &[&[u8]]) -> Self {
        let mut ret = Self::new();

        for name in names {
            ret.push(ProtocolName::from(name.to_vec()));
        }

        ret
    }

    fn to_slices(&self) -> Vec<&[u8]> {
        self.iter()
            .map(|proto| proto.as_ref())
            .collect::<Vec<&[u8]>>()
    }

    fn as_single_slice(&self) -> Option<&[u8]> {
        if self.len() == 1 {
            Some(self[0].as_ref())
        } else {
            None
        }
    }
}

// --- TLS 1.3 Key shares ---
#[derive(Clone, Debug)]
pub struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    pub(crate) payload: PayloadU16,
}

impl KeyShareEntry {
    pub fn new(group: NamedGroup, payload: &[u8]) -> Self {
        Self {
            group,
            payload: PayloadU16::new(payload.to_vec()),
        }
    }

    pub fn group(&self) -> NamedGroup {
        self.group
    }
}

impl Codec for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let group = NamedGroup::read(r)?;
        let payload = PayloadU16::read(r)?;

        Ok(Self { group, payload })
    }
}

// --- TLS 1.3 PresharedKey offers ---
#[derive(Clone, Debug)]
pub(crate) struct PresharedKeyIdentity {
    pub(crate) identity: PayloadU16,
    pub(crate) obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity {
    pub(crate) fn new(id: Vec<u8>, age: u32) -> Self {
        Self {
            identity: PayloadU16::new(id),
            obfuscated_ticket_age: age,
        }
    }
}

impl Codec for PresharedKeyIdentity {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            identity: PayloadU16::read(r)?,
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

impl TlsListElement for PresharedKeyIdentity {
    const SIZE_LEN: ListLength = ListLength::U16;
}

wrapped_payload!(pub(crate) struct PresharedKeyBinder, PayloadU8,);

impl TlsListElement for PresharedKeyBinder {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct PresharedKeyOffer {
    pub(crate) identities: Vec<PresharedKeyIdentity>,
    pub(crate) binders: Vec<PresharedKeyBinder>,
}

impl PresharedKeyOffer {
    /// Make a new one with one entry.
    pub(crate) fn new(id: PresharedKeyIdentity, binder: Vec<u8>) -> Self {
        Self {
            identities: vec![id],
            binders: vec![PresharedKeyBinder::from(binder)],
        }
    }
}

impl Codec for PresharedKeyOffer {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identities.encode(bytes);
        self.binders.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            identities: Vec::read(r)?,
            binders: Vec::read(r)?,
        })
    }
}

// --- RFC6066 certificate status request ---
wrapped_payload!(pub(crate) struct ResponderId, PayloadU16,);

impl TlsListElement for ResponderId {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct OcspCertificateStatusRequest {
    pub(crate) responder_ids: Vec<ResponderId>,
    pub(crate) extensions: PayloadU16,
}

impl Codec for OcspCertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.responder_ids.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            responder_ids: Vec::read(r)?,
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CertificateStatusRequest {
    Ocsp(OcspCertificateStatusRequest),
    Unknown((CertificateStatusType, Payload)),
}

impl Codec for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ocsp(ref r) => r.encode(bytes),
            Self::Unknown((typ, payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => {
                let ocsp_req = OcspCertificateStatusRequest::read(r)?;
                Ok(Self::Ocsp(ocsp_req))
            }
            _ => {
                let data = Payload::read(r);
                Ok(Self::Unknown((typ, data)))
            }
        }
    }
}

impl CertificateStatusRequest {
    pub(crate) fn build_ocsp() -> Self {
        let ocsp = OcspCertificateStatusRequest {
            responder_ids: Vec::new(),
            extensions: PayloadU16::empty(),
        };
        Self::Ocsp(ocsp)
    }
}

// ---

impl TlsListElement for PSKKeyExchangeMode {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for KeyShareEntry {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for ProtocolVersion {
    const SIZE_LEN: ListLength = ListLength::U8;
}

#[derive(Clone, Debug)]
pub enum ClientExtension {
    EcPointFormats(Vec<ECPointFormat>),
    NamedGroups(Vec<NamedGroup>),
    SignatureAlgorithms(Vec<SignatureScheme>),
    ServerName(Vec<ServerName>),
    SessionTicket(ClientSessionTicket),
    Protocols(Vec<ProtocolName>),
    SupportedVersions(Vec<ProtocolVersion>),
    KeyShare(Vec<KeyShareEntry>),
    PresharedKeyModes(Vec<PSKKeyExchangeMode>),
    PresharedKey(PresharedKeyOffer),
    Cookie(PayloadU16),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(CertificateStatusRequest),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    Unknown(UnknownExtension),
}

impl ClientExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::EcPointFormats(_) => ExtensionType::ECPointFormats,
            Self::NamedGroups(_) => ExtensionType::EllipticCurves,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SessionTicket(_) => ExtensionType::SessionTicket,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKeyModes(_) => ExtensionType::PSKKeyExchangeModes,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::ExtendedMasterSecretRequest => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusRequest(_) => ExtensionType::StatusRequest,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::EcPointFormats(ref r) => r.encode(nested.buf),
            Self::NamedGroups(ref r) => r.encode(nested.buf),
            Self::SignatureAlgorithms(ref r) => r.encode(nested.buf),
            Self::ServerName(ref r) => r.encode(nested.buf),
            Self::SessionTicket(ClientSessionTicket::Request)
            | Self::ExtendedMasterSecretRequest
            | Self::EarlyData => {}
            Self::SessionTicket(ClientSessionTicket::Offer(ref r)) => r.encode(nested.buf),
            Self::Protocols(ref r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::KeyShare(ref r) => r.encode(nested.buf),
            Self::PresharedKeyModes(ref r) => r.encode(nested.buf),
            Self::PresharedKey(ref r) => r.encode(nested.buf),
            Self::Cookie(ref r) => r.encode(nested.buf),
            Self::CertificateStatusRequest(ref r) => r.encode(nested.buf),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => Self::EcPointFormats(Vec::read(&mut sub)?),
            ExtensionType::EllipticCurves => Self::NamedGroups(Vec::read(&mut sub)?),
            ExtensionType::SignatureAlgorithms => Self::SignatureAlgorithms(Vec::read(&mut sub)?),
            ExtensionType::ServerName => Self::ServerName(Vec::read(&mut sub)?),
            ExtensionType::SessionTicket => {
                if sub.any_left() {
                    let contents = Payload::read(&mut sub);
                    Self::SessionTicket(ClientSessionTicket::Offer(contents))
                } else {
                    Self::SessionTicket(ClientSessionTicket::Request)
                }
            }
            ExtensionType::ALProtocolNegotiation => Self::Protocols(Vec::read(&mut sub)?),
            ExtensionType::SupportedVersions => Self::SupportedVersions(Vec::read(&mut sub)?),
            ExtensionType::KeyShare => Self::KeyShare(Vec::read(&mut sub)?),
            ExtensionType::PSKKeyExchangeModes => Self::PresharedKeyModes(Vec::read(&mut sub)?),
            ExtensionType::PreSharedKey => Self::PresharedKey(PresharedKeyOffer::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret if !sub.any_left() => {
                Self::ExtendedMasterSecretRequest
            }
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                Self::CertificateStatusRequest(csr)
            }
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData if !sub.any_left() => Self::EarlyData,
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("ClientExtension")
            .map(|_| ext)
    }
}

fn trim_hostname_trailing_dot_for_sni(dns_name: &DnsName<'_>) -> DnsName<'static> {
    let dns_name_str = dns_name.as_ref();

    // RFC6066: "The hostname is represented as a byte string using
    // ASCII encoding without a trailing dot"
    if dns_name_str.ends_with('.') {
        let trimmed = &dns_name_str[0..dns_name_str.len() - 1];
        DnsName::try_from(trimmed)
            .unwrap()
            .to_owned()
    } else {
        dns_name.to_owned()
    }
}

impl ClientExtension {
    /// Make a basic SNI ServerNameRequest quoting `hostname`.
    pub(crate) fn make_sni(dns_name: &DnsName<'_>) -> Self {
        let name = ServerName {
            typ: ServerNameType::HostName,
            payload: ServerNamePayload::new_hostname(trim_hostname_trailing_dot_for_sni(dns_name)),
        };

        Self::ServerName(vec![name])
    }
}

#[derive(Clone, Debug)]
pub enum ClientSessionTicket {
    Request,
    Offer(Payload),
}

#[derive(Clone, Debug)]
pub enum ServerExtension {
    EcPointFormats(Vec<ECPointFormat>),
    ServerNameAck,
    SessionTicketAck,
    RenegotiationInfo(PayloadU8),
    Protocols(Vec<ProtocolName>),
    KeyShare(KeyShareEntry),
    PresharedKey(u16),
    ExtendedMasterSecretAck,
    CertificateStatusAck,
    SupportedVersions(ProtocolVersion),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    Unknown(UnknownExtension),
}

impl ServerExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::EcPointFormats(_) => ExtensionType::ECPointFormats,
            Self::ServerNameAck => ExtensionType::ServerName,
            Self::SessionTicketAck => ExtensionType::SessionTicket,
            Self::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusAck => ExtensionType::StatusRequest,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec for ServerExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::EcPointFormats(ref r) => r.encode(nested.buf),
            Self::ServerNameAck
            | Self::SessionTicketAck
            | Self::ExtendedMasterSecretAck
            | Self::CertificateStatusAck
            | Self::EarlyData => {}
            Self::RenegotiationInfo(ref r) => r.encode(nested.buf),
            Self::Protocols(ref r) => r.encode(nested.buf),
            Self::KeyShare(ref r) => r.encode(nested.buf),
            Self::PresharedKey(r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => Self::EcPointFormats(Vec::read(&mut sub)?),
            ExtensionType::ServerName => Self::ServerNameAck,
            ExtensionType::SessionTicket => Self::SessionTicketAck,
            ExtensionType::StatusRequest => Self::CertificateStatusAck,
            ExtensionType::RenegotiationInfo => Self::RenegotiationInfo(PayloadU8::read(&mut sub)?),
            ExtensionType::ALProtocolNegotiation => Self::Protocols(Vec::read(&mut sub)?),
            ExtensionType::KeyShare => Self::KeyShare(KeyShareEntry::read(&mut sub)?),
            ExtensionType::PreSharedKey => Self::PresharedKey(u16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret => Self::ExtendedMasterSecretAck,
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData => Self::EarlyData,
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("ServerExtension")
            .map(|_| ext)
    }
}

impl ServerExtension {
    pub(crate) fn make_alpn(proto: &[&[u8]]) -> Self {
        Self::Protocols(Vec::from_slices(proto))
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn make_empty_renegotiation_info() -> Self {
        let empty = Vec::new();
        Self::RenegotiationInfo(PayloadU8::new(empty))
    }
}

#[derive(Debug)]
pub struct ClientHelloPayload {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<Compression>,
    pub extensions: Vec<ClientExtension>,
}

impl Codec for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);

        if !self.extensions.is_empty() {
            self.extensions.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let mut ret = Self {
            client_version: ProtocolVersion::read(r)?,
            random: Random::read(r)?,
            session_id: SessionId::read(r)?,
            cipher_suites: Vec::read(r)?,
            compression_methods: Vec::read(r)?,
            extensions: Vec::new(),
        };

        if r.any_left() {
            ret.extensions = Vec::read(r)?;
        }

        match (r.any_left(), ret.extensions.is_empty()) {
            (true, _) => Err(InvalidMessage::TrailingData("ClientHelloPayload")),
            (_, true) => Err(InvalidMessage::MissingData("ClientHelloPayload")),
            _ => Ok(ret),
        }
    }
}

impl TlsListElement for CipherSuite {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for Compression {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for ClientExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl ClientHelloPayload {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub(crate) fn has_duplicate_extension(&self) -> bool {
        let mut seen = BTreeSet::new();

        for ext in &self.extensions {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
        self.extensions
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub(crate) fn get_sni_extension(&self) -> Option<&[ServerName]> {
        let ext = self.find_extension(ExtensionType::ServerName)?;
        match *ext {
            ClientExtension::ServerName(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_sigalgs_extension(&self) -> Option<&[SignatureScheme]> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            ClientExtension::SignatureAlgorithms(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn get_namedgroups_extension(&self) -> Option<&[NamedGroup]> {
        let ext = self.find_extension(ExtensionType::EllipticCurves)?;
        match *ext {
            ClientExtension::NamedGroups(ref req) => Some(req),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn get_ecpoints_extension(&self) -> Option<&[ECPointFormat]> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ClientExtension::EcPointFormats(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn get_alpn_extension(&self) -> Option<&Vec<ProtocolName>> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ClientExtension::Protocols(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn get_quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ClientExtension::TransportParameters(ref bytes)
            | ClientExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn get_ticket_extension(&self) -> Option<&ClientExtension> {
        self.find_extension(ExtensionType::SessionTicket)
    }

    pub(crate) fn get_versions_extension(&self) -> Option<&[ProtocolVersion]> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ClientExtension::SupportedVersions(ref vers) => Some(vers),
            _ => None,
        }
    }

    pub fn get_keyshare_extension(&self) -> Option<&[KeyShareEntry]> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ClientExtension::KeyShare(ref shares) => Some(shares),
            _ => None,
        }
    }

    pub(crate) fn has_keyshare_extension_with_duplicates(&self) -> bool {
        if let Some(entries) = self.get_keyshare_extension() {
            let mut seen = BTreeSet::new();

            for kse in entries {
                let grp = kse.group.get_u16();

                if !seen.insert(grp) {
                    return true;
                }
            }
        }

        false
    }

    pub(crate) fn get_psk(&self) -> Option<&PresharedKeyOffer> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ClientExtension::PresharedKey(ref psk) => Some(psk),
            _ => None,
        }
    }

    pub(crate) fn check_psk_ext_is_last(&self) -> bool {
        self.extensions
            .last()
            .map_or(false, |ext| ext.get_type() == ExtensionType::PreSharedKey)
    }

    pub(crate) fn get_psk_modes(&self) -> Option<&[PSKKeyExchangeMode]> {
        let ext = self.find_extension(ExtensionType::PSKKeyExchangeModes)?;
        match *ext {
            ClientExtension::PresharedKeyModes(ref psk_modes) => Some(psk_modes),
            _ => None,
        }
    }

    pub(crate) fn psk_mode_offered(&self, mode: PSKKeyExchangeMode) -> bool {
        self.get_psk_modes()
            .map(|modes| modes.contains(&mode))
            .unwrap_or(false)
    }

    pub(crate) fn set_psk_binder(&mut self, binder: impl Into<Vec<u8>>) {
        let last_extension = self.extensions.last_mut();
        if let Some(ClientExtension::PresharedKey(ref mut offer)) = last_extension {
            offer.binders[0] = PresharedKeyBinder::from(binder.into());
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn ems_support_offered(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub(crate) fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData)
            .is_some()
    }
}

#[derive(Debug)]
pub(crate) enum HelloRetryExtension {
    KeyShare(NamedGroup),
    Cookie(PayloadU16),
    SupportedVersions(ProtocolVersion),
    Unknown(UnknownExtension),
}

impl HelloRetryExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec for HelloRetryExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::KeyShare(ref r) => r.encode(nested.buf),
            Self::Cookie(ref r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::KeyShare => Self::KeyShare(NamedGroup::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("HelloRetryExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for HelloRetryExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub struct HelloRetryRequest {
    pub(crate) legacy_version: ProtocolVersion,
    pub session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: Vec<HelloRetryExtension>,
}

impl Codec for HelloRetryRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        HELLO_RETRY_REQUEST_RANDOM.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        Compression::Null.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let session_id = SessionId::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let compression = Compression::read(r)?;

        if compression != Compression::Null {
            return Err(InvalidMessage::UnsupportedCompression);
        }

        Ok(Self {
            legacy_version: ProtocolVersion::Unknown(0),
            session_id,
            cipher_suite,
            extensions: Vec::read(r)?,
        })
    }
}

impl HelloRetryRequest {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub(crate) fn has_duplicate_extension(&self) -> bool {
        let mut seen = BTreeSet::new();

        for ext in &self.extensions {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub(crate) fn has_unknown_extension(&self) -> bool {
        self.extensions.iter().any(|ext| {
            ext.get_type() != ExtensionType::KeyShare
                && ext.get_type() != ExtensionType::SupportedVersions
                && ext.get_type() != ExtensionType::Cookie
        })
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&HelloRetryExtension> {
        self.extensions
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub fn get_requested_key_share_group(&self) -> Option<NamedGroup> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            HelloRetryExtension::KeyShare(grp) => Some(grp),
            _ => None,
        }
    }

    pub(crate) fn get_cookie(&self) -> Option<&PayloadU16> {
        let ext = self.find_extension(ExtensionType::Cookie)?;
        match *ext {
            HelloRetryExtension::Cookie(ref ck) => Some(ck),
            _ => None,
        }
    }

    pub(crate) fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            HelloRetryExtension::SupportedVersions(ver) => Some(ver),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ServerHelloPayload {
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: Compression,
    pub(crate) extensions: Vec<ServerExtension>,
}

impl Codec for ServerHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        self.random.encode(bytes);

        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);

        if !self.extensions.is_empty() {
            self.extensions.encode(bytes);
        }
    }

    // minus version and random, which have already been read.
    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let session_id = SessionId::read(r)?;
        let suite = CipherSuite::read(r)?;
        let compression = Compression::read(r)?;

        // RFC5246:
        // "The presence of extensions can be detected by determining whether
        //  there are bytes following the compression_method field at the end of
        //  the ServerHello."
        let extensions = if r.any_left() { Vec::read(r)? } else { vec![] };

        let ret = Self {
            legacy_version: ProtocolVersion::Unknown(0),
            random: ZERO_RANDOM,
            session_id,
            cipher_suite: suite,
            compression_method: compression,
            extensions,
        };

        r.expect_empty("ServerHelloPayload")
            .map(|_| ret)
    }
}

impl HasServerExtensions for ServerHelloPayload {
    fn get_extensions(&self) -> &[ServerExtension] {
        &self.extensions
    }
}

impl ServerHelloPayload {
    pub(crate) fn get_key_share(&self) -> Option<&KeyShareEntry> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ServerExtension::KeyShare(ref share) => Some(share),
            _ => None,
        }
    }

    pub(crate) fn get_psk_index(&self) -> Option<u16> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ServerExtension::PresharedKey(ref index) => Some(*index),
            _ => None,
        }
    }

    pub(crate) fn get_ecpoints_extension(&self) -> Option<&[ECPointFormat]> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ServerExtension::EcPointFormats(ref fmts) => Some(fmts),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn ems_support_acked(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub(crate) fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ServerExtension::SupportedVersions(vers) => Some(vers),
            _ => None,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct CertificateChain(pub Vec<CertificateDer<'static>>);

impl Codec for CertificateChain {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Vec::encode(&self.0, bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Vec::read(r).map(Self)
    }
}

impl Deref for CertificateChain {
    type Target = [CertificateDer<'static>];

    fn deref(&self) -> &[CertificateDer<'static>] {
        &self.0
    }
}

impl TlsListElement for CertificateDer<'_> {
    const SIZE_LEN: ListLength = ListLength::U24 { max: 0x1_0000 };
}

// TLS1.3 changes the Certificate payload encoding.
// That's annoying. It means the parsing is not
// context-free any more.

#[derive(Debug)]
pub(crate) enum CertificateExtension {
    CertificateStatus(CertificateStatus),
    Unknown(UnknownExtension),
}

impl CertificateExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::CertificateStatus(_) => ExtensionType::StatusRequest,
            Self::Unknown(ref r) => r.typ,
        }
    }

    pub(crate) fn get_cert_status(&self) -> Option<&Vec<u8>> {
        match *self {
            Self::CertificateStatus(ref cs) => Some(&cs.ocsp_response.0),
            _ => None,
        }
    }
}

impl Codec for CertificateExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::CertificateStatus(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::StatusRequest => {
                let st = CertificateStatus::read(&mut sub)?;
                Self::CertificateStatus(st)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("CertificateExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for CertificateExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub(crate) struct CertificateEntry {
    pub(crate) cert: CertificateDer<'static>,
    pub(crate) exts: Vec<CertificateExtension>,
}

impl Codec for CertificateEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            cert: CertificateDer::read(r)?,
            exts: Vec::read(r)?,
        })
    }
}

impl CertificateEntry {
    pub(crate) fn new(cert: CertificateDer<'static>) -> Self {
        Self {
            cert,
            exts: Vec::new(),
        }
    }

    pub(crate) fn has_duplicate_extension(&self) -> bool {
        let mut seen = BTreeSet::new();

        for ext in &self.exts {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub(crate) fn has_unknown_extension(&self) -> bool {
        self.exts
            .iter()
            .any(|ext| ext.get_type() != ExtensionType::StatusRequest)
    }

    pub(crate) fn get_ocsp_response(&self) -> Option<&Vec<u8>> {
        self.exts
            .iter()
            .find(|ext| ext.get_type() == ExtensionType::StatusRequest)
            .and_then(CertificateExtension::get_cert_status)
    }
}

impl TlsListElement for CertificateEntry {
    const SIZE_LEN: ListLength = ListLength::U24 { max: 0x1_0000 };
}

#[derive(Debug)]
pub struct CertificatePayloadTls13 {
    pub(crate) context: PayloadU8,
    pub(crate) entries: Vec<CertificateEntry>,
}

impl Codec for CertificatePayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.entries.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            context: PayloadU8::read(r)?,
            entries: Vec::read(r)?,
        })
    }
}

impl CertificatePayloadTls13 {
    pub(crate) fn new(entries: Vec<CertificateEntry>) -> Self {
        Self {
            context: PayloadU8::empty(),
            entries,
        }
    }

    pub(crate) fn any_entry_has_duplicate_extension(&self) -> bool {
        for entry in &self.entries {
            if entry.has_duplicate_extension() {
                return true;
            }
        }

        false
    }

    pub(crate) fn any_entry_has_unknown_extension(&self) -> bool {
        for entry in &self.entries {
            if entry.has_unknown_extension() {
                return true;
            }
        }

        false
    }

    pub(crate) fn any_entry_has_extension(&self) -> bool {
        for entry in &self.entries {
            if !entry.exts.is_empty() {
                return true;
            }
        }

        false
    }

    pub(crate) fn get_end_entity_ocsp(&self) -> Vec<u8> {
        self.entries
            .first()
            .and_then(CertificateEntry::get_ocsp_response)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn convert(self) -> CertificateChain {
        CertificateChain(
            self.entries
                .into_iter()
                .map(|e| e.cert)
                .collect(),
        )
    }
}

/// Describes supported key exchange mechanisms.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    /// Key exchange performed via elliptic curve Diffie-Hellman.
    ECDHE,
}

// We don't support arbitrary curves.  It's a terrible
// idea and unnecessary attack surface.  Please,
// get a grip.
#[derive(Debug)]
pub(crate) struct EcParameters {
    pub(crate) curve_type: ECCurveType,
    pub(crate) named_group: NamedGroup,
}

impl Codec for EcParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let ct = ECCurveType::read(r)?;
        if ct != ECCurveType::NamedCurve {
            return Err(InvalidMessage::UnsupportedCurveType);
        }

        let grp = NamedGroup::read(r)?;

        Ok(Self {
            curve_type: ct,
            named_group: grp,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ClientEcdhParams {
    pub(crate) public: PayloadU8,
}

impl Codec for ClientEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let pb = PayloadU8::read(r)?;
        Ok(Self { public: pb })
    }
}

#[derive(Debug)]
pub(crate) struct ServerEcdhParams {
    pub(crate) curve_params: EcParameters,
    pub(crate) public: PayloadU8,
}

impl ServerEcdhParams {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        Self {
            curve_params: EcParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group: kx.group(),
            },
            public: PayloadU8::new(kx.pub_key().to_vec()),
        }
    }
}

impl Codec for ServerEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_params.encode(bytes);
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let cp = EcParameters::read(r)?;
        let pb = PayloadU8::read(r)?;

        Ok(Self {
            curve_params: cp,
            public: pb,
        })
    }
}

#[derive(Debug)]
pub struct EcdheServerKeyExchange {
    pub(crate) params: ServerEcdhParams,
    pub(crate) dss: DigitallySignedStruct,
}

impl Codec for EcdheServerKeyExchange {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let params = ServerEcdhParams::read(r)?;
        let dss = DigitallySignedStruct::read(r)?;

        Ok(Self { params, dss })
    }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload {
    Ecdhe(EcdheServerKeyExchange),
    Unknown(Payload),
}

impl Codec for ServerKeyExchangePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::Ecdhe(ref x) => x.encode(bytes),
            Self::Unknown(ref x) => x.encode(bytes),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        // read as Unknown, fully parse when we know the
        // KeyExchangeAlgorithm
        Ok(Self::Unknown(Payload::read(r)))
    }
}

impl ServerKeyExchangePayload {
    #[cfg(feature = "tls12")]
    pub(crate) fn unwrap_given_kxa(
        &self,
        kxa: KeyExchangeAlgorithm,
    ) -> Option<EcdheServerKeyExchange> {
        if let Self::Unknown(ref unk) = *self {
            let mut rd = Reader::init(&unk.0);

            let result = match kxa {
                KeyExchangeAlgorithm::ECDHE => EcdheServerKeyExchange::read(&mut rd),
            };

            if !rd.any_left() {
                return result.ok();
            };
        }

        None
    }
}

// -- EncryptedExtensions (TLS1.3 only) --

impl TlsListElement for ServerExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait HasServerExtensions {
    fn get_extensions(&self) -> &[ServerExtension];

    /// Returns true if there is more than one extension of a given
    /// type.
    fn has_duplicate_extension(&self) -> bool {
        let mut seen = BTreeSet::new();

        for ext in self.get_extensions() {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&ServerExtension> {
        self.get_extensions()
            .iter()
            .find(|x| x.get_type() == ext)
    }

    fn get_alpn_protocol(&self) -> Option<&[u8]> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ServerExtension::Protocols(ref protos) => protos.as_single_slice(),
            _ => None,
        }
    }

    fn get_quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ServerExtension::TransportParameters(ref bytes)
            | ServerExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData)
            .is_some()
    }
}

impl HasServerExtensions for Vec<ServerExtension> {
    fn get_extensions(&self) -> &[ServerExtension] {
        self
    }
}

impl TlsListElement for ClientCertificateType {
    const SIZE_LEN: ListLength = ListLength::U8;
}

wrapped_payload!(
    /// A `DistinguishedName` is a `Vec<u8>` wrapped in internal types.
    ///
    /// It contains the DER or BER encoded [`Subject` field from RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6)
    /// for a single certificate. The Subject field is [encoded as an RFC 5280 `Name`](https://datatracker.ietf.org/doc/html/rfc5280#page-116).
    /// It can be decoded using [x509-parser's FromDer trait](https://docs.rs/x509-parser/latest/x509_parser/prelude/trait.FromDer.html).
    ///
    /// ```ignore
    /// for name in distinguished_names {
    ///     use x509_parser::prelude::FromDer;
    ///     println!("{}", x509_parser::x509::X509Name::from_der(&name.0)?.1);
    /// }
    /// ```
    pub struct DistinguishedName,
    PayloadU16,
);

impl DistinguishedName {
    /// Create a [`DistinguishedName`] after prepending its outer SEQUENCE encoding.
    ///
    /// This can be decoded using [x509-parser's FromDer trait](https://docs.rs/x509-parser/latest/x509_parser/prelude/trait.FromDer.html).
    ///
    /// ```ignore
    /// use x509_parser::prelude::FromDer;
    /// println!("{}", x509_parser::x509::X509Name::from_der(dn.as_ref())?.1);
    /// ```
    pub fn in_sequence(bytes: &[u8]) -> Self {
        Self(PayloadU16::new(wrap_in_sequence(bytes)))
    }
}

impl TlsListElement for DistinguishedName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub struct CertificateRequestPayload {
    pub(crate) certtypes: Vec<ClientCertificateType>,
    pub(crate) sigschemes: Vec<SignatureScheme>,
    pub(crate) canames: Vec<DistinguishedName>,
}

impl Codec for CertificateRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.certtypes.encode(bytes);
        self.sigschemes.encode(bytes);
        self.canames.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let certtypes = Vec::read(r)?;
        let sigschemes = Vec::read(r)?;
        let canames = Vec::read(r)?;

        if sigschemes.is_empty() {
            warn!("meaningless CertificateRequest message");
            Err(InvalidMessage::NoSignatureSchemes)
        } else {
            Ok(Self {
                certtypes,
                sigschemes,
                canames,
            })
        }
    }
}

#[derive(Debug)]
pub(crate) enum CertReqExtension {
    SignatureAlgorithms(Vec<SignatureScheme>),
    AuthorityNames(Vec<DistinguishedName>),
    Unknown(UnknownExtension),
}

impl CertReqExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::AuthorityNames(_) => ExtensionType::CertificateAuthorities,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec for CertReqExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::SignatureAlgorithms(ref r) => r.encode(nested.buf),
            Self::AuthorityNames(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::SignatureAlgorithms => {
                let schemes = Vec::read(&mut sub)?;
                if schemes.is_empty() {
                    return Err(InvalidMessage::NoSignatureSchemes);
                }
                Self::SignatureAlgorithms(schemes)
            }
            ExtensionType::CertificateAuthorities => {
                let cas = Vec::read(&mut sub)?;
                Self::AuthorityNames(cas)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("CertReqExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for CertReqExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub struct CertificateRequestPayloadTls13 {
    pub(crate) context: PayloadU8,
    pub(crate) extensions: Vec<CertReqExtension>,
}

impl Codec for CertificateRequestPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let context = PayloadU8::read(r)?;
        let extensions = Vec::read(r)?;

        Ok(Self {
            context,
            extensions,
        })
    }
}

impl CertificateRequestPayloadTls13 {
    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&CertReqExtension> {
        self.extensions
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub(crate) fn get_sigalgs_extension(&self) -> Option<&[SignatureScheme]> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            CertReqExtension::SignatureAlgorithms(ref sa) => Some(sa),
            _ => None,
        }
    }

    pub(crate) fn get_authorities_extension(&self) -> Option<&[DistinguishedName]> {
        let ext = self.find_extension(ExtensionType::CertificateAuthorities)?;
        match *ext {
            CertReqExtension::AuthorityNames(ref an) => Some(an),
            _ => None,
        }
    }
}

// -- NewSessionTicket --
#[derive(Debug)]
pub struct NewSessionTicketPayload {
    pub(crate) lifetime_hint: u32,
    pub(crate) ticket: PayloadU16,
}

impl NewSessionTicketPayload {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(lifetime_hint: u32, ticket: Vec<u8>) -> Self {
        Self {
            lifetime_hint,
            ticket: PayloadU16::new(ticket),
        }
    }
}

impl Codec for NewSessionTicketPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let lifetime = u32::read(r)?;
        let ticket = PayloadU16::read(r)?;

        Ok(Self {
            lifetime_hint: lifetime,
            ticket,
        })
    }
}

// -- NewSessionTicket electric boogaloo --
#[derive(Debug)]
pub(crate) enum NewSessionTicketExtension {
    EarlyData(u32),
    Unknown(UnknownExtension),
}

impl NewSessionTicketExtension {
    pub(crate) fn get_type(&self) -> ExtensionType {
        match *self {
            Self::EarlyData(_) => ExtensionType::EarlyData,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec for NewSessionTicketExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::EarlyData(r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::EarlyData => Self::EarlyData(u32::read(&mut sub)?),
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("NewSessionTicketExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for NewSessionTicketExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub struct NewSessionTicketPayloadTls13 {
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) nonce: PayloadU8,
    pub(crate) ticket: PayloadU16,
    pub(crate) exts: Vec<NewSessionTicketExtension>,
}

impl NewSessionTicketPayloadTls13 {
    pub(crate) fn new(lifetime: u32, age_add: u32, nonce: Vec<u8>, ticket: Vec<u8>) -> Self {
        Self {
            lifetime,
            age_add,
            nonce: PayloadU8::new(nonce),
            ticket: PayloadU16::new(ticket),
            exts: vec![],
        }
    }

    pub(crate) fn has_duplicate_extension(&self) -> bool {
        let mut seen = BTreeSet::new();

        for ext in &self.exts {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&NewSessionTicketExtension> {
        self.exts
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub(crate) fn get_max_early_data_size(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionType::EarlyData)?;
        match *ext {
            NewSessionTicketExtension::EarlyData(ref sz) => Some(*sz),
            _ => None,
        }
    }
}

impl Codec for NewSessionTicketPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let nonce = PayloadU8::read(r)?;
        let ticket = PayloadU16::read(r)?;
        let exts = Vec::read(r)?;

        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            exts,
        })
    }
}

// -- RFC6066 certificate status types

/// Only supports OCSP
#[derive(Debug)]
pub struct CertificateStatus {
    pub(crate) ocsp_response: PayloadU24,
}

impl Codec for CertificateStatus {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.ocsp_response.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => Ok(Self {
                ocsp_response: PayloadU24::read(r)?,
            }),
            _ => Err(InvalidMessage::InvalidCertificateStatusType),
        }
    }
}

impl CertificateStatus {
    pub(crate) fn new(ocsp: Vec<u8>) -> Self {
        Self {
            ocsp_response: PayloadU24::new(ocsp),
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.0
    }
}

#[derive(Debug)]
pub enum HandshakePayload {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    HelloRetryRequest(HelloRetryRequest),
    Certificate(CertificateChain),
    CertificateTls13(CertificatePayloadTls13),
    ServerKeyExchange(ServerKeyExchangePayload),
    CertificateRequest(CertificateRequestPayload),
    CertificateRequestTls13(CertificateRequestPayloadTls13),
    CertificateVerify(DigitallySignedStruct),
    ServerHelloDone,
    EndOfEarlyData,
    ClientKeyExchange(Payload),
    NewSessionTicket(NewSessionTicketPayload),
    NewSessionTicketTls13(NewSessionTicketPayloadTls13),
    EncryptedExtensions(Vec<ServerExtension>),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload),
    CertificateStatus(CertificateStatus),
    MessageHash(Payload),
    Unknown(Payload),
}

impl HandshakePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        use self::HandshakePayload::*;
        match *self {
            HelloRequest | ServerHelloDone | EndOfEarlyData => {}
            ClientHello(ref x) => x.encode(bytes),
            ServerHello(ref x) => x.encode(bytes),
            HelloRetryRequest(ref x) => x.encode(bytes),
            Certificate(ref x) => x.encode(bytes),
            CertificateTls13(ref x) => x.encode(bytes),
            ServerKeyExchange(ref x) => x.encode(bytes),
            ClientKeyExchange(ref x) => x.encode(bytes),
            CertificateRequest(ref x) => x.encode(bytes),
            CertificateRequestTls13(ref x) => x.encode(bytes),
            CertificateVerify(ref x) => x.encode(bytes),
            NewSessionTicket(ref x) => x.encode(bytes),
            NewSessionTicketTls13(ref x) => x.encode(bytes),
            EncryptedExtensions(ref x) => x.encode(bytes),
            KeyUpdate(ref x) => x.encode(bytes),
            Finished(ref x) => x.encode(bytes),
            CertificateStatus(ref x) => x.encode(bytes),
            MessageHash(ref x) => x.encode(bytes),
            Unknown(ref x) => x.encode(bytes),
        }
    }
}

#[derive(Debug)]
pub struct HandshakeMessagePayload {
    pub typ: HandshakeType,
    pub payload: HandshakePayload,
}

impl Codec for HandshakeMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // output type, length, and encoded payload
        match self.typ {
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U24 { max: usize::MAX }, bytes);
        self.payload.encode(nested.buf);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Self::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

impl HandshakeMessagePayload {
    pub(crate) fn read_version(
        r: &mut Reader,
        vers: ProtocolVersion,
    ) -> Result<Self, InvalidMessage> {
        let mut typ = HandshakeType::read(r)?;
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;

        let payload = match typ {
            HandshakeType::HelloRequest if sub.left() == 0 => HandshakePayload::HelloRequest,
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                let version = ProtocolVersion::read(&mut sub)?;
                let random = Random::read(&mut sub)?;

                if random == HELLO_RETRY_REQUEST_RANDOM {
                    let mut hrr = HelloRetryRequest::read(&mut sub)?;
                    hrr.legacy_version = version;
                    typ = HandshakeType::HelloRetryRequest;
                    HandshakePayload::HelloRetryRequest(hrr)
                } else {
                    let mut shp = ServerHelloPayload::read(&mut sub)?;
                    shp.legacy_version = version;
                    shp.random = random;
                    HandshakePayload::ServerHello(shp)
                }
            }
            HandshakeType::Certificate if vers == ProtocolVersion::TLSv1_3 => {
                let p = CertificatePayloadTls13::read(&mut sub)?;
                HandshakePayload::CertificateTls13(p)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(CertificateChain::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                let p = ServerKeyExchangePayload::read(&mut sub)?;
                HandshakePayload::ServerKeyExchange(p)
            }
            HandshakeType::ServerHelloDone => {
                sub.expect_empty("ServerHelloDone")?;
                HandshakePayload::ServerHelloDone
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(Payload::read(&mut sub))
            }
            HandshakeType::CertificateRequest if vers == ProtocolVersion::TLSv1_3 => {
                let p = CertificateRequestPayloadTls13::read(&mut sub)?;
                HandshakePayload::CertificateRequestTls13(p)
            }
            HandshakeType::CertificateRequest => {
                let p = CertificateRequestPayload::read(&mut sub)?;
                HandshakePayload::CertificateRequest(p)
            }
            HandshakeType::CertificateVerify => {
                HandshakePayload::CertificateVerify(DigitallySignedStruct::read(&mut sub)?)
            }
            HandshakeType::NewSessionTicket if vers == ProtocolVersion::TLSv1_3 => {
                let p = NewSessionTicketPayloadTls13::read(&mut sub)?;
                HandshakePayload::NewSessionTicketTls13(p)
            }
            HandshakeType::NewSessionTicket => {
                let p = NewSessionTicketPayload::read(&mut sub)?;
                HandshakePayload::NewSessionTicket(p)
            }
            HandshakeType::EncryptedExtensions => {
                HandshakePayload::EncryptedExtensions(Vec::read(&mut sub)?)
            }
            HandshakeType::KeyUpdate => {
                HandshakePayload::KeyUpdate(KeyUpdateRequest::read(&mut sub)?)
            }
            HandshakeType::EndOfEarlyData => {
                sub.expect_empty("EndOfEarlyData")?;
                HandshakePayload::EndOfEarlyData
            }
            HandshakeType::Finished => HandshakePayload::Finished(Payload::read(&mut sub)),
            HandshakeType::CertificateStatus => {
                HandshakePayload::CertificateStatus(CertificateStatus::read(&mut sub)?)
            }
            HandshakeType::MessageHash => {
                // does not appear on the wire
                return Err(InvalidMessage::UnexpectedMessage("MessageHash"));
            }
            HandshakeType::HelloRetryRequest => {
                // not legal on wire
                return Err(InvalidMessage::UnexpectedMessage("HelloRetryRequest"));
            }
            _ => HandshakePayload::Unknown(Payload::read(&mut sub)),
        };

        sub.expect_empty("HandshakeMessagePayload")
            .map(|_| Self { typ, payload })
    }

    pub(crate) fn build_key_update_notify() -> Self {
        Self {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        }
    }

    pub(crate) fn get_encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut ret = self.get_encoding();

        let binder_len = match self.payload {
            HandshakePayload::ClientHello(ref ch) => match ch.extensions.last() {
                Some(ClientExtension::PresharedKey(ref offer)) => {
                    let mut binders_encoding = Vec::new();
                    offer
                        .binders
                        .encode(&mut binders_encoding);
                    binders_encoding.len()
                }
                _ => 0,
            },
            _ => 0,
        };

        let ret_len = ret.len() - binder_len;
        ret.truncate(ret_len);
        ret
    }

    pub(crate) fn build_handshake_hash(hash: &[u8]) -> Self {
        Self {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.to_vec())),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: HpkeKdf,
    pub aead_id: HpkeAead,
}

impl Codec for HpkeSymmetricCipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            kdf_id: HpkeKdf::read(r)?,
            aead_id: HpkeAead::read(r)?,
        })
    }
}

impl TlsListElement for HpkeSymmetricCipherSuite {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct HpkeKeyConfig {
    pub config_id: u8,
    pub kem_id: HpkeKem,
    pub public_key: PayloadU16,
    pub symmetric_cipher_suites: Vec<HpkeSymmetricCipherSuite>,
}

impl Codec for HpkeKeyConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        self.kem_id.encode(bytes);
        self.public_key.encode(bytes);
        self.symmetric_cipher_suites
            .encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            config_id: u8::read(r)?,
            kem_id: HpkeKem::read(r)?,
            public_key: PayloadU16::read(r)?,
            symmetric_cipher_suites: Vec::<HpkeSymmetricCipherSuite>::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct EchConfigContents {
    pub key_config: HpkeKeyConfig,
    pub maximum_name_length: u8,
    pub public_name: DnsName<'static>,
    pub extensions: PayloadU16,
}

impl Codec for EchConfigContents {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.key_config.encode(bytes);
        self.maximum_name_length.encode(bytes);
        let dns_name = &self.public_name.borrow();
        PayloadU8::encode_slice(dns_name.as_ref().as_ref(), bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(Self {
            key_config: HpkeKeyConfig::read(r)?,
            maximum_name_length: u8::read(r)?,
            public_name: {
                DnsName::try_from(PayloadU8::read(r)?.0.as_slice())
                    .map_err(|_| InvalidMessage::InvalidServerName)?
                    .to_owned()
            },
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct EchConfig {
    pub version: EchVersion,
    pub contents: EchConfigContents,
}

impl Codec for EchConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        let mut contents = Vec::with_capacity(128);
        self.contents.encode(&mut contents);
        let length: &mut [u8; 2] = &mut [0, 0];
        codec::put_u16(contents.len() as u16, length);
        bytes.extend_from_slice(length);
        bytes.extend(contents);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let version = EchVersion::read(r)?;
        let length = u16::read(r)?;
        Ok(Self {
            version,
            contents: EchConfigContents::read(&mut r.sub(length as usize)?)?,
        })
    }
}

impl TlsListElement for EchConfig {
    const SIZE_LEN: ListLength = ListLength::U16;
}
