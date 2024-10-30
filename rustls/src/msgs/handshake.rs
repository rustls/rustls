use alloc::collections::BTreeSet;
#[cfg(feature = "logging")]
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Deref;
use core::{fmt, iter};

use pki_types::{CertificateDer, DnsName};

#[cfg(feature = "tls12")]
use crate::crypto::ActiveKeyExchange;
use crate::crypto::SecureRandom;
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, EchClientHelloType, HandshakeType,
    ProtocolVersion, SignatureScheme,
};
use crate::error::InvalidMessage;
#[cfg(feature = "tls12")]
use crate::ffdhe_groups::FfdheGroup;
use crate::log::warn;
use crate::msgs::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use crate::msgs::codec::{self, Codec, LengthPrefixedBuffer, ListLength, Reader, TlsListElement};
use crate::msgs::enums::{
    CertificateStatusType, CertificateType, ClientCertificateType, Compression, ECCurveType,
    ECPointFormat, EchVersion, ExtensionType, HpkeAead, HpkeKdf, HpkeKem, KeyUpdateRequest,
    NamedGroup, PSKKeyExchangeMode, ServerNameType,
};
use crate::rand;
use crate::verify::DigitallySignedStruct;
use crate::x509::wrap_in_sequence;

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

    impl Codec<'_> for $name {
        fn encode(&self, bytes: &mut Vec<u8>) {
            self.0.encode(bytes);
        }

        fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl Codec<'_> for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl Codec<'_> for SessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(self.as_ref());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload<'static>,
}

impl UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut Reader<'_>) -> Self {
        let payload = Payload::read(r).into_owned();
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
    IpAddress(PayloadU16),
    Unknown(Payload<'static>),
}

impl ServerNamePayload {
    pub(crate) fn new_hostname(hostname: DnsName<'static>) -> Self {
        Self::HostName(hostname)
    }

    fn read_hostname(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        use pki_types::ServerName;
        let raw = PayloadU16::read(r)?;

        match ServerName::try_from(raw.0.as_slice()) {
            Ok(ServerName::DnsName(d)) => Ok(Self::HostName(d.to_owned())),
            Ok(ServerName::IpAddress(_)) => Ok(Self::IpAddress(raw)),
            Ok(_) | Err(_) => {
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
            Self::IpAddress(ref r) => r.encode(bytes),
            Self::Unknown(ref r) => r.encode(bytes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerName {
    pub(crate) typ: ServerNameType,
    pub(crate) payload: ServerNamePayload,
}

impl Codec<'_> for ServerName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r).into_owned()),
        };

        Ok(Self { typ, payload })
    }
}

impl TlsListElement for ServerName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait ConvertServerNameList {
    fn has_duplicate_names_for_type(&self) -> bool;
    fn single_hostname(&self) -> Option<DnsName<'_>>;
}

impl ConvertServerNameList for [ServerName] {
    /// RFC6066: "The ServerNameList MUST NOT contain more than one name of the same name_type."
    fn has_duplicate_names_for_type(&self) -> bool {
        has_duplicates::<_, _, u8>(self.iter().map(|name| name.typ))
    }

    fn single_hostname(&self) -> Option<DnsName<'_>> {
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
    pub fn new(group: NamedGroup, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            group,
            payload: PayloadU16::new(payload.into()),
        }
    }

    pub fn group(&self) -> NamedGroup {
        self.group
    }
}

impl Codec<'_> for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl Codec<'_> for PresharedKeyIdentity {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl Codec<'_> for PresharedKeyOffer {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identities.encode(bytes);
        self.binders.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl Codec<'_> for OcspCertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.responder_ids.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            responder_ids: Vec::read(r)?,
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CertificateStatusRequest {
    Ocsp(OcspCertificateStatusRequest),
    Unknown((CertificateStatusType, Payload<'static>)),
}

impl Codec<'_> for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ocsp(ref r) => r.encode(bytes),
            Self::Unknown((typ, payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => {
                let ocsp_req = OcspCertificateStatusRequest::read(r)?;
                Ok(Self::Ocsp(ocsp_req))
            }
            _ => {
                let data = Payload::read(r).into_owned();
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

impl TlsListElement for CertificateType {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for CertificateCompressionAlgorithm {
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
    ServerCertTypes(Vec<CertificateType>),
    ClientCertTypes(Vec<CertificateType>),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    CertificateCompressionAlgorithms(Vec<CertificateCompressionAlgorithm>),
    EncryptedClientHello(EncryptedClientHello),
    EncryptedClientHelloOuterExtensions(Vec<ExtensionType>),
    Unknown(UnknownExtension),
}

impl ClientExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
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
            Self::ClientCertTypes(_) => ExtensionType::ClientCertificateType,
            Self::ServerCertTypes(_) => ExtensionType::ServerCertificateType,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::CertificateCompressionAlgorithms(_) => ExtensionType::CompressCertificate,
            Self::EncryptedClientHello(_) => ExtensionType::EncryptedClientHello,
            Self::EncryptedClientHelloOuterExtensions(_) => {
                ExtensionType::EncryptedClientHelloOuterExtensions
            }
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

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
            Self::ClientCertTypes(ref r) => r.encode(nested.buf),
            Self::ServerCertTypes(ref r) => r.encode(nested.buf),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::CertificateCompressionAlgorithms(ref r) => r.encode(nested.buf),
            Self::EncryptedClientHello(ref r) => r.encode(nested.buf),
            Self::EncryptedClientHelloOuterExtensions(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
                    let contents = Payload::read(&mut sub).into_owned();
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
            ExtensionType::ClientCertificateType => Self::ClientCertTypes(Vec::read(&mut sub)?),
            ExtensionType::ServerCertificateType => Self::ServerCertTypes(Vec::read(&mut sub)?),
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                Self::CertificateStatusRequest(csr)
            }
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData if !sub.any_left() => Self::EarlyData,
            ExtensionType::CompressCertificate => {
                Self::CertificateCompressionAlgorithms(Vec::read(&mut sub)?)
            }
            ExtensionType::EncryptedClientHelloOuterExtensions => {
                Self::EncryptedClientHelloOuterExtensions(Vec::read(&mut sub)?)
            }
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
    Offer(Payload<'static>),
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
    ServerCertType(CertificateType),
    ClientCertType(CertificateType),
    SupportedVersions(ProtocolVersion),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    EncryptedClientHello(ServerEncryptedClientHello),
    Unknown(UnknownExtension),
}

impl ServerExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::EcPointFormats(_) => ExtensionType::ECPointFormats,
            Self::ServerNameAck => ExtensionType::ServerName,
            Self::SessionTicketAck => ExtensionType::SessionTicket,
            Self::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::ClientCertType(_) => ExtensionType::ClientCertificateType,
            Self::ServerCertType(_) => ExtensionType::ServerCertificateType,
            Self::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusAck => ExtensionType::StatusRequest,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::EncryptedClientHello(_) => ExtensionType::EncryptedClientHello,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for ServerExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

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
            Self::ClientCertType(r) => r.encode(nested.buf),
            Self::ServerCertType(r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::EncryptedClientHello(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
            ExtensionType::ClientCertificateType => {
                Self::ClientCertType(CertificateType::read(&mut sub)?)
            }
            ExtensionType::ServerCertificateType => {
                Self::ServerCertType(CertificateType::read(&mut sub)?)
            }
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
            ExtensionType::EncryptedClientHello => {
                Self::EncryptedClientHello(ServerEncryptedClientHello::read(&mut sub)?)
            }
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

#[derive(Clone, Debug)]
pub struct ClientHelloPayload {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<Compression>,
    pub extensions: Vec<ClientExtension>,
}

impl Codec<'_> for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

impl TlsListElement for ExtensionType {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl ClientHelloPayload {
    pub(crate) fn ech_inner_encoding(&self, to_compress: Vec<ExtensionType>) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.payload_encode(&mut bytes, Encoding::EchInnerHello { to_compress });
        bytes
    }

    pub(crate) fn payload_encode(&self, bytes: &mut Vec<u8>, purpose: Encoding) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);

        match purpose {
            // SessionID is required to be empty in the encoded inner client hello.
            Encoding::EchInnerHello { .. } => SessionId::empty().encode(bytes),
            _ => self.session_id.encode(bytes),
        }

        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);

        let to_compress = match purpose {
            // Compressed extensions must be replaced in the encoded inner client hello.
            Encoding::EchInnerHello { to_compress } if !to_compress.is_empty() => to_compress,
            _ => {
                if !self.extensions.is_empty() {
                    self.extensions.encode(bytes);
                }
                return;
            }
        };

        // Safety: not empty check in match guard.
        let first_compressed_type = *to_compress.first().unwrap();

        // Compressed extensions are in a contiguous range and must be replaced
        // with a marker extension.
        let compressed_start_idx = self
            .extensions
            .iter()
            .position(|ext| ext.ext_type() == first_compressed_type);
        let compressed_end_idx = compressed_start_idx.map(|start| start + to_compress.len());
        let marker_ext = ClientExtension::EncryptedClientHelloOuterExtensions(to_compress);

        let exts = self
            .extensions
            .iter()
            .enumerate()
            .filter_map(|(i, ext)| {
                if Some(i) == compressed_start_idx {
                    Some(&marker_ext)
                } else if Some(i) > compressed_start_idx && Some(i) < compressed_end_idx {
                    None
                } else {
                    Some(ext)
                }
            });

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        for ext in exts {
            ext.encode(nested.buf);
        }
    }

    /// Returns true if there is more than one extension of a given
    /// type.
    pub(crate) fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.extensions
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
        self.extensions
            .iter()
            .find(|x| x.ext_type() == ext)
    }

    pub(crate) fn sni_extension(&self) -> Option<&[ServerName]> {
        let ext = self.find_extension(ExtensionType::ServerName)?;
        match *ext {
            // Does this comply with RFC6066?
            //
            // [RFC6066][] specifies that literal IP addresses are illegal in
            // `ServerName`s with a `name_type` of `host_name`.
            //
            // Some clients incorrectly send such extensions: we choose to
            // successfully parse these (into `ServerNamePayload::IpAddress`)
            // but then act like the client sent no `server_name` extension.
            //
            // [RFC6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
            ClientExtension::ServerName(ref req)
                if !req
                    .iter()
                    .any(|name| matches!(name.payload, ServerNamePayload::IpAddress(_))) =>
            {
                Some(req)
            }
            _ => None,
        }
    }

    pub fn sigalgs_extension(&self) -> Option<&[SignatureScheme]> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            ClientExtension::SignatureAlgorithms(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn namedgroups_extension(&self) -> Option<&[NamedGroup]> {
        let ext = self.find_extension(ExtensionType::EllipticCurves)?;
        match *ext {
            ClientExtension::NamedGroups(ref req) => Some(req),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn ecpoints_extension(&self) -> Option<&[ECPointFormat]> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ClientExtension::EcPointFormats(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn server_certificate_extension(&self) -> Option<&[CertificateType]> {
        let ext = self.find_extension(ExtensionType::ServerCertificateType)?;
        match ext {
            ClientExtension::ServerCertTypes(req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn client_certificate_extension(&self) -> Option<&[CertificateType]> {
        let ext = self.find_extension(ExtensionType::ClientCertificateType)?;
        match ext {
            ClientExtension::ClientCertTypes(req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn alpn_extension(&self) -> Option<&Vec<ProtocolName>> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ClientExtension::Protocols(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn quic_params_extension(&self) -> Option<Vec<u8>> {
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
    pub(crate) fn ticket_extension(&self) -> Option<&ClientExtension> {
        self.find_extension(ExtensionType::SessionTicket)
    }

    pub(crate) fn versions_extension(&self) -> Option<&[ProtocolVersion]> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ClientExtension::SupportedVersions(ref vers) => Some(vers),
            _ => None,
        }
    }

    pub fn keyshare_extension(&self) -> Option<&[KeyShareEntry]> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ClientExtension::KeyShare(ref shares) => Some(shares),
            _ => None,
        }
    }

    pub(crate) fn has_keyshare_extension_with_duplicates(&self) -> bool {
        self.keyshare_extension()
            .map(|entries| {
                has_duplicates::<_, _, u16>(
                    entries
                        .iter()
                        .map(|kse| u16::from(kse.group)),
                )
            })
            .unwrap_or_default()
    }

    pub(crate) fn psk(&self) -> Option<&PresharedKeyOffer> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ClientExtension::PresharedKey(ref psk) => Some(psk),
            _ => None,
        }
    }

    pub(crate) fn check_psk_ext_is_last(&self) -> bool {
        self.extensions
            .last()
            .map_or(false, |ext| ext.ext_type() == ExtensionType::PreSharedKey)
    }

    pub(crate) fn psk_modes(&self) -> Option<&[PSKKeyExchangeMode]> {
        let ext = self.find_extension(ExtensionType::PSKKeyExchangeModes)?;
        match *ext {
            ClientExtension::PresharedKeyModes(ref psk_modes) => Some(psk_modes),
            _ => None,
        }
    }

    pub(crate) fn psk_mode_offered(&self, mode: PSKKeyExchangeMode) -> bool {
        self.psk_modes()
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

    pub(crate) fn certificate_compression_extension(
        &self,
    ) -> Option<&[CertificateCompressionAlgorithm]> {
        let ext = self.find_extension(ExtensionType::CompressCertificate)?;
        match *ext {
            ClientExtension::CertificateCompressionAlgorithms(ref algs) => Some(algs),
            _ => None,
        }
    }

    pub(crate) fn has_certificate_compression_extension_with_duplicates(&self) -> bool {
        if let Some(algs) = self.certificate_compression_extension() {
            has_duplicates::<_, _, u16>(algs.iter().cloned())
        } else {
            false
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum HelloRetryExtension {
    KeyShare(NamedGroup),
    Cookie(PayloadU16),
    SupportedVersions(ProtocolVersion),
    EchHelloRetryRequest(Vec<u8>),
    Unknown(UnknownExtension),
}

impl HelloRetryExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::EchHelloRetryRequest(_) => ExtensionType::EncryptedClientHello,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for HelloRetryExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::KeyShare(ref r) => r.encode(nested.buf),
            Self::Cookie(ref r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::EchHelloRetryRequest(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::KeyShare => Self::KeyShare(NamedGroup::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            ExtensionType::EncryptedClientHello => Self::EchHelloRetryRequest(sub.rest().to_vec()),
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("HelloRetryExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for HelloRetryExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct HelloRetryRequest {
    pub(crate) legacy_version: ProtocolVersion,
    pub session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: Vec<HelloRetryExtension>,
}

impl Codec<'_> for HelloRetryRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
        has_duplicates::<_, _, u16>(
            self.extensions
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    pub(crate) fn has_unknown_extension(&self) -> bool {
        self.extensions.iter().any(|ext| {
            ext.ext_type() != ExtensionType::KeyShare
                && ext.ext_type() != ExtensionType::SupportedVersions
                && ext.ext_type() != ExtensionType::Cookie
                && ext.ext_type() != ExtensionType::EncryptedClientHello
        })
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&HelloRetryExtension> {
        self.extensions
            .iter()
            .find(|x| x.ext_type() == ext)
    }

    pub fn requested_key_share_group(&self) -> Option<NamedGroup> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            HelloRetryExtension::KeyShare(grp) => Some(grp),
            _ => None,
        }
    }

    pub(crate) fn cookie(&self) -> Option<&PayloadU16> {
        let ext = self.find_extension(ExtensionType::Cookie)?;
        match *ext {
            HelloRetryExtension::Cookie(ref ck) => Some(ck),
            _ => None,
        }
    }

    pub(crate) fn supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            HelloRetryExtension::SupportedVersions(ver) => Some(ver),
            _ => None,
        }
    }

    pub(crate) fn ech(&self) -> Option<&Vec<u8>> {
        let ext = self.find_extension(ExtensionType::EncryptedClientHello)?;
        match *ext {
            HelloRetryExtension::EchHelloRetryRequest(ref ech) => Some(ech),
            _ => None,
        }
    }

    fn payload_encode(&self, bytes: &mut Vec<u8>, purpose: Encoding) {
        self.legacy_version.encode(bytes);
        HELLO_RETRY_REQUEST_RANDOM.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        Compression::Null.encode(bytes);

        match purpose {
            // For the purpose of ECH confirmation, the Encrypted Client Hello extension
            // must have its payload replaced by 8 zero bytes.
            //
            // See draft-ietf-tls-esni-18 7.2.1:
            // <https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#name-sending-helloretryrequest-2>
            Encoding::EchConfirmation => {
                let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);
                for ext in &self.extensions {
                    match ext.ext_type() {
                        ExtensionType::EncryptedClientHello => {
                            HelloRetryExtension::EchHelloRetryRequest(vec![0u8; 8])
                                .encode(extensions.buf);
                        }
                        _ => {
                            ext.encode(extensions.buf);
                        }
                    }
                }
            }
            _ => {
                self.extensions.encode(bytes);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerHelloPayload {
    pub extensions: Vec<ServerExtension>,
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: Compression,
}

impl Codec<'_> for ServerHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard)
    }

    // minus version and random, which have already been read.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
    fn extensions(&self) -> &[ServerExtension] {
        &self.extensions
    }
}

impl ServerHelloPayload {
    pub(crate) fn key_share(&self) -> Option<&KeyShareEntry> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ServerExtension::KeyShare(ref share) => Some(share),
            _ => None,
        }
    }

    pub(crate) fn psk_index(&self) -> Option<u16> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ServerExtension::PresharedKey(ref index) => Some(*index),
            _ => None,
        }
    }

    pub(crate) fn ecpoints_extension(&self) -> Option<&[ECPointFormat]> {
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

    pub(crate) fn supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ServerExtension::SupportedVersions(vers) => Some(vers),
            _ => None,
        }
    }

    fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
        self.legacy_version.encode(bytes);

        match encoding {
            // When encoding a ServerHello for ECH confirmation, the random value
            // has the last 8 bytes zeroed out.
            Encoding::EchConfirmation => {
                // Indexing safety: self.random is 32 bytes long by definition.
                let rand_vec = self.random.get_encoding();
                bytes.extend_from_slice(&rand_vec.as_slice()[..24]);
                bytes.extend_from_slice(&[0u8; 8]);
            }
            _ => self.random.encode(bytes),
        }

        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);

        if !self.extensions.is_empty() {
            self.extensions.encode(bytes);
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct CertificateChain<'a>(pub Vec<CertificateDer<'a>>);

impl CertificateChain<'_> {
    pub(crate) fn into_owned(self) -> CertificateChain<'static> {
        CertificateChain(
            self.0
                .into_iter()
                .map(|c| c.into_owned())
                .collect(),
        )
    }
}

impl<'a> Codec<'a> for CertificateChain<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Vec::encode(&self.0, bytes)
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Vec::read(r).map(Self)
    }
}

impl<'a> Deref for CertificateChain<'a> {
    type Target = [CertificateDer<'a>];

    fn deref(&self) -> &[CertificateDer<'a>] {
        &self.0
    }
}

impl TlsListElement for CertificateDer<'_> {
    const SIZE_LEN: ListLength = ListLength::U24 {
        max: CERTIFICATE_MAX_SIZE_LIMIT,
        error: InvalidMessage::CertificatePayloadTooLarge,
    };
}

/// TLS has a 16MB size limit on any handshake message,
/// plus a 16MB limit on any given certificate.
///
/// We contract that to 64KB to limit the amount of memory allocation
/// that is directly controllable by the peer.
pub(crate) const CERTIFICATE_MAX_SIZE_LIMIT: usize = 0x1_0000;

#[derive(Debug)]
pub(crate) enum CertificateExtension<'a> {
    CertificateStatus(CertificateStatus<'a>),
    Unknown(UnknownExtension),
}

impl CertificateExtension<'_> {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::CertificateStatus(_) => ExtensionType::StatusRequest,
            Self::Unknown(ref r) => r.typ,
        }
    }

    pub(crate) fn cert_status(&self) -> Option<&[u8]> {
        match *self {
            Self::CertificateStatus(ref cs) => Some(cs.ocsp_response.0.bytes()),
            _ => None,
        }
    }

    pub(crate) fn into_owned(self) -> CertificateExtension<'static> {
        match self {
            Self::CertificateStatus(st) => CertificateExtension::CertificateStatus(st.into_owned()),
            Self::Unknown(unk) => CertificateExtension::Unknown(unk),
        }
    }
}

impl<'a> Codec<'a> for CertificateExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::CertificateStatus(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
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

impl TlsListElement for CertificateExtension<'_> {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug)]
pub(crate) struct CertificateEntry<'a> {
    pub(crate) cert: CertificateDer<'a>,
    pub(crate) exts: Vec<CertificateExtension<'a>>,
}

impl<'a> Codec<'a> for CertificateEntry<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            cert: CertificateDer::read(r)?,
            exts: Vec::read(r)?,
        })
    }
}

impl<'a> CertificateEntry<'a> {
    pub(crate) fn new(cert: CertificateDer<'a>) -> Self {
        Self {
            cert,
            exts: Vec::new(),
        }
    }

    pub(crate) fn into_owned(self) -> CertificateEntry<'static> {
        CertificateEntry {
            cert: self.cert.into_owned(),
            exts: self
                .exts
                .into_iter()
                .map(CertificateExtension::into_owned)
                .collect(),
        }
    }

    pub(crate) fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.exts
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    pub(crate) fn has_unknown_extension(&self) -> bool {
        self.exts
            .iter()
            .any(|ext| ext.ext_type() != ExtensionType::StatusRequest)
    }

    pub(crate) fn ocsp_response(&self) -> Option<&[u8]> {
        self.exts
            .iter()
            .find(|ext| ext.ext_type() == ExtensionType::StatusRequest)
            .and_then(CertificateExtension::cert_status)
    }
}

impl TlsListElement for CertificateEntry<'_> {
    const SIZE_LEN: ListLength = ListLength::U24 {
        max: CERTIFICATE_MAX_SIZE_LIMIT,
        error: InvalidMessage::CertificatePayloadTooLarge,
    };
}

#[derive(Debug)]
pub struct CertificatePayloadTls13<'a> {
    pub(crate) context: PayloadU8,
    pub(crate) entries: Vec<CertificateEntry<'a>>,
}

impl<'a> Codec<'a> for CertificatePayloadTls13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.entries.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            context: PayloadU8::read(r)?,
            entries: Vec::read(r)?,
        })
    }
}

impl<'a> CertificatePayloadTls13<'a> {
    pub(crate) fn new(
        certs: impl Iterator<Item = &'a CertificateDer<'a>>,
        ocsp_response: Option<&'a [u8]>,
    ) -> Self {
        Self {
            context: PayloadU8::empty(),
            entries: certs
                // zip certificate iterator with `ocsp_response` followed by
                // an infinite-length iterator of `None`.
                .zip(
                    ocsp_response
                        .into_iter()
                        .map(Some)
                        .chain(iter::repeat(None)),
                )
                .map(|(cert, ocsp)| {
                    let mut e = CertificateEntry::new(cert.clone());
                    if let Some(ocsp) = ocsp {
                        e.exts
                            .push(CertificateExtension::CertificateStatus(
                                CertificateStatus::new(ocsp),
                            ));
                    }
                    e
                })
                .collect(),
        }
    }

    pub(crate) fn into_owned(self) -> CertificatePayloadTls13<'static> {
        CertificatePayloadTls13 {
            context: self.context,
            entries: self
                .entries
                .into_iter()
                .map(CertificateEntry::into_owned)
                .collect(),
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

    pub(crate) fn end_entity_ocsp(&self) -> Vec<u8> {
        self.entries
            .first()
            .and_then(CertificateEntry::ocsp_response)
            .map(|resp| resp.to_vec())
            .unwrap_or_default()
    }

    pub(crate) fn into_certificate_chain(self) -> CertificateChain<'a> {
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
    /// Diffie-Hellman Key exchange (with only known parameters as defined in [RFC 7919]).
    ///
    /// [RFC 7919]: https://datatracker.ietf.org/doc/html/rfc7919
    DHE,
    /// Key exchange performed via elliptic curve Diffie-Hellman.
    ECDHE,
}

pub(crate) static ALL_KEY_EXCHANGE_ALGORITHMS: &[KeyExchangeAlgorithm] =
    &[KeyExchangeAlgorithm::ECDHE, KeyExchangeAlgorithm::DHE];

// We don't support arbitrary curves.  It's a terrible
// idea and unnecessary attack surface.  Please,
// get a grip.
#[derive(Debug)]
pub(crate) struct EcParameters {
    pub(crate) curve_type: ECCurveType,
    pub(crate) named_group: NamedGroup,
}

impl Codec<'_> for EcParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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

#[cfg(feature = "tls12")]
pub(crate) trait KxDecode<'a>: fmt::Debug + Sized {
    /// Decode a key exchange message given the key_exchange `algo`
    fn decode(r: &mut Reader<'a>, algo: KeyExchangeAlgorithm) -> Result<Self, InvalidMessage>;
}

#[cfg(feature = "tls12")]
#[derive(Debug)]
pub(crate) enum ClientKeyExchangeParams {
    Ecdh(ClientEcdhParams),
    Dh(ClientDhParams),
}

#[cfg(feature = "tls12")]
impl ClientKeyExchangeParams {
    pub(crate) fn pub_key(&self) -> &[u8] {
        match self {
            Self::Ecdh(ecdh) => &ecdh.public.0,
            Self::Dh(dh) => &dh.public.0,
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ecdh(ecdh) => ecdh.encode(buf),
            Self::Dh(dh) => dh.encode(buf),
        }
    }
}

#[cfg(feature = "tls12")]
impl KxDecode<'_> for ClientKeyExchangeParams {
    fn decode(r: &mut Reader<'_>, algo: KeyExchangeAlgorithm) -> Result<Self, InvalidMessage> {
        use KeyExchangeAlgorithm::*;
        Ok(match algo {
            ECDHE => Self::Ecdh(ClientEcdhParams::read(r)?),
            DHE => Self::Dh(ClientDhParams::read(r)?),
        })
    }
}

#[cfg(feature = "tls12")]
#[derive(Debug)]
pub(crate) struct ClientEcdhParams {
    pub(crate) public: PayloadU8,
}

#[cfg(feature = "tls12")]
impl Codec<'_> for ClientEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let pb = PayloadU8::read(r)?;
        Ok(Self { public: pb })
    }
}

#[cfg(feature = "tls12")]
#[derive(Debug)]
pub(crate) struct ClientDhParams {
    pub(crate) public: PayloadU16,
}

#[cfg(feature = "tls12")]
impl Codec<'_> for ClientDhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            public: PayloadU16::read(r)?,
        })
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

impl Codec<'_> for ServerEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_params.encode(bytes);
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let cp = EcParameters::read(r)?;
        let pb = PayloadU8::read(r)?;

        Ok(Self {
            curve_params: cp,
            public: pb,
        })
    }
}

#[derive(Debug)]
#[allow(non_snake_case)]
pub(crate) struct ServerDhParams {
    pub(crate) dh_p: PayloadU16,
    pub(crate) dh_g: PayloadU16,
    pub(crate) dh_Ys: PayloadU16,
}

impl ServerDhParams {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        let params = match kx.ffdhe_group() {
            Some(params) => params,
            None => panic!("invalid NamedGroup for DHE key exchange: {:?}", kx.group()),
        };

        Self {
            dh_p: PayloadU16::new(params.p.to_vec()),
            dh_g: PayloadU16::new(params.g.to_vec()),
            dh_Ys: PayloadU16::new(kx.pub_key().to_vec()),
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn as_ffdhe_group(&self) -> FfdheGroup<'_> {
        FfdheGroup::from_params_trimming_leading_zeros(&self.dh_p.0, &self.dh_g.0)
    }
}

impl Codec<'_> for ServerDhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.dh_p.encode(bytes);
        self.dh_g.encode(bytes);
        self.dh_Ys.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            dh_p: PayloadU16::read(r)?,
            dh_g: PayloadU16::read(r)?,
            dh_Ys: PayloadU16::read(r)?,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ServerKeyExchangeParams {
    Ecdh(ServerEcdhParams),
    Dh(ServerDhParams),
}

impl ServerKeyExchangeParams {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        match kx.group().key_exchange_algorithm() {
            KeyExchangeAlgorithm::DHE => Self::Dh(ServerDhParams::new(kx)),
            KeyExchangeAlgorithm::ECDHE => Self::Ecdh(ServerEcdhParams::new(kx)),
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn pub_key(&self) -> &[u8] {
        match self {
            Self::Ecdh(ecdh) => &ecdh.public.0,
            Self::Dh(dh) => &dh.dh_Ys.0,
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ecdh(ecdh) => ecdh.encode(buf),
            Self::Dh(dh) => dh.encode(buf),
        }
    }
}

#[cfg(feature = "tls12")]
impl KxDecode<'_> for ServerKeyExchangeParams {
    fn decode(r: &mut Reader<'_>, algo: KeyExchangeAlgorithm) -> Result<Self, InvalidMessage> {
        use KeyExchangeAlgorithm::*;
        Ok(match algo {
            ECDHE => Self::Ecdh(ServerEcdhParams::read(r)?),
            DHE => Self::Dh(ServerDhParams::read(r)?),
        })
    }
}

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub(crate) params: ServerKeyExchangeParams,
    pub(crate) dss: DigitallySignedStruct,
}

impl ServerKeyExchange {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.params.encode(buf);
        self.dss.encode(buf);
    }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload {
    Known(ServerKeyExchange),
    Unknown(Payload<'static>),
}

impl From<ServerKeyExchange> for ServerKeyExchangePayload {
    fn from(value: ServerKeyExchange) -> Self {
        Self::Known(value)
    }
}

impl Codec<'_> for ServerKeyExchangePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::Known(ref x) => x.encode(bytes),
            Self::Unknown(ref x) => x.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        // read as Unknown, fully parse when we know the
        // KeyExchangeAlgorithm
        Ok(Self::Unknown(Payload::read(r).into_owned()))
    }
}

impl ServerKeyExchangePayload {
    #[cfg(feature = "tls12")]
    pub(crate) fn unwrap_given_kxa(&self, kxa: KeyExchangeAlgorithm) -> Option<ServerKeyExchange> {
        if let Self::Unknown(ref unk) = *self {
            let mut rd = Reader::init(unk.bytes());

            let result = ServerKeyExchange {
                params: ServerKeyExchangeParams::decode(&mut rd, kxa).ok()?,
                dss: DigitallySignedStruct::read(&mut rd).ok()?,
            };

            if !rd.any_left() {
                return Some(result);
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
    fn extensions(&self) -> &[ServerExtension];

    /// Returns true if there is more than one extension of a given
    /// type.
    fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.extensions()
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&ServerExtension> {
        self.extensions()
            .iter()
            .find(|x| x.ext_type() == ext)
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ServerExtension::Protocols(ref protos) => protos.as_single_slice(),
            _ => None,
        }
    }

    fn server_cert_type(&self) -> Option<&CertificateType> {
        let ext = self.find_extension(ExtensionType::ServerCertificateType)?;
        match ext {
            ServerExtension::ServerCertType(req) => Some(req),
            _ => None,
        }
    }

    fn client_cert_type(&self) -> Option<&CertificateType> {
        let ext = self.find_extension(ExtensionType::ClientCertificateType)?;
        match ext {
            ServerExtension::ClientCertType(req) => Some(req),
            _ => None,
        }
    }

    fn quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ServerExtension::TransportParameters(ref bytes)
            | ServerExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    fn server_ech_extension(&self) -> Option<ServerEncryptedClientHello> {
        let ext = self.find_extension(ExtensionType::EncryptedClientHello)?;
        match ext {
            ServerExtension::EncryptedClientHello(ech) => Some(ech.clone()),
            _ => None,
        }
    }

    fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData)
            .is_some()
    }
}

impl HasServerExtensions for Vec<ServerExtension> {
    fn extensions(&self) -> &[ServerExtension] {
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

impl Codec<'_> for CertificateRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.certtypes.encode(bytes);
        self.sigschemes.encode(bytes);
        self.canames.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
    CertificateCompressionAlgorithms(Vec<CertificateCompressionAlgorithm>),
    Unknown(UnknownExtension),
}

impl CertReqExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::AuthorityNames(_) => ExtensionType::CertificateAuthorities,
            Self::CertificateCompressionAlgorithms(_) => ExtensionType::CompressCertificate,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for CertReqExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::SignatureAlgorithms(ref r) => r.encode(nested.buf),
            Self::AuthorityNames(ref r) => r.encode(nested.buf),
            Self::CertificateCompressionAlgorithms(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
            ExtensionType::CompressCertificate => {
                Self::CertificateCompressionAlgorithms(Vec::read(&mut sub)?)
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

impl Codec<'_> for CertificateRequestPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
            .find(|x| x.ext_type() == ext)
    }

    pub(crate) fn sigalgs_extension(&self) -> Option<&[SignatureScheme]> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            CertReqExtension::SignatureAlgorithms(ref sa) => Some(sa),
            _ => None,
        }
    }

    pub(crate) fn authorities_extension(&self) -> Option<&[DistinguishedName]> {
        let ext = self.find_extension(ExtensionType::CertificateAuthorities)?;
        match *ext {
            CertReqExtension::AuthorityNames(ref an) => Some(an),
            _ => None,
        }
    }

    pub(crate) fn certificate_compression_extension(
        &self,
    ) -> Option<&[CertificateCompressionAlgorithm]> {
        let ext = self.find_extension(ExtensionType::CompressCertificate)?;
        match *ext {
            CertReqExtension::CertificateCompressionAlgorithms(ref comps) => Some(comps),
            _ => None,
        }
    }
}

// -- NewSessionTicket --
#[derive(Debug)]
pub struct NewSessionTicketPayload {
    pub(crate) lifetime_hint: u32,
    // Tickets can be large (KB), so we deserialise this straight
    // into an Arc, so it can be passed directly into the client's
    // session object without copying.
    pub(crate) ticket: Arc<PayloadU16>,
}

impl NewSessionTicketPayload {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(lifetime_hint: u32, ticket: Vec<u8>) -> Self {
        Self {
            lifetime_hint,
            ticket: Arc::new(PayloadU16::new(ticket)),
        }
    }
}

impl Codec<'_> for NewSessionTicketPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let lifetime = u32::read(r)?;
        let ticket = Arc::new(PayloadU16::read(r)?);

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
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::EarlyData(_) => ExtensionType::EarlyData,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for NewSessionTicketExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::EarlyData(r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
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
    pub(crate) ticket: Arc<PayloadU16>,
    pub(crate) exts: Vec<NewSessionTicketExtension>,
}

impl NewSessionTicketPayloadTls13 {
    pub(crate) fn new(lifetime: u32, age_add: u32, nonce: Vec<u8>, ticket: Vec<u8>) -> Self {
        Self {
            lifetime,
            age_add,
            nonce: PayloadU8::new(nonce),
            ticket: Arc::new(PayloadU16::new(ticket)),
            exts: vec![],
        }
    }

    pub(crate) fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.exts
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&NewSessionTicketExtension> {
        self.exts
            .iter()
            .find(|x| x.ext_type() == ext)
    }

    pub(crate) fn max_early_data_size(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionType::EarlyData)?;
        match *ext {
            NewSessionTicketExtension::EarlyData(ref sz) => Some(*sz),
            _ => None,
        }
    }
}

impl Codec<'_> for NewSessionTicketPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let nonce = PayloadU8::read(r)?;
        let ticket = Arc::new(PayloadU16::read(r)?);
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
pub struct CertificateStatus<'a> {
    pub(crate) ocsp_response: PayloadU24<'a>,
}

impl<'a> Codec<'a> for CertificateStatus<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.ocsp_response.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => Ok(Self {
                ocsp_response: PayloadU24::read(r)?,
            }),
            _ => Err(InvalidMessage::InvalidCertificateStatusType),
        }
    }
}

impl<'a> CertificateStatus<'a> {
    pub(crate) fn new(ocsp: &'a [u8]) -> Self {
        CertificateStatus {
            ocsp_response: PayloadU24(Payload::Borrowed(ocsp)),
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.0.into_vec()
    }

    pub(crate) fn into_owned(self) -> CertificateStatus<'static> {
        CertificateStatus {
            ocsp_response: self.ocsp_response.into_owned(),
        }
    }
}

// -- RFC8879 compressed certificates

#[derive(Debug)]
pub struct CompressedCertificatePayload<'a> {
    pub(crate) alg: CertificateCompressionAlgorithm,
    pub(crate) uncompressed_len: u32,
    pub(crate) compressed: PayloadU24<'a>,
}

impl<'a> Codec<'a> for CompressedCertificatePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.alg.encode(bytes);
        codec::u24(self.uncompressed_len).encode(bytes);
        self.compressed.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            alg: CertificateCompressionAlgorithm::read(r)?,
            uncompressed_len: codec::u24::read(r)?.0,
            compressed: PayloadU24::read(r)?,
        })
    }
}

impl CompressedCertificatePayload<'_> {
    fn into_owned(self) -> CompressedCertificatePayload<'static> {
        CompressedCertificatePayload {
            compressed: self.compressed.into_owned(),
            ..self
        }
    }

    pub(crate) fn as_borrowed(&self) -> CompressedCertificatePayload<'_> {
        CompressedCertificatePayload {
            alg: self.alg,
            uncompressed_len: self.uncompressed_len,
            compressed: PayloadU24(Payload::Borrowed(self.compressed.0.bytes())),
        }
    }
}

#[derive(Debug)]
pub enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    HelloRetryRequest(HelloRetryRequest),
    Certificate(CertificateChain<'a>),
    CertificateTls13(CertificatePayloadTls13<'a>),
    CompressedCertificate(CompressedCertificatePayload<'a>),
    ServerKeyExchange(ServerKeyExchangePayload),
    CertificateRequest(CertificateRequestPayload),
    CertificateRequestTls13(CertificateRequestPayloadTls13),
    CertificateVerify(DigitallySignedStruct),
    ServerHelloDone,
    EndOfEarlyData,
    ClientKeyExchange(Payload<'a>),
    NewSessionTicket(NewSessionTicketPayload),
    NewSessionTicketTls13(NewSessionTicketPayloadTls13),
    EncryptedExtensions(Vec<ServerExtension>),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    MessageHash(Payload<'a>),
    Unknown(Payload<'a>),
}

impl HandshakePayload<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        use self::HandshakePayload::*;
        match *self {
            HelloRequest | ServerHelloDone | EndOfEarlyData => {}
            ClientHello(ref x) => x.encode(bytes),
            ServerHello(ref x) => x.encode(bytes),
            HelloRetryRequest(ref x) => x.encode(bytes),
            Certificate(ref x) => x.encode(bytes),
            CertificateTls13(ref x) => x.encode(bytes),
            CompressedCertificate(ref x) => x.encode(bytes),
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

    fn into_owned(self) -> HandshakePayload<'static> {
        use HandshakePayload::*;

        match self {
            HelloRequest => HelloRequest,
            ClientHello(x) => ClientHello(x),
            ServerHello(x) => ServerHello(x),
            HelloRetryRequest(x) => HelloRetryRequest(x),
            Certificate(x) => Certificate(x.into_owned()),
            CertificateTls13(x) => CertificateTls13(x.into_owned()),
            CompressedCertificate(x) => CompressedCertificate(x.into_owned()),
            ServerKeyExchange(x) => ServerKeyExchange(x),
            CertificateRequest(x) => CertificateRequest(x),
            CertificateRequestTls13(x) => CertificateRequestTls13(x),
            CertificateVerify(x) => CertificateVerify(x),
            ServerHelloDone => ServerHelloDone,
            EndOfEarlyData => EndOfEarlyData,
            ClientKeyExchange(x) => ClientKeyExchange(x.into_owned()),
            NewSessionTicket(x) => NewSessionTicket(x),
            NewSessionTicketTls13(x) => NewSessionTicketTls13(x),
            EncryptedExtensions(x) => EncryptedExtensions(x),
            KeyUpdate(x) => KeyUpdate(x),
            Finished(x) => Finished(x.into_owned()),
            CertificateStatus(x) => CertificateStatus(x.into_owned()),
            MessageHash(x) => MessageHash(x.into_owned()),
            Unknown(x) => Unknown(x.into_owned()),
        }
    }
}

#[derive(Debug)]
pub struct HandshakeMessagePayload<'a> {
    pub typ: HandshakeType,
    pub payload: HandshakePayload<'a>,
}

impl<'a> Codec<'a> for HandshakeMessagePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Self::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

impl<'a> HandshakeMessagePayload<'a> {
    pub(crate) fn read_version(
        r: &mut Reader<'a>,
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
            HandshakeType::CompressedCertificate => HandshakePayload::CompressedCertificate(
                CompressedCertificatePayload::read(&mut sub)?,
            ),
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

    pub(crate) fn encoding_for_binder_signing(&self) -> Vec<u8> {
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

    pub(crate) fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
        // output type, length, and encoded payload
        match self.typ {
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);

        let nested = LengthPrefixedBuffer::new(
            ListLength::U24 {
                max: usize::MAX,
                error: InvalidMessage::MessageTooLarge,
            },
            bytes,
        );

        match &self.payload {
            // for Server Hello and HelloRetryRequest payloads we need to encode the payload
            // differently based on the purpose of the encoding.
            HandshakePayload::ServerHello(payload) => payload.payload_encode(nested.buf, encoding),
            HandshakePayload::HelloRetryRequest(payload) => {
                payload.payload_encode(nested.buf, encoding)
            }

            // All other payload types are encoded the same regardless of purpose.
            _ => self.payload.encode(nested.buf),
        }
    }

    pub(crate) fn build_handshake_hash(hash: &[u8]) -> Self {
        Self {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.to_vec())),
        }
    }

    pub(crate) fn into_owned(self) -> HandshakeMessagePayload<'static> {
        let Self { typ, payload } = self;
        HandshakeMessagePayload {
            typ,
            payload: payload.into_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: HpkeKdf,
    pub aead_id: HpkeAead,
}

impl Codec<'_> for HpkeSymmetricCipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            kdf_id: HpkeKdf::read(r)?,
            aead_id: HpkeAead::read(r)?,
        })
    }
}

impl TlsListElement for HpkeSymmetricCipherSuite {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug, PartialEq)]
pub struct HpkeKeyConfig {
    pub config_id: u8,
    pub kem_id: HpkeKem,
    pub public_key: PayloadU16,
    pub symmetric_cipher_suites: Vec<HpkeSymmetricCipherSuite>,
}

impl Codec<'_> for HpkeKeyConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        self.kem_id.encode(bytes);
        self.public_key.encode(bytes);
        self.symmetric_cipher_suites
            .encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            config_id: u8::read(r)?,
            kem_id: HpkeKem::read(r)?,
            public_key: PayloadU16::read(r)?,
            symmetric_cipher_suites: Vec::<HpkeSymmetricCipherSuite>::read(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EchConfigContents {
    pub key_config: HpkeKeyConfig,
    pub maximum_name_length: u8,
    pub public_name: DnsName<'static>,
    pub extensions: Vec<EchConfigExtension>,
}

impl EchConfigContents {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub(crate) fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.extensions
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    /// Returns true if there is at least one mandatory unsupported extension.
    pub(crate) fn has_unknown_mandatory_extension(&self) -> bool {
        self.extensions
            .iter()
            // An extension is considered mandatory if the high bit of its type is set.
            .any(|ext| {
                matches!(ext.ext_type(), ExtensionType::Unknown(_))
                    && u16::from(ext.ext_type()) & 0x8000 != 0
            })
    }
}

impl Codec<'_> for EchConfigContents {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.key_config.encode(bytes);
        self.maximum_name_length.encode(bytes);
        let dns_name = &self.public_name.borrow();
        PayloadU8::encode_slice(dns_name.as_ref().as_ref(), bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            key_config: HpkeKeyConfig::read(r)?,
            maximum_name_length: u8::read(r)?,
            public_name: {
                DnsName::try_from(PayloadU8::read(r)?.0.as_slice())
                    .map_err(|_| InvalidMessage::InvalidServerName)?
                    .to_owned()
            },
            extensions: Vec::read(r)?,
        })
    }
}

/// An encrypted client hello (ECH) config.
#[derive(Clone, Debug, PartialEq)]
pub enum EchConfigPayload {
    /// A recognized V18 ECH configuration.
    V18(EchConfigContents),
    /// An unknown version ECH configuration.
    Unknown {
        version: EchVersion,
        contents: PayloadU16,
    },
}

impl TlsListElement for EchConfigPayload {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Codec<'_> for EchConfigPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::V18(c) => {
                // Write the version, the length, and the contents.
                EchVersion::V18.encode(bytes);
                let inner = LengthPrefixedBuffer::new(ListLength::U16, bytes);
                c.encode(inner.buf);
            }
            Self::Unknown { version, contents } => {
                // Unknown configuration versions are opaque.
                version.encode(bytes);
                contents.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let version = EchVersion::read(r)?;
        let length = u16::read(r)?;
        let mut contents = r.sub(length as usize)?;

        Ok(match version {
            EchVersion::V18 => Self::V18(EchConfigContents::read(&mut contents)?),
            _ => {
                // Note: we don't PayloadU16::read() here because we've already read the length prefix.
                let data = PayloadU16::new(contents.rest().into());
                Self::Unknown {
                    version,
                    contents: data,
                }
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EchConfigExtension {
    Unknown(UnknownExtension),
}

impl EchConfigExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for EchConfigExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        #[allow(clippy::match_single_binding)] // Future-proofing.
        let ext = match typ {
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("EchConfigExtension")
            .map(|_| ext)
    }
}

impl TlsListElement for EchConfigExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

/// Representation of the `ECHClientHello` client extension specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub enum EncryptedClientHello {
    /// A `ECHClientHello` with type [EchClientHelloType::ClientHelloOuter].
    Outer(EncryptedClientHelloOuter),
    /// An empty `ECHClientHello` with type [EchClientHelloType::ClientHelloInner].
    ///
    /// This variant has no payload.
    Inner,
}

impl Codec<'_> for EncryptedClientHello {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Outer(payload) => {
                EchClientHelloType::ClientHelloOuter.encode(bytes);
                payload.encode(bytes);
            }
            Self::Inner => {
                EchClientHelloType::ClientHelloInner.encode(bytes);
                // Empty payload.
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match EchClientHelloType::read(r)? {
            EchClientHelloType::ClientHelloOuter => {
                Ok(Self::Outer(EncryptedClientHelloOuter::read(r)?))
            }
            EchClientHelloType::ClientHelloInner => Ok(Self::Inner),
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }
}

/// Representation of the ECHClientHello extension with type outer specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub struct EncryptedClientHelloOuter {
    /// The cipher suite used to encrypt ClientHelloInner. Must match a value from
    /// ECHConfigContents.cipher_suites list.
    pub cipher_suite: HpkeSymmetricCipherSuite,
    /// The ECHConfigContents.key_config.config_id for the chosen ECHConfig.
    pub config_id: u8,
    /// The HPKE encapsulated key, used by servers to decrypt the corresponding payload field.
    /// This field is empty in a ClientHelloOuter sent in response to a HelloRetryRequest.
    pub enc: PayloadU16,
    /// The serialized and encrypted ClientHelloInner structure, encrypted using HPKE.
    pub payload: PayloadU16,
}

impl Codec<'_> for EncryptedClientHelloOuter {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cipher_suite.encode(bytes);
        self.config_id.encode(bytes);
        self.enc.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            cipher_suite: HpkeSymmetricCipherSuite::read(r)?,
            config_id: u8::read(r)?,
            enc: PayloadU16::read(r)?,
            payload: PayloadU16::read(r)?,
        })
    }
}

/// Representation of the ECHEncryptedExtensions extension specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub struct ServerEncryptedClientHello {
    pub(crate) retry_configs: Vec<EchConfigPayload>,
}

impl Codec<'_> for ServerEncryptedClientHello {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.retry_configs.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            retry_configs: Vec::<EchConfigPayload>::read(r)?,
        })
    }
}

/// The method of encoding to use for a handshake message.
///
/// In some cases a handshake message may be encoded differently depending on the purpose
/// the encoded message is being used for. For example, a [ServerHelloPayload] may be encoded
/// with the last 8 bytes of the random zeroed out when being encoded for ECH confirmation.
pub(crate) enum Encoding {
    /// Standard RFC 8446 encoding.
    Standard,
    /// Encoding for ECH confirmation.
    EchConfirmation,
    /// Encoding for ECH inner client hello.
    EchInnerHello { to_compress: Vec<ExtensionType> },
}

fn has_duplicates<I: IntoIterator<Item = E>, E: Into<T>, T: Eq + Ord>(iter: I) -> bool {
    let mut seen = BTreeSet::new();

    for x in iter {
        if !seen.insert(x.into()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_config_dupe_exts() {
        let unknown_ext = EchConfigExtension::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(0x42),
            payload: Payload::new(vec![0x42]),
        });
        let mut config = config_template();
        config
            .extensions
            .push(unknown_ext.clone());
        config.extensions.push(unknown_ext);

        assert!(config.has_duplicate_extension());
        assert!(!config.has_unknown_mandatory_extension());
    }

    #[test]
    fn test_ech_config_mandatory_exts() {
        let mandatory_unknown_ext = EchConfigExtension::Unknown(UnknownExtension {
            typ: ExtensionType::Unknown(0x42 | 0x8000), // Note: high bit set.
            payload: Payload::new(vec![0x42]),
        });
        let mut config = config_template();
        config
            .extensions
            .push(mandatory_unknown_ext);

        assert!(!config.has_duplicate_extension());
        assert!(config.has_unknown_mandatory_extension());
    }

    fn config_template() -> EchConfigContents {
        EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id: 0,
                kem_id: HpkeKem::DHKEM_P256_HKDF_SHA256,
                public_key: PayloadU16(b"xxx".into()),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::HKDF_SHA256,
                    aead_id: HpkeAead::AES_128_GCM,
                }],
            },
            maximum_name_length: 0,
            public_name: DnsName::try_from("example.com").unwrap(),
            extensions: vec![],
        }
    }
}
