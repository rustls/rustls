use crate::key;
use crate::msgs::base::{Payload, PayloadU8, PayloadU16, PayloadU24};
use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ECCurveType;
use crate::msgs::enums::PSKKeyExchangeMode;
use crate::msgs::enums::{CertificateStatusType, ClientCertificateType};
use crate::msgs::enums::{CipherSuite, Compression, ECPointFormat, ExtensionType};
use crate::msgs::enums::{HandshakeType, ProtocolVersion};
use crate::msgs::enums::{HashAlgorithm, ServerNameType, SignatureAlgorithm};
use crate::msgs::enums::{KeyUpdateRequest, NamedGroup, SignatureScheme};
use crate::rand;

#[cfg(feature = "logging")]
use crate::log::warn;

use std::borrow::Cow;
use std::collections;
use std::fmt;

macro_rules! declare_u8_vec(
  ($name:ident, $itemtype:ty) => {
    pub type $name = Vec<$itemtype>;

    impl<'a> Codec<'a> for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u8(bytes, self);
      }

      fn read(r: &mut Reader<'a>) -> Option<$name> {
        codec::read_vec_u8::<$itemtype>(r)
      }
    }
  }
);

macro_rules! declare_u16_vec(
  ($name:ident, $itemtype:ty) => {
    pub type $name = Vec<$itemtype>;

    impl<'a> Codec<'a> for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u16(bytes, self);
      }

      fn read(r: &mut Reader<'a>) -> Option<$name> {
        codec::read_vec_u16::<$itemtype>(r)
      }
    }
  }
);

macro_rules! declare_u16_vec_lifetime(
    ($name:ident, $item:ident) => {
      pub type $name<'a> = Vec<$item<'a>>;

      impl<'a> Codec<'a> for $name<'a> {
        fn encode(&self, bytes: &mut Vec<u8>) {
          codec::encode_vec_u16(bytes, self);
        }

        fn read(r: &mut Reader<'a>) -> Option<$name<'a>> {
          codec::read_vec_u16::<$item<'a>>(r)
        }
      }
    }
);

declare_u16_vec_lifetime!(VecU16OfPayloadU8, PayloadU8);
declare_u16_vec_lifetime!(VecU16OfPayloadU16, PayloadU16);

#[derive(Debug, PartialEq, Clone)]
pub struct Random([u8; 32]);

static HELLO_RETRY_REQUEST_RANDOM: Random = Random([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

static ZERO_RANDOM: Random = Random([0u8; 32]);

impl<'a> Codec<'a> for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'a>) -> Option<Random> {
        let bytes = r.take(32)?;
        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);

        Some(Random(opaque))
    }
}

impl Random {
    pub fn write_slice(&self, bytes: &mut [u8]) {
        let buf = self.get_encoding();
        bytes.copy_from_slice(&buf);
    }
}

impl From<[u8; 32]> for Random {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Copy, Clone)]
pub struct SessionID {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut t = f.debug_tuple("SessionID");
        for i in 0..self.len() {
            t.field(&self.data[i]);
        }
        t.finish()
    }
}

impl PartialEq for SessionID {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.data[i] ^ other.data[i]
        }

        diff == 0u8
    }
}

impl<'a> Codec<'a> for SessionID {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut Reader<'a>) -> Option<SessionID> {
        let len = u8::read(r)? as usize;
        if len > 32 {
            return None;
        }

        let bytes = r.take(len)?;
        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);

        Some(SessionID { data: out, len })
    }
}

impl SessionID {
    pub fn random() -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        rand::fill_random(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    pub fn empty() -> SessionID {
        SessionID {
            data: [0u8; 32],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Debug)]
pub struct UnknownExtension<'a> {
    pub typ: ExtensionType,
    pub payload: Payload<'a>,
}

impl<'a> UnknownExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut Reader<'a>) -> Self {
        let payload = Payload::read(r);
        Self { typ, payload }
    }
}

declare_u8_vec!(ECPointFormatList, ECPointFormat);

pub trait SupportedPointFormats {
    fn supported() -> ECPointFormatList;
}

impl SupportedPointFormats for ECPointFormatList {
    fn supported() -> ECPointFormatList {
        vec![ECPointFormat::Uncompressed]
    }
}

declare_u16_vec!(NamedGroups, NamedGroup);

declare_u16_vec!(SupportedSignatureSchemes, SignatureScheme);

pub trait DecomposedSignatureScheme {
    fn sign(&self) -> SignatureAlgorithm;
    fn make(alg: SignatureAlgorithm, hash: HashAlgorithm) -> SignatureScheme;
}

impl DecomposedSignatureScheme for SignatureScheme {
    fn sign(&self) -> SignatureAlgorithm {
        match *self {
            SignatureScheme::RSA_PKCS1_SHA1
            | SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
            SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }

    fn make(alg: SignatureAlgorithm, hash: HashAlgorithm) -> SignatureScheme {
        use crate::msgs::enums::HashAlgorithm::{SHA1, SHA256, SHA384, SHA512};
        use crate::msgs::enums::SignatureAlgorithm::{ECDSA, RSA};

        match (alg, hash) {
            (RSA, SHA1) => SignatureScheme::RSA_PKCS1_SHA1,
            (RSA, SHA256) => SignatureScheme::RSA_PKCS1_SHA256,
            (RSA, SHA384) => SignatureScheme::RSA_PKCS1_SHA384,
            (RSA, SHA512) => SignatureScheme::RSA_PKCS1_SHA512,
            (ECDSA, SHA256) => SignatureScheme::ECDSA_NISTP256_SHA256,
            (ECDSA, SHA384) => SignatureScheme::ECDSA_NISTP384_SHA384,
            (ECDSA, SHA512) => SignatureScheme::ECDSA_NISTP521_SHA512,
            (_, _) => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ServerNamePayload<'a> {
    // Stored twice, bytes so we can round-trip, and DnsName for use
    HostName((PayloadU16<'a>, webpki::DnsName)),
    Unknown(Payload<'a>),
}

impl<'a> ServerNamePayload<'a> {
    pub fn new_hostname(hostname: webpki::DnsName) -> ServerNamePayload<'static> {
        let raw = {
            let s: &str = hostname.as_ref().into();
            PayloadU16::new(s.as_bytes().to_vec())
        };
        ServerNamePayload::HostName((raw, hostname))
    }

    fn read_hostname(r: &mut Reader<'a>) -> Option<ServerNamePayload<'a>> {
        let raw = PayloadU16::read(r)?;

        let dns_name = {
            match webpki::DnsNameRef::try_from_ascii(&raw.0) {
                Ok(dns_name) => dns_name.into(),
                Err(_) => {
                    warn!("Illegal SNI hostname received {:?}", raw.0);
                    return None;
                }
            }
        };
        Some(ServerNamePayload::HostName((raw, dns_name)))
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServerNamePayload::HostName((ref r, _)) => r.encode(bytes),
            ServerNamePayload::Unknown(ref r) => r.encode(bytes),
        }
    }

    fn to_owned(&self) -> ServerNamePayload<'static> {
        use ServerNamePayload::*;
        match self {
            HostName((payload, dns)) => HostName((payload.to_owned(), dns.clone())),
            Unknown(payload) => Unknown(payload.to_owned()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerName<'a> {
    pub typ: ServerNameType,
    pub payload: ServerNamePayload<'a>,
}

impl<'a> ServerName<'a> {
    pub fn to_owned(&self) -> ServerName<'static> {
        ServerName {
            typ: self.typ,
            payload: self.payload.to_owned(),
        }
    }
}

impl<'a> Codec<'a> for ServerName<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<ServerName<'a>> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r)),
        };

        Some(ServerName { typ, payload })
    }
}

declare_u16_vec_lifetime!(ServerNameRequest, ServerName);

pub trait ConvertServerNameList {
    fn has_duplicate_names_for_type(&self) -> bool;
    fn get_single_hostname(&self) -> Option<webpki::DnsNameRef>;
}

impl<'a> ConvertServerNameList for ServerNameRequest<'a> {
    /// RFC6066: "The ServerNameList MUST NOT contain more than one name of the same name_type."
    fn has_duplicate_names_for_type(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for name in self {
            if !seen.insert(name.typ.get_u8()) {
                return true;
            }
        }

        false
    }

    fn get_single_hostname(&self) -> Option<webpki::DnsNameRef<'_>> {
        fn only_dns_hostnames<'a>(name: &'a ServerName) -> Option<webpki::DnsNameRef<'a>> {
            if let ServerNamePayload::HostName((_, ref dns)) = name.payload {
                Some(dns.as_ref())
            } else {
                None
            }
        }

        self.iter()
            .filter_map(only_dns_hostnames)
            .next()
    }
}

pub type ProtocolNameList<'a> = VecU16OfPayloadU8<'a>;

pub trait ConvertProtocolNameList {
    fn from_slices(names: &[&[u8]]) -> Self;
    fn to_slices(&self) -> Vec<&[u8]>;
    fn as_single_slice(&self) -> Option<&[u8]>;
}

impl<'a> ConvertProtocolNameList for ProtocolNameList<'a> {
    fn from_slices(names: &[&[u8]]) -> ProtocolNameList<'static> {
        let mut ret = Vec::new();

        for name in names {
            ret.push(PayloadU8::new(name.to_vec()));
        }

        ret
    }

    fn to_slices(&self) -> Vec<&[u8]> {
        self.iter()
            .map(|proto| -> &[u8] { &proto.0 })
            .collect::<Vec<&[u8]>>()
    }

    fn as_single_slice(&self) -> Option<&[u8]> {
        if self.len() == 1 {
            Some(&self[0].0)
        } else {
            None
        }
    }
}

// --- TLS 1.3 Key shares ---
#[derive(Clone, Debug)]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup,
    pub payload: PayloadU16<'a>,
}

impl KeyShareEntry<'static> {
    pub fn new(group: NamedGroup, payload: &[u8]) -> KeyShareEntry {
        KeyShareEntry {
            group,
            payload: PayloadU16::new(payload.to_vec()),
        }
    }
}

impl<'a> Codec<'a> for KeyShareEntry<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<KeyShareEntry<'a>> {
        let group = NamedGroup::read(r)?;
        let payload = PayloadU16::read(r)?;

        Some(KeyShareEntry { group, payload })
    }
}

// --- TLS 1.3 PresharedKey offers ---
#[derive(Clone, Debug)]
pub struct PresharedKeyIdentity<'a> {
    pub identity: PayloadU16<'a>,
    pub obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity<'static> {
    pub fn new(id: Vec<u8>, age: u32) -> Self {
        PresharedKeyIdentity {
            identity: PayloadU16::new(id),
            obfuscated_ticket_age: age,
        }
    }
}

impl<'a> Codec<'a> for PresharedKeyIdentity<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<PresharedKeyIdentity<'a>> {
        Some(PresharedKeyIdentity {
            identity: PayloadU16::read(r)?,
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

declare_u16_vec_lifetime!(PresharedKeyIdentities, PresharedKeyIdentity);

pub type PresharedKeyBinder<'a> = PayloadU8<'a>;
pub type PresharedKeyBinders<'a> = VecU16OfPayloadU8<'a>;

#[derive(Clone, Debug)]
pub struct PresharedKeyOffer<'a> {
    pub identities: PresharedKeyIdentities<'a>,
    pub binders: PresharedKeyBinders<'a>,
}

impl PresharedKeyOffer<'static> {
    /// Make a new one with one entry.
    pub fn new(id: PresharedKeyIdentity<'static>, binder: Vec<u8>) -> Self {
        PresharedKeyOffer {
            identities: vec![id],
            binders: vec![PresharedKeyBinder::new(binder)],
        }
    }
}

impl<'a> Codec<'a> for PresharedKeyOffer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identities.encode(bytes);
        self.binders.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<PresharedKeyOffer<'a>> {
        Some(PresharedKeyOffer {
            identities: PresharedKeyIdentities::read(r)?,
            binders: PresharedKeyBinders::read(r)?,
        })
    }
}

// --- RFC6066 certificate status request ---
type ResponderIDs<'a> = VecU16OfPayloadU16<'a>;

#[derive(Clone, Debug)]
pub struct OCSPCertificateStatusRequest<'a> {
    pub responder_ids: ResponderIDs<'a>,
    pub extensions: PayloadU16<'a>,
}

impl<'a> Codec<'a> for OCSPCertificateStatusRequest<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.responder_ids.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<OCSPCertificateStatusRequest<'a>> {
        Some(OCSPCertificateStatusRequest {
            responder_ids: ResponderIDs::read(r)?,
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CertificateStatusRequest<'a> {
    OCSP(OCSPCertificateStatusRequest<'a>),
    Unknown((CertificateStatusType, Payload<'a>)),
}

impl<'a> Codec<'a> for CertificateStatusRequest<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            CertificateStatusRequest::OCSP(ref r) => r.encode(bytes),
            CertificateStatusRequest::Unknown((typ, ref payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateStatusRequest<'a>> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => {
                let ocsp_req = OCSPCertificateStatusRequest::read(r)?;
                Some(CertificateStatusRequest::OCSP(ocsp_req))
            }
            _ => {
                let data = Payload::read(r);
                Some(CertificateStatusRequest::Unknown((typ, data)))
            }
        }
    }
}

impl CertificateStatusRequest<'static> {
    pub fn build_ocsp() -> Self {
        let ocsp = OCSPCertificateStatusRequest {
            responder_ids: ResponderIDs::new(),
            extensions: PayloadU16::empty(),
        };
        CertificateStatusRequest::OCSP(ocsp)
    }
}

// ---
// SCTs

pub type SCTList<'a> = VecU16OfPayloadU16<'a>;

// ---

declare_u8_vec!(PSKKeyExchangeModes, PSKKeyExchangeMode);
declare_u16_vec_lifetime!(KeyShareEntries, KeyShareEntry);
declare_u8_vec!(ProtocolVersions, ProtocolVersion);

#[derive(Clone, Debug)]
pub enum ClientExtension<'a> {
    ECPointFormats(ECPointFormatList),
    NamedGroups(NamedGroups),
    SignatureAlgorithms(SupportedSignatureSchemes),
    ServerName(ServerNameRequest<'a>),
    SessionTicketRequest,
    SessionTicketOffer(Payload<'a>),
    Protocols(ProtocolNameList<'a>),
    SupportedVersions(ProtocolVersions),
    KeyShare(KeyShareEntries<'a>),
    PresharedKeyModes(PSKKeyExchangeModes),
    PresharedKey(PresharedKeyOffer<'a>),
    Cookie(PayloadU16<'a>),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(CertificateStatusRequest<'a>),
    SignedCertificateTimestampRequest,
    TransportParameters(Cow<'a, [u8]>),
    TransportParametersDraft(Cow<'a, [u8]>),
    EarlyData,
    Unknown(UnknownExtension<'a>),
}

impl<'a> ClientExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            ClientExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
            ClientExtension::NamedGroups(_) => ExtensionType::EllipticCurves,
            ClientExtension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            ClientExtension::ServerName(_) => ExtensionType::ServerName,
            ClientExtension::SessionTicketRequest | ClientExtension::SessionTicketOffer(_) => {
                ExtensionType::SessionTicket
            }
            ClientExtension::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            ClientExtension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            ClientExtension::KeyShare(_) => ExtensionType::KeyShare,
            ClientExtension::PresharedKeyModes(_) => ExtensionType::PSKKeyExchangeModes,
            ClientExtension::PresharedKey(_) => ExtensionType::PreSharedKey,
            ClientExtension::Cookie(_) => ExtensionType::Cookie,
            ClientExtension::ExtendedMasterSecretRequest => ExtensionType::ExtendedMasterSecret,
            ClientExtension::CertificateStatusRequest(_) => ExtensionType::StatusRequest,
            ClientExtension::SignedCertificateTimestampRequest => ExtensionType::SCT,
            ClientExtension::TransportParameters(_) => ExtensionType::TransportParameters,
            ClientExtension::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            ClientExtension::EarlyData => ExtensionType::EarlyData,
            ClientExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl<'a> Codec<'a> for ClientExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            ClientExtension::ECPointFormats(ref r) => r.encode(&mut sub),
            ClientExtension::NamedGroups(ref r) => r.encode(&mut sub),
            ClientExtension::SignatureAlgorithms(ref r) => r.encode(&mut sub),
            ClientExtension::ServerName(ref r) => r.encode(&mut sub),
            ClientExtension::SessionTicketRequest
            | ClientExtension::ExtendedMasterSecretRequest
            | ClientExtension::SignedCertificateTimestampRequest
            | ClientExtension::EarlyData => {}
            ClientExtension::SessionTicketOffer(ref r) => r.encode(&mut sub),
            ClientExtension::Protocols(ref r) => r.encode(&mut sub),
            ClientExtension::SupportedVersions(ref r) => r.encode(&mut sub),
            ClientExtension::KeyShare(ref r) => r.encode(&mut sub),
            ClientExtension::PresharedKeyModes(ref r) => r.encode(&mut sub),
            ClientExtension::PresharedKey(ref r) => r.encode(&mut sub),
            ClientExtension::Cookie(ref r) => r.encode(&mut sub),
            ClientExtension::CertificateStatusRequest(ref r) => r.encode(&mut sub),
            ClientExtension::TransportParameters(ref r)
            | ClientExtension::TransportParametersDraft(ref r) => sub.extend_from_slice(r),
            ClientExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<ClientExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => {
                ClientExtension::ECPointFormats(ECPointFormatList::read(&mut sub)?)
            }
            ExtensionType::EllipticCurves => {
                ClientExtension::NamedGroups(NamedGroups::read(&mut sub)?)
            }
            ExtensionType::SignatureAlgorithms => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                ClientExtension::SignatureAlgorithms(schemes)
            }
            ExtensionType::ServerName => {
                ClientExtension::ServerName(ServerNameRequest::read(&mut sub)?)
            }
            ExtensionType::SessionTicket => {
                if sub.any_left() {
                    let contents = Payload::read(&mut sub);
                    ClientExtension::SessionTicketOffer(contents)
                } else {
                    ClientExtension::SessionTicketRequest
                }
            }
            ExtensionType::ALProtocolNegotiation => {
                ClientExtension::Protocols(ProtocolNameList::read(&mut sub)?)
            }
            ExtensionType::SupportedVersions => {
                ClientExtension::SupportedVersions(ProtocolVersions::read(&mut sub)?)
            }
            ExtensionType::KeyShare => ClientExtension::KeyShare(KeyShareEntries::read(&mut sub)?),
            ExtensionType::PSKKeyExchangeModes => {
                ClientExtension::PresharedKeyModes(PSKKeyExchangeModes::read(&mut sub)?)
            }
            ExtensionType::PreSharedKey => {
                ClientExtension::PresharedKey(PresharedKeyOffer::read(&mut sub)?)
            }
            ExtensionType::Cookie => ClientExtension::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret if !sub.any_left() => {
                ClientExtension::ExtendedMasterSecretRequest
            }
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                ClientExtension::CertificateStatusRequest(csr)
            }
            ExtensionType::SCT if !sub.any_left() => {
                ClientExtension::SignedCertificateTimestampRequest
            }
            ExtensionType::TransportParameters => {
                ClientExtension::TransportParameters(sub.rest().into())
            }
            ExtensionType::TransportParametersDraft => {
                ClientExtension::TransportParametersDraft(sub.rest().into())
            }
            ExtensionType::EarlyData if !sub.any_left() => ClientExtension::EarlyData,
            _ => ClientExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

fn trim_hostname_trailing_dot_for_sni(dns_name: webpki::DnsNameRef) -> webpki::DnsName {
    let dns_name_str: &str = dns_name.into();

    // RFC6066: "The hostname is represented as a byte string using
    // ASCII encoding without a trailing dot"
    if dns_name_str.ends_with('.') {
        let trimmed = &dns_name_str[0..dns_name_str.len() - 1];
        webpki::DnsNameRef::try_from_ascii_str(trimmed)
            .unwrap()
            .to_owned()
    } else {
        dns_name.to_owned()
    }
}

impl ClientExtension<'static> {
    /// Make a basic SNI ServerNameRequest quoting `hostname`.
    pub fn make_sni(dns_name: webpki::DnsNameRef) -> Self {
        let name = ServerName {
            typ: ServerNameType::HostName,
            payload: ServerNamePayload::new_hostname(trim_hostname_trailing_dot_for_sni(dns_name)),
        };

        ClientExtension::ServerName(vec![name])
    }
}

#[derive(Clone, Debug)]
pub enum ServerExtension<'a> {
    ECPointFormats(ECPointFormatList),
    ServerNameAck,
    SessionTicketAck,
    RenegotiationInfo(PayloadU8<'a>),
    Protocols(ProtocolNameList<'a>),
    KeyShare(KeyShareEntry<'a>),
    PresharedKey(u16),
    ExtendedMasterSecretAck,
    CertificateStatusAck,
    SignedCertificateTimestamp(SCTList<'a>),
    SupportedVersions(ProtocolVersion),
    TransportParameters(Cow<'a, [u8]>),
    TransportParametersDraft(Cow<'a, [u8]>),
    EarlyData,
    Unknown(UnknownExtension<'a>),
}

impl<'a> ServerExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            ServerExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
            ServerExtension::ServerNameAck => ExtensionType::ServerName,
            ServerExtension::SessionTicketAck => ExtensionType::SessionTicket,
            ServerExtension::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            ServerExtension::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            ServerExtension::KeyShare(_) => ExtensionType::KeyShare,
            ServerExtension::PresharedKey(_) => ExtensionType::PreSharedKey,
            ServerExtension::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            ServerExtension::CertificateStatusAck => ExtensionType::StatusRequest,
            ServerExtension::SignedCertificateTimestamp(_) => ExtensionType::SCT,
            ServerExtension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            ServerExtension::TransportParameters(_) => ExtensionType::TransportParameters,
            ServerExtension::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            ServerExtension::EarlyData => ExtensionType::EarlyData,
            ServerExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl<'a> Codec<'a> for ServerExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            ServerExtension::ECPointFormats(ref r) => r.encode(&mut sub),
            ServerExtension::ServerNameAck
            | ServerExtension::SessionTicketAck
            | ServerExtension::ExtendedMasterSecretAck
            | ServerExtension::CertificateStatusAck
            | ServerExtension::EarlyData => {}
            ServerExtension::RenegotiationInfo(ref r) => r.encode(&mut sub),
            ServerExtension::Protocols(ref r) => r.encode(&mut sub),
            ServerExtension::KeyShare(ref r) => r.encode(&mut sub),
            ServerExtension::PresharedKey(r) => r.encode(&mut sub),
            ServerExtension::SignedCertificateTimestamp(ref r) => r.encode(&mut sub),
            ServerExtension::SupportedVersions(ref r) => r.encode(&mut sub),
            ServerExtension::TransportParameters(ref r)
            | ServerExtension::TransportParametersDraft(ref r) => sub.extend_from_slice(r),
            ServerExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<ServerExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => {
                ServerExtension::ECPointFormats(ECPointFormatList::read(&mut sub)?)
            }
            ExtensionType::ServerName => ServerExtension::ServerNameAck,
            ExtensionType::SessionTicket => ServerExtension::SessionTicketAck,
            ExtensionType::StatusRequest => ServerExtension::CertificateStatusAck,
            ExtensionType::RenegotiationInfo => {
                ServerExtension::RenegotiationInfo(PayloadU8::read(&mut sub)?)
            }
            ExtensionType::ALProtocolNegotiation => {
                ServerExtension::Protocols(ProtocolNameList::read(&mut sub)?)
            }
            ExtensionType::KeyShare => ServerExtension::KeyShare(KeyShareEntry::read(&mut sub)?),
            ExtensionType::PreSharedKey => ServerExtension::PresharedKey(u16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret => ServerExtension::ExtendedMasterSecretAck,
            ExtensionType::SCT => {
                let scts = SCTList::read(&mut sub)?;
                ServerExtension::SignedCertificateTimestamp(scts)
            }
            ExtensionType::SupportedVersions => {
                ServerExtension::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            ExtensionType::TransportParameters => {
                ServerExtension::TransportParameters(sub.rest().into())
            }
            ExtensionType::TransportParametersDraft => {
                ServerExtension::TransportParametersDraft(sub.rest().into())
            }
            ExtensionType::EarlyData => ServerExtension::EarlyData,
            _ => ServerExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

impl<'a> ServerExtension<'a> {
    pub fn make_alpn(proto: &[&[u8]]) -> ServerExtension<'static> {
        ServerExtension::Protocols(ProtocolNameList::from_slices(proto))
    }

    pub fn make_empty_renegotiation_info() -> ServerExtension<'static> {
        let empty = Vec::new();
        ServerExtension::RenegotiationInfo(PayloadU8::new(empty))
    }

    pub fn make_sct(sctl: &[u8]) -> ServerExtension<'static> {
        let scts = SCTList::read_bytes(&sctl).expect("invalid SCT list");
        ServerExtension::SignedCertificateTimestamp(
            scts.into_iter()
                .map(|x| x.to_owned())
                .collect(),
        )
    }
}

#[derive(Debug)]
pub struct ClientHelloPayload<'a> {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<Compression>,
    pub extensions: Vec<ClientExtension<'a>>,
}

impl<'a> Codec<'a> for ClientHelloPayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        codec::encode_vec_u16(bytes, &self.cipher_suites);
        codec::encode_vec_u8(bytes, &self.compression_methods);

        if !self.extensions.is_empty() {
            codec::encode_vec_u16(bytes, &self.extensions);
        }
    }

    fn read(r: &mut Reader<'a>) -> Option<ClientHelloPayload<'a>> {
        let mut ret = ClientHelloPayload {
            client_version: ProtocolVersion::read(r)?,
            random: Random::read(r)?,
            session_id: SessionID::read(r)?,
            cipher_suites: codec::read_vec_u16::<CipherSuite>(r)?,
            compression_methods: codec::read_vec_u8::<Compression>(r)?,
            extensions: Vec::new(),
        };

        if r.any_left() {
            ret.extensions = codec::read_vec_u16::<ClientExtension>(r)?;
        }

        if r.any_left() || ret.extensions.is_empty() {
            None
        } else {
            Some(ret)
        }
    }
}

impl<'a> ClientHelloPayload<'a> {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.extensions {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
        self.extensions
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub fn get_sni_extension(&self) -> Option<&ServerNameRequest> {
        let ext = self.find_extension(ExtensionType::ServerName)?;
        match *ext {
            ClientExtension::ServerName(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureSchemes> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            ClientExtension::SignatureAlgorithms(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_namedgroups_extension(&self) -> Option<&NamedGroups> {
        let ext = self.find_extension(ExtensionType::EllipticCurves)?;
        match *ext {
            ClientExtension::NamedGroups(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ClientExtension::ECPointFormats(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_alpn_extension(&self) -> Option<&ProtocolNameList> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ClientExtension::Protocols(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ClientExtension::TransportParameters(ref bytes)
            | ClientExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    pub fn get_ticket_extension(&self) -> Option<&ClientExtension> {
        self.find_extension(ExtensionType::SessionTicket)
    }

    pub fn get_versions_extension(&self) -> Option<&ProtocolVersions> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ClientExtension::SupportedVersions(ref vers) => Some(vers),
            _ => None,
        }
    }

    pub fn get_keyshare_extension(&self) -> Option<&KeyShareEntries> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ClientExtension::KeyShare(ref shares) => Some(shares),
            _ => None,
        }
    }

    pub fn has_keyshare_extension_with_duplicates(&self) -> bool {
        if let Some(entries) = self.get_keyshare_extension() {
            let mut seen = collections::HashSet::new();

            for kse in entries {
                let grp = kse.group.get_u16();

                if !seen.insert(grp) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_psk(&self) -> Option<&PresharedKeyOffer> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ClientExtension::PresharedKey(ref psk) => Some(psk),
            _ => None,
        }
    }

    pub fn check_psk_ext_is_last(&self) -> bool {
        self.extensions
            .last()
            .map_or(false, |ext| ext.get_type() == ExtensionType::PreSharedKey)
    }

    pub fn get_psk_modes(&self) -> Option<&PSKKeyExchangeModes> {
        let ext = self.find_extension(ExtensionType::PSKKeyExchangeModes)?;
        match *ext {
            ClientExtension::PresharedKeyModes(ref psk_modes) => Some(psk_modes),
            _ => None,
        }
    }

    pub fn psk_mode_offered(&self, mode: PSKKeyExchangeMode) -> bool {
        self.get_psk_modes()
            .map(|modes| modes.contains(&mode))
            .unwrap_or(false)
    }


    pub fn set_psk_binder(&mut self, binder: impl Into<Vec<u8>>) {
        let last_extension = self.extensions.last_mut();
        if let Some(ClientExtension::PresharedKey(ref mut offer)) = last_extension {
            offer.binders[0] = PresharedKeyBinder::new(binder.into());
        }
    }

    pub fn ems_support_offered(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData)
            .is_some()
    }
}

#[derive(Debug)]
pub enum HelloRetryExtension<'a> {
    KeyShare(NamedGroup),
    Cookie(PayloadU16<'a>),
    SupportedVersions(ProtocolVersion),
    Unknown(UnknownExtension<'a>),
}

impl<'a> HelloRetryExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            HelloRetryExtension::KeyShare(_) => ExtensionType::KeyShare,
            HelloRetryExtension::Cookie(_) => ExtensionType::Cookie,
            HelloRetryExtension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            HelloRetryExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl<'a> Codec<'a> for HelloRetryExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            HelloRetryExtension::KeyShare(ref r) => r.encode(&mut sub),
            HelloRetryExtension::Cookie(ref r) => r.encode(&mut sub),
            HelloRetryExtension::SupportedVersions(ref r) => r.encode(&mut sub),
            HelloRetryExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<HelloRetryExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::KeyShare => HelloRetryExtension::KeyShare(NamedGroup::read(&mut sub)?),
            ExtensionType::Cookie => HelloRetryExtension::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::SupportedVersions => {
                HelloRetryExtension::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            _ => HelloRetryExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

#[derive(Debug)]
pub struct HelloRetryRequest<'a> {
    pub legacy_version: ProtocolVersion,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<HelloRetryExtension<'a>>,
}

impl<'a> Codec<'a> for HelloRetryRequest<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        HELLO_RETRY_REQUEST_RANDOM.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        Compression::Null.encode(bytes);
        codec::encode_vec_u16(bytes, &self.extensions);
    }

    fn read(r: &mut Reader<'a>) -> Option<HelloRetryRequest<'a>> {
        let session_id = SessionID::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let compression = Compression::read(r)?;

        if compression != Compression::Null {
            return None;
        }

        Some(HelloRetryRequest {
            legacy_version: ProtocolVersion::Unknown(0),
            session_id,
            cipher_suite,
            extensions: codec::read_vec_u16::<HelloRetryExtension>(r)?,
        })
    }
}

impl<'a> HelloRetryRequest<'a> {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.extensions {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn has_unknown_extension(&self) -> bool {
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

    pub fn get_cookie(&self) -> Option<&PayloadU16> {
        let ext = self.find_extension(ExtensionType::Cookie)?;
        match *ext {
            HelloRetryExtension::Cookie(ref ck) => Some(ck),
            _ => None,
        }
    }

    pub fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            HelloRetryExtension::SupportedVersions(ver) => Some(ver),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ServerHelloPayload<'a> {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: Compression,
    pub extensions: Vec<ServerExtension<'a>>,
}

impl<'a> Codec<'a> for ServerHelloPayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        self.random.encode(bytes);

        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        codec::encode_vec_u16(bytes, &self.extensions);
    }

    // minus version and random, which have already been read.
    fn read(r: &mut Reader<'a>) -> Option<ServerHelloPayload<'a>> {
        let session_id = SessionID::read(r)?;
        let suite = CipherSuite::read(r)?;
        let compression = Compression::read(r)?;
        let extensions = codec::read_vec_u16::<ServerExtension>(r)?;

        let ret = ServerHelloPayload {
            legacy_version: ProtocolVersion::Unknown(0),
            random: ZERO_RANDOM.clone(),
            session_id,
            cipher_suite: suite,
            compression_method: compression,
            extensions,
        };

        if r.any_left() { None } else { Some(ret) }
    }
}

impl<'a> HasServerExtensions for ServerHelloPayload<'a> {
    fn get_extensions(&self) -> &[ServerExtension] {
        &self.extensions
    }
}

impl<'a> ServerHelloPayload<'a> {
    pub fn get_key_share(&self) -> Option<&KeyShareEntry> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ServerExtension::KeyShare(ref share) => Some(share),
            _ => None,
        }
    }

    pub fn get_psk_index(&self) -> Option<u16> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ServerExtension::PresharedKey(ref index) => Some(*index),
            _ => None,
        }
    }

    pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ServerExtension::ECPointFormats(ref fmts) => Some(fmts),
            _ => None,
        }
    }

    pub fn ems_support_acked(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub fn get_sct_list(&self) -> Option<&SCTList> {
        let ext = self.find_extension(ExtensionType::SCT)?;
        match *ext {
            ServerExtension::SignedCertificateTimestamp(ref sctl) => Some(sctl),
            _ => None,
        }
    }

    pub fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ServerExtension::SupportedVersions(vers) => Some(vers),
            _ => None,
        }
    }
}

pub type CertificatePayload<'a> = Vec<key::Certificate<'a>>;

impl<'a> Codec<'a> for CertificatePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u24(bytes, self);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificatePayload<'a>> {
        // 64KB of certificates is plenty, 16MB is obviously silly
        codec::read_vec_u24_limited(r, 0x10000)
    }
}

// TLS1.3 changes the Certificate payload encoding.
// That's annoying. It means the parsing is not
// context-free any more.

#[derive(Debug)]
pub enum CertificateExtension<'a> {
    CertificateStatus(CertificateStatus<'a>),
    SignedCertificateTimestamp(SCTList<'a>),
    Unknown(UnknownExtension<'a>),
}

impl<'a> CertificateExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            CertificateExtension::CertificateStatus(_) => ExtensionType::StatusRequest,
            CertificateExtension::SignedCertificateTimestamp(_) => ExtensionType::SCT,
            CertificateExtension::Unknown(ref r) => r.typ,
        }
    }

    pub fn make_sct(sct_list: &'a [u8]) -> CertificateExtension<'a> {
        let sctl = SCTList::read_bytes(sct_list).expect("invalid SCT list");
        CertificateExtension::SignedCertificateTimestamp(sctl)
    }

    pub fn get_cert_status(&self) -> Option<&[u8]> {
        match *self {
            CertificateExtension::CertificateStatus(ref cs) => Some(&cs.ocsp_response.0),
            _ => None,
        }
    }

    pub fn get_sct_list(&self) -> Option<&SCTList> {
        match *self {
            CertificateExtension::SignedCertificateTimestamp(ref sctl) => Some(sctl),
            _ => None,
        }
    }
}

impl<'a> Codec<'a> for CertificateExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            CertificateExtension::CertificateStatus(ref r) => r.encode(&mut sub),
            CertificateExtension::SignedCertificateTimestamp(ref r) => r.encode(&mut sub),
            CertificateExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::StatusRequest => {
                let st = CertificateStatus::read(&mut sub)?;
                CertificateExtension::CertificateStatus(st)
            }
            ExtensionType::SCT => {
                let scts = SCTList::read(&mut sub)?;
                CertificateExtension::SignedCertificateTimestamp(scts)
            }
            _ => CertificateExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

declare_u16_vec_lifetime!(CertificateExtensions, CertificateExtension);

#[derive(Debug)]
pub struct CertificateEntry<'a> {
    pub cert: key::Certificate<'a>,
    pub exts: CertificateExtensions<'a>,
}

impl<'a> Codec<'a> for CertificateEntry<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateEntry<'a>> {
        Some(CertificateEntry {
            cert: key::Certificate::read(r)?,
            exts: CertificateExtensions::read(r)?,
        })
    }
}

impl<'a> CertificateEntry<'a> {
    pub fn new(cert: key::Certificate<'a>) -> CertificateEntry<'a> {
        CertificateEntry {
            cert,
            exts: Vec::new(),
        }
    }

    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.exts {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn has_unknown_extension(&self) -> bool {
        self.exts.iter().any(|ext| {
            ext.get_type() != ExtensionType::StatusRequest && ext.get_type() != ExtensionType::SCT
        })
    }

    pub fn get_ocsp_response(&self) -> Option<&[u8]> {
        self.exts
            .iter()
            .find(|ext| ext.get_type() == ExtensionType::StatusRequest)
            .and_then(CertificateExtension::get_cert_status)
    }

    pub fn get_scts(&self) -> Option<&SCTList> {
        self.exts
            .iter()
            .find(|ext| ext.get_type() == ExtensionType::SCT)
            .and_then(CertificateExtension::get_sct_list)
    }
}

#[derive(Debug)]
pub struct CertificatePayloadTLS13<'a> {
    pub context: PayloadU8<'a>,
    pub entries: Vec<CertificateEntry<'a>>,
}

impl<'a> Codec<'a> for CertificatePayloadTLS13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        codec::encode_vec_u24(bytes, &self.entries);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificatePayloadTLS13<'a>> {
        Some(CertificatePayloadTLS13 {
            context: PayloadU8::read(r)?,
            entries: codec::read_vec_u24_limited::<CertificateEntry>(r, 0x10000)?,
        })
    }
}

impl<'a> CertificatePayloadTLS13<'a> {
    pub fn new(entries: Vec<CertificateEntry>) -> CertificatePayloadTLS13 {
        CertificatePayloadTLS13 {
            context: PayloadU8::empty(),
            entries,
        }
    }

    pub fn any_entry_has_duplicate_extension(&self) -> bool {
        for entry in &self.entries {
            if entry.has_duplicate_extension() {
                return true;
            }
        }

        false
    }

    pub fn any_entry_has_unknown_extension(&self) -> bool {
        for entry in &self.entries {
            if entry.has_unknown_extension() {
                return true;
            }
        }

        false
    }

    pub fn any_entry_has_extension(&self) -> bool {
        for entry in &self.entries {
            if !entry.exts.is_empty() {
                return true;
            }
        }

        false
    }

    pub fn get_end_entity_ocsp(&self) -> Vec<u8> {
        self.entries
            .first()
            .and_then(CertificateEntry::get_ocsp_response)
            .map(|bytes| bytes.to_vec())
            .unwrap_or_else(Vec::new)
    }

    pub fn get_end_entity_scts(&self) -> Option<SCTList<'static>> {
        self.entries.first().and_then(|entry| {
            CertificateEntry::get_scts(entry).map(|sct_list| {
                sct_list
                    .iter()
                    .map(|x| x.to_owned())
                    .collect()
            })
        })
    }

    pub fn convert(&self) -> CertificatePayload<'static> {
        let mut ret = Vec::new();
        for entry in &self.entries {
            ret.push(entry.cert.to_owned());
        }
        ret
    }
}

#[derive(Debug)]
pub enum KeyExchangeAlgorithm {
    BulkOnly,
    DH,
    DHE,
    RSA,
    ECDH,
    ECDHE,
}

// We don't support arbitrary curves.  It's a terrible
// idea and unnecessary attack surface.  Please,
// get a grip.
#[derive(Clone, Copy, Debug)]
pub struct ECParameters {
    pub curve_type: ECCurveType,
    pub named_group: NamedGroup,
}

impl<'a> Codec<'a> for ECParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<ECParameters> {
        let ct = ECCurveType::read(r)?;

        if ct != ECCurveType::NamedCurve {
            return None;
        }

        let grp = NamedGroup::read(r)?;

        Some(ECParameters {
            curve_type: ct,
            named_group: grp,
        })
    }
}

#[derive(Debug)]
pub struct DigitallySignedStruct<'a> {
    pub scheme: SignatureScheme,
    pub sig: PayloadU16<'a>,
}

impl<'a> DigitallySignedStruct<'a> {
    pub fn new(scheme: SignatureScheme, sig: Vec<u8>) -> DigitallySignedStruct<'static> {
        DigitallySignedStruct {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }

    pub fn to_owned(&self) -> DigitallySignedStruct<'static> {
        DigitallySignedStruct {
            scheme: self.scheme,
            sig: self.sig.to_owned(),
        }
    }
}

impl<'a> Codec<'a> for DigitallySignedStruct<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<DigitallySignedStruct<'a>> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;

        Some(DigitallySignedStruct { scheme, sig })
    }
}

#[derive(Debug)]
pub struct ClientECDHParams<'a> {
    pub public: PayloadU8<'a>,
}

impl<'a> Codec<'a> for ClientECDHParams<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<ClientECDHParams<'a>> {
        let pb = PayloadU8::read(r)?;
        Some(ClientECDHParams { public: pb })
    }
}

#[derive(Debug)]
pub struct ServerECDHParams<'a> {
    pub curve_params: ECParameters,
    pub public: PayloadU8<'a>,
}

impl<'a> ServerECDHParams<'a> {
    pub fn new(named_group: NamedGroup, pubkey: &[u8]) -> ServerECDHParams<'static> {
        ServerECDHParams {
            curve_params: ECParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group,
            },
            public: PayloadU8::new(pubkey.to_vec()),
        }
    }
}

impl<'a> Codec<'a> for ServerECDHParams<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_params.encode(bytes);
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<ServerECDHParams<'a>> {
        let cp = ECParameters::read(r)?;
        let pb = PayloadU8::read(r)?;

        Some(ServerECDHParams {
            curve_params: cp,
            public: pb,
        })
    }
}

#[derive(Debug)]
pub struct ECDHEServerKeyExchange<'a> {
    pub params: ServerECDHParams<'a>,
    pub dss: DigitallySignedStruct<'a>,
}

impl<'a> Codec<'a> for ECDHEServerKeyExchange<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<ECDHEServerKeyExchange<'a>> {
        let params = ServerECDHParams::read(r)?;
        let dss = DigitallySignedStruct::read(r)?;

        Some(ECDHEServerKeyExchange { params, dss })
    }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload<'a> {
    ECDHE(ECDHEServerKeyExchange<'a>),
    Unknown(Payload<'a>),
}

impl<'a> Codec<'a> for ServerKeyExchangePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServerKeyExchangePayload::ECDHE(ref x) => x.encode(bytes),
            ServerKeyExchangePayload::Unknown(ref x) => x.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'a>) -> Option<ServerKeyExchangePayload<'a>> {
        // read as Unknown, fully parse when we know the
        // KeyExchangeAlgorithm
        Some(ServerKeyExchangePayload::Unknown(Payload::read(r)))
    }
}

impl<'a> ServerKeyExchangePayload<'a> {
    pub fn unwrap_given_kxa(&self, kxa: &KeyExchangeAlgorithm) -> Option<ServerKeyExchangePayload> {
        if let ServerKeyExchangePayload::Unknown(ref unk) = *self {
            let mut rd = Reader::init(&unk.0);

            let result = match *kxa {
                KeyExchangeAlgorithm::ECDHE => {
                    ECDHEServerKeyExchange::read(&mut rd).map(ServerKeyExchangePayload::ECDHE)
                }
                _ => None,
            };

            if !rd.any_left() {
                return result;
            };
        }

        None
    }

    pub fn encode_params(&self, bytes: &mut Vec<u8>) {
        bytes.clear();

        if let ServerKeyExchangePayload::ECDHE(ref x) = *self {
            x.params.encode(bytes);
        }
    }

    pub fn get_sig(&self) -> Option<&DigitallySignedStruct<'a>> {
        match *self {
            ServerKeyExchangePayload::ECDHE(ref x) => Some(&x.dss),
            _ => None,
        }
    }
}

// -- EncryptedExtensions (TLS1.3 only) --
declare_u16_vec_lifetime!(EncryptedExtensions, ServerExtension);

pub trait HasServerExtensions {
    fn get_extensions(&self) -> &[ServerExtension];

    /// Returns true if there is more than one extension of a given
    /// type.
    fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

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

impl<'a> HasServerExtensions for EncryptedExtensions<'a> {
    fn get_extensions(&self) -> &[ServerExtension] {
        self
    }
}

// -- CertificateRequest and sundries --
declare_u8_vec!(ClientCertificateTypes, ClientCertificateType);
pub type DistinguishedName<'a> = PayloadU16<'a>;
pub type DistinguishedNames<'a> = VecU16OfPayloadU16<'a>;

#[derive(Debug)]
pub struct CertificateRequestPayload<'a> {
    pub certtypes: ClientCertificateTypes,
    pub sigschemes: SupportedSignatureSchemes,
    pub canames: DistinguishedNames<'a>,
}

impl<'a> Codec<'a> for CertificateRequestPayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.certtypes.encode(bytes);
        self.sigschemes.encode(bytes);
        self.canames.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateRequestPayload<'a>> {
        let certtypes = ClientCertificateTypes::read(r)?;
        let sigschemes = SupportedSignatureSchemes::read(r)?;
        let canames = DistinguishedNames::read(r)?;

        if sigschemes.is_empty() {
            warn!("meaningless CertificateRequest message");
            None
        } else {
            Some(CertificateRequestPayload {
                certtypes,
                sigschemes,
                canames,
            })
        }
    }
}

#[derive(Debug)]
pub enum CertReqExtension<'a> {
    SignatureAlgorithms(SupportedSignatureSchemes),
    AuthorityNames(DistinguishedNames<'a>),
    Unknown(UnknownExtension<'a>),
}

impl<'a> CertReqExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            CertReqExtension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            CertReqExtension::AuthorityNames(_) => ExtensionType::CertificateAuthorities,
            CertReqExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl<'a> Codec<'a> for CertReqExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            CertReqExtension::SignatureAlgorithms(ref r) => r.encode(&mut sub),
            CertReqExtension::AuthorityNames(ref r) => r.encode(&mut sub),
            CertReqExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertReqExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::SignatureAlgorithms => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                if schemes.is_empty() {
                    return None;
                }
                CertReqExtension::SignatureAlgorithms(schemes)
            }
            ExtensionType::CertificateAuthorities => {
                let cas = DistinguishedNames::read(&mut sub)?;
                CertReqExtension::AuthorityNames(cas)
            }
            _ => CertReqExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

declare_u16_vec_lifetime!(CertReqExtensions, CertReqExtension);

#[derive(Debug)]
pub struct CertificateRequestPayloadTLS13<'a> {
    pub context: PayloadU8<'a>,
    pub extensions: CertReqExtensions<'a>,
}

impl<'a> Codec<'a> for CertificateRequestPayloadTLS13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateRequestPayloadTLS13<'a>> {
        let context = PayloadU8::read(r)?;
        let extensions = CertReqExtensions::read(r)?;

        Some(CertificateRequestPayloadTLS13 {
            context,
            extensions,
        })
    }
}

impl<'a> CertificateRequestPayloadTLS13<'a> {
    pub fn find_extension(&self, ext: ExtensionType) -> Option<&CertReqExtension> {
        self.extensions
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureSchemes> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            CertReqExtension::SignatureAlgorithms(ref sa) => Some(sa),
            _ => None,
        }
    }

    pub fn get_authorities_extension(&self) -> Option<&DistinguishedNames> {
        let ext = self.find_extension(ExtensionType::CertificateAuthorities)?;
        match *ext {
            CertReqExtension::AuthorityNames(ref an) => Some(an),
            _ => None,
        }
    }
}

// -- NewSessionTicket --
#[derive(Debug)]
pub struct NewSessionTicketPayload<'a> {
    pub lifetime_hint: u32,
    pub ticket: PayloadU16<'a>,
}

impl<'a> NewSessionTicketPayload<'a> {
    pub fn new(lifetime_hint: u32, ticket: Vec<u8>) -> NewSessionTicketPayload<'static> {
        NewSessionTicketPayload {
            lifetime_hint,
            ticket: PayloadU16::new(ticket),
        }
    }
}

impl<'a> Codec<'a> for NewSessionTicketPayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<NewSessionTicketPayload<'a>> {
        let lifetime = u32::read(r)?;
        let ticket = PayloadU16::read(r)?;

        Some(NewSessionTicketPayload {
            lifetime_hint: lifetime,
            ticket,
        })
    }
}

// -- NewSessionTicket electric boogaloo --
#[derive(Debug)]
pub enum NewSessionTicketExtension<'a> {
    EarlyData(u32),
    Unknown(UnknownExtension<'a>),
}

impl<'a> NewSessionTicketExtension<'a> {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            NewSessionTicketExtension::EarlyData(_) => ExtensionType::EarlyData,
            NewSessionTicketExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl<'a> Codec<'a> for NewSessionTicketExtension<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            NewSessionTicketExtension::EarlyData(r) => r.encode(&mut sub),
            NewSessionTicketExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<NewSessionTicketExtension<'a>> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::EarlyData => NewSessionTicketExtension::EarlyData(u32::read(&mut sub)?),
            _ => NewSessionTicketExtension::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() { None } else { Some(ext) }
    }
}

declare_u16_vec_lifetime!(NewSessionTicketExtensions, NewSessionTicketExtension);

#[derive(Debug)]
pub struct NewSessionTicketPayloadTLS13<'a> {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: PayloadU8<'a>,
    pub ticket: PayloadU16<'a>,
    pub exts: NewSessionTicketExtensions<'a>,
}

impl<'a> NewSessionTicketPayloadTLS13<'a> {
    pub fn new(
        lifetime: u32,
        age_add: u32,
        nonce: Vec<u8>,
        ticket: Vec<u8>,
    ) -> NewSessionTicketPayloadTLS13<'static> {
        NewSessionTicketPayloadTLS13 {
            lifetime,
            age_add,
            nonce: PayloadU8::new(nonce),
            ticket: PayloadU16::new(ticket),
            exts: vec![],
        }
    }

    pub fn find_extension(&self, ext: ExtensionType) -> Option<&NewSessionTicketExtension> {
        self.exts
            .iter()
            .find(|x| x.get_type() == ext)
    }

    pub fn get_max_early_data_size(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionType::EarlyData)?;
        match *ext {
            NewSessionTicketExtension::EarlyData(ref sz) => Some(*sz),
            _ => None,
        }
    }
}

impl<'a> Codec<'a> for NewSessionTicketPayloadTLS13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<NewSessionTicketPayloadTLS13<'a>> {
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let nonce = PayloadU8::read(r)?;
        let ticket = PayloadU16::read(r)?;
        let exts = NewSessionTicketExtensions::read(r)?;

        Some(NewSessionTicketPayloadTLS13 {
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
    pub ocsp_response: PayloadU24<'a>,
}

impl<'a> Codec<'a> for CertificateStatus<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.ocsp_response.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Option<CertificateStatus<'a>> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => Some(CertificateStatus {
                ocsp_response: PayloadU24::read(r)?,
            }),
            _ => None,
        }
    }
}

impl<'a> CertificateStatus<'a> {
    pub fn new(ocsp: Vec<u8>) -> CertificateStatus<'static> {
        CertificateStatus {
            ocsp_response: PayloadU24::new(ocsp),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.0.into_owned()
    }
}

#[derive(Debug)]
pub enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload<'a>),
    ServerHello(ServerHelloPayload<'a>),
    HelloRetryRequest(HelloRetryRequest<'a>),
    Certificate(CertificatePayload<'a>),
    CertificateTLS13(CertificatePayloadTLS13<'a>),
    ServerKeyExchange(ServerKeyExchangePayload<'a>),
    CertificateRequest(CertificateRequestPayload<'a>),
    CertificateRequestTLS13(CertificateRequestPayloadTLS13<'a>),
    CertificateVerify(DigitallySignedStruct<'a>),
    ServerHelloDone,
    EarlyData,
    EndOfEarlyData,
    ClientKeyExchange(Payload<'a>),
    NewSessionTicket(NewSessionTicketPayload<'a>),
    NewSessionTicketTLS13(NewSessionTicketPayloadTLS13<'a>),
    EncryptedExtensions(EncryptedExtensions<'a>),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    MessageHash(Payload<'a>),
    Unknown(Payload<'a>),
}

impl<'a> HandshakePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            HandshakePayload::HelloRequest
            | HandshakePayload::ServerHelloDone
            | HandshakePayload::EarlyData
            | HandshakePayload::EndOfEarlyData => {}
            HandshakePayload::ClientHello(ref x) => x.encode(bytes),
            HandshakePayload::ServerHello(ref x) => x.encode(bytes),
            HandshakePayload::HelloRetryRequest(ref x) => x.encode(bytes),
            HandshakePayload::Certificate(ref x) => x.encode(bytes),
            HandshakePayload::CertificateTLS13(ref x) => x.encode(bytes),
            HandshakePayload::ServerKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::ClientKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::CertificateRequest(ref x) => x.encode(bytes),
            HandshakePayload::CertificateRequestTLS13(ref x) => x.encode(bytes),
            HandshakePayload::CertificateVerify(ref x) => x.encode(bytes),
            HandshakePayload::NewSessionTicket(ref x) => x.encode(bytes),
            HandshakePayload::NewSessionTicketTLS13(ref x) => x.encode(bytes),
            HandshakePayload::EncryptedExtensions(ref x) => x.encode(bytes),
            HandshakePayload::KeyUpdate(ref x) => x.encode(bytes),
            HandshakePayload::Finished(ref x) => x.encode(bytes),
            HandshakePayload::CertificateStatus(ref x) => x.encode(bytes),
            HandshakePayload::MessageHash(ref x) => x.encode(bytes),
            HandshakePayload::Unknown(ref x) => x.encode(bytes),
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
        // encode payload to learn length
        let mut sub: Vec<u8> = Vec::new();
        self.payload.encode(&mut sub);

        // output type, length, and encoded payload
        match self.typ {
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);
        codec::u24(sub.len() as u32).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader<'a>) -> Option<HandshakeMessagePayload<'a>> {
        HandshakeMessagePayload::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

impl<'a> HandshakeMessagePayload<'a> {
    pub fn read_version(
        r: &mut Reader<'a>,
        vers: ProtocolVersion,
    ) -> Option<HandshakeMessagePayload<'a>> {
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
                let p = CertificatePayloadTLS13::read(&mut sub)?;
                HandshakePayload::CertificateTLS13(p)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(CertificatePayload::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                let p = ServerKeyExchangePayload::read(&mut sub)?;
                HandshakePayload::ServerKeyExchange(p)
            }
            HandshakeType::ServerHelloDone => {
                if sub.any_left() {
                    return None;
                }
                HandshakePayload::ServerHelloDone
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(Payload::read(&mut sub))
            }
            HandshakeType::CertificateRequest if vers == ProtocolVersion::TLSv1_3 => {
                let p = CertificateRequestPayloadTLS13::read(&mut sub)?;
                HandshakePayload::CertificateRequestTLS13(p)
            }
            HandshakeType::CertificateRequest => {
                let p = CertificateRequestPayload::read(&mut sub)?;
                HandshakePayload::CertificateRequest(p)
            }
            HandshakeType::CertificateVerify => {
                HandshakePayload::CertificateVerify(DigitallySignedStruct::read(&mut sub)?)
            }
            HandshakeType::NewSessionTicket if vers == ProtocolVersion::TLSv1_3 => {
                let p = NewSessionTicketPayloadTLS13::read(&mut sub)?;
                HandshakePayload::NewSessionTicketTLS13(p)
            }
            HandshakeType::NewSessionTicket => {
                let p = NewSessionTicketPayload::read(&mut sub)?;
                HandshakePayload::NewSessionTicket(p)
            }
            HandshakeType::EncryptedExtensions => {
                HandshakePayload::EncryptedExtensions(EncryptedExtensions::read(&mut sub)?)
            }
            HandshakeType::KeyUpdate => {
                HandshakePayload::KeyUpdate(KeyUpdateRequest::read(&mut sub)?)
            }
            HandshakeType::Finished => HandshakePayload::Finished(Payload::read(&mut sub)),
            HandshakeType::CertificateStatus => {
                HandshakePayload::CertificateStatus(CertificateStatus::read(&mut sub)?)
            }
            HandshakeType::MessageHash => {
                // does not appear on the wire
                return None;
            }
            HandshakeType::HelloRetryRequest => {
                // not legal on wire
                return None;
            }
            _ => HandshakePayload::Unknown(Payload::read(&mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(HandshakeMessagePayload { typ, payload })
        }
    }

    pub fn build_key_update_notify() -> HandshakeMessagePayload<'static> {
        HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        }
    }

    pub fn get_encoding_for_binder_signing(&self) -> Vec<u8> {
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

    pub fn build_handshake_hash(hash: &[u8]) -> HandshakeMessagePayload {
        HandshakeMessagePayload {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.to_vec())),
        }
    }
}
