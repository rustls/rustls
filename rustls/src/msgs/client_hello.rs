use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use pki_types::DnsName;

use super::codec::{
    Codec, LengthPrefixedBuffer, ListLength, MaybeEmpty, NonEmpty, Reader, SizedPayload,
    TlsListElement, TlsListIter,
};
use super::enums::{CertificateStatusType, Compression, ExtensionType, PskKeyExchangeMode};
use super::handshake::{
    DuplicateExtensionChecker, Encoding, KeyShareEntry, Random, SessionId, SupportedEcPointFormats,
    SupportedProtocolVersions, has_duplicates,
};
use crate::crypto::cipher::Payload;
use crate::crypto::hpke::HpkeSymmetricCipherSuite;
use crate::crypto::kx::NamedGroup;
use crate::crypto::{CipherSuite, SignatureScheme};
use crate::enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CertificateType, EchClientHelloType,
    ProtocolVersion,
};
use crate::error::InvalidMessage;
use crate::log::warn;
use crate::msgs::enums::ServerNameType;
use crate::verify::DistinguishedName;

#[derive(Clone, Debug)]
pub(crate) struct ClientHelloPayload {
    pub(crate) client_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) compression_methods: Vec<Compression>,
    pub(crate) extensions: Box<ClientExtensions<'static>>,
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
            Encoding::EchInnerHello { to_compress } if !to_compress.is_empty() => to_compress,
            _ => {
                self.extensions.encode(bytes);
                return;
            }
        };

        let mut compressed = self.extensions.clone();

        // First, eliminate the full-fat versions of the extensions
        for e in &to_compress {
            compressed.clear(*e);
        }

        // Replace with the marker noting which extensions were elided.
        compressed.encrypted_client_hello_outer = Some(to_compress);

        // And encode as normal.
        compressed.encode(bytes);
    }

    pub(crate) fn has_keyshare_extension_with_duplicates(&self) -> bool {
        self.key_shares
            .as_ref()
            .map(|entries| {
                has_duplicates::<_, _, u16>(
                    entries
                        .iter()
                        .map(|kse| u16::from(kse.group)),
                )
            })
            .unwrap_or_default()
    }

    pub(crate) fn has_certificate_compression_extension_with_duplicates(&self) -> bool {
        if let Some(algs) = &self.certificate_compression_algorithms {
            has_duplicates::<_, _, u16>(algs.iter().copied())
        } else {
            false
        }
    }
}

impl Codec<'_> for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let ret = Self {
            client_version: ProtocolVersion::read(r)?,
            random: Random::read(r)?,
            session_id: SessionId::read(r)?,
            cipher_suites: Vec::read(r)?,
            compression_methods: Vec::read(r)?,
            extensions: Box::new(ClientExtensions::read(r)?.into_owned()),
        };

        match r.any_left() {
            true => Err(InvalidMessage::TrailingData("ClientHelloPayload")),
            false => Ok(ret),
        }
    }
}

impl Deref for ClientHelloPayload {
    type Target = ClientExtensions<'static>;
    fn deref(&self) -> &Self::Target {
        &self.extensions
    }
}

impl DerefMut for ClientHelloPayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.extensions
    }
}

extension_struct! {
    /// A representation of extensions present in a `ClientHello` message
    ///
    /// All extensions are optional (by definition) so are represented with `Option<T>`.
    ///
    /// Some extensions have an empty value and are represented with Option<()>.
    ///
    /// Unknown extensions are dropped during parsing.
    pub(crate) struct ClientExtensions<'a> {
        /// Requested server name indication (RFC6066)
        ExtensionType::ServerName =>
            pub(crate) server_name: Option<ServerNamePayload<'a>>,

        /// Certificate status is requested (RFC6066)
        ExtensionType::StatusRequest =>
            pub(crate) certificate_status_request: Option<CertificateStatusRequest>,

        /// Supported groups (RFC4492/RFC8446)
        ExtensionType::EllipticCurves =>
            pub(crate) named_groups: Option<Vec<NamedGroup>>,

        /// Supported EC point formats (RFC4492)
        ExtensionType::ECPointFormats =>
            pub(crate) ec_point_formats: Option<SupportedEcPointFormats>,

        /// Supported signature schemes (RFC5246/RFC8446)
        ExtensionType::SignatureAlgorithms =>
            pub(crate) signature_schemes: Option<Vec<SignatureScheme>>,

        /// Offered ALPN protocols (RFC6066)
        ExtensionType::ALProtocolNegotiation =>
            pub(crate) protocols: Option<Vec<ApplicationProtocol<'a>>>,

        /// Available client certificate types (RFC7250)
        ExtensionType::ClientCertificateType =>
            pub(crate) client_certificate_types: Option<Vec<CertificateType>>,

        /// Acceptable server certificate types (RFC7250)
        ExtensionType::ServerCertificateType =>
            pub(crate) server_certificate_types: Option<Vec<CertificateType>>,

        /// Extended master secret is requested (RFC7627)
        ExtensionType::ExtendedMasterSecret =>
            pub(crate) extended_master_secret_request: Option<()>,

        /// Offered certificate compression methods (RFC8879)
        ExtensionType::CompressCertificate =>
            pub(crate) certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,

        /// Session ticket offer or request (RFC5077/RFC8446)
        ExtensionType::SessionTicket =>
            pub(crate) session_ticket: Option<ClientSessionTicket>,

        /// Offered preshared keys (RFC8446)
        ExtensionType::PreSharedKey =>
            pub(crate) preshared_key_offer: Option<PresharedKeyOffer>,

        /// Early data is requested (RFC8446)
        ExtensionType::EarlyData =>
            pub(crate) early_data_request: Option<()>,

        /// Supported TLS versions (RFC8446)
        ExtensionType::SupportedVersions =>
            pub(crate) supported_versions: Option<SupportedProtocolVersions>,

        /// Stateless HelloRetryRequest cookie (RFC8446)
        ExtensionType::Cookie =>
            pub(crate) cookie: Option<SizedPayload<'a, u16, NonEmpty>>,

        /// Offered preshared key modes (RFC8446)
        ExtensionType::PSKKeyExchangeModes =>
            pub(crate) preshared_key_modes: Option<PskKeyExchangeModes>,

        /// Certificate authority names (RFC8446)
        ExtensionType::CertificateAuthorities =>
            pub(crate) certificate_authority_names: Option<Vec<DistinguishedName>>,

        /// Offered key exchange shares (RFC8446)
        ExtensionType::KeyShare =>
            pub(crate) key_shares: Option<Vec<KeyShareEntry>>,

        /// QUIC transport parameters (RFC9001)
        ExtensionType::TransportParameters =>
            pub(crate) transport_parameters: Option<Payload<'a>>,

        /// Secure renegotiation (RFC5746)
        ExtensionType::RenegotiationInfo =>
            pub(crate) renegotiation_info: Option<SizedPayload<'a, u8>>,

        /// Encrypted inner client hello (draft-ietf-tls-esni)
        ExtensionType::EncryptedClientHello =>
            pub(crate) encrypted_client_hello: Option<EncryptedClientHello>,

        /// Encrypted client hello outer extensions (draft-ietf-tls-esni)
        ExtensionType::EncryptedClientHelloOuterExtensions =>
            pub(crate) encrypted_client_hello_outer: Option<Vec<ExtensionType>>,
    } + {
        /// Order randomization seed.
        pub(crate) order_seed: u16,

        /// Extensions that must appear contiguously.
        pub(crate) contiguous_extensions: Vec<ExtensionType>,
    }
}

impl ClientExtensions<'_> {
    pub(crate) fn into_owned(self) -> ClientExtensions<'static> {
        let Self {
            server_name,
            certificate_status_request,
            named_groups,
            ec_point_formats,
            signature_schemes,
            protocols,
            client_certificate_types,
            server_certificate_types,
            extended_master_secret_request,
            certificate_compression_algorithms,
            session_ticket,
            preshared_key_offer,
            early_data_request,
            supported_versions,
            cookie,
            preshared_key_modes,
            certificate_authority_names,
            key_shares,
            transport_parameters,
            renegotiation_info,
            encrypted_client_hello,
            encrypted_client_hello_outer,
            order_seed,
            contiguous_extensions,
        } = self;
        ClientExtensions {
            server_name: server_name.map(|x| x.into_owned()),
            certificate_status_request,
            named_groups,
            ec_point_formats,
            signature_schemes,
            protocols: protocols.map(|ps| {
                ps.into_iter()
                    .map(|p| p.to_owned())
                    .collect::<Vec<_>>()
            }),
            client_certificate_types,
            server_certificate_types,
            extended_master_secret_request,
            certificate_compression_algorithms,
            session_ticket,
            preshared_key_offer,
            early_data_request,
            supported_versions,
            cookie: cookie.map(|x| x.into_owned()),
            preshared_key_modes,
            certificate_authority_names,
            key_shares,
            transport_parameters: transport_parameters.map(|x| x.into_owned()),
            renegotiation_info: renegotiation_info.map(|x| x.into_owned()),
            encrypted_client_hello,
            encrypted_client_hello_outer,
            order_seed,
            contiguous_extensions,
        }
    }

    pub(crate) fn used_extensions_in_encoding_order(&self) -> Vec<ExtensionType> {
        let mut exts = self.order_insensitive_extensions_in_random_order();
        exts.extend(&self.contiguous_extensions);

        if self
            .encrypted_client_hello_outer
            .is_some()
        {
            exts.push(ExtensionType::EncryptedClientHelloOuterExtensions);
        }
        if self.encrypted_client_hello.is_some() {
            exts.push(ExtensionType::EncryptedClientHello);
        }
        if self.preshared_key_offer.is_some() {
            exts.push(ExtensionType::PreSharedKey);
        }
        exts
    }

    /// Returns extensions which don't need a specific order, in randomized order.
    ///
    /// Extensions are encoded in three portions:
    ///
    /// - First, extensions not otherwise dealt with by other cases.
    ///   These are encoded in random order, controlled by `self.order_seed`,
    ///   and this is the set of extensions returned by this function.
    ///
    /// - Second, extensions named in `self.contiguous_extensions`, in the order
    ///   given by that field.
    ///
    /// - Lastly, any ECH and PSK extensions (in that order).  These
    ///   are required to be last by the standard.
    fn order_insensitive_extensions_in_random_order(&self) -> Vec<ExtensionType> {
        let mut order = self.collect_used();

        // Remove extensions which have specific order requirements.
        order.retain(|ext| {
            !(matches!(
                ext,
                ExtensionType::PreSharedKey
                    | ExtensionType::EncryptedClientHello
                    | ExtensionType::EncryptedClientHelloOuterExtensions
            ) || self.contiguous_extensions.contains(ext))
        });

        order.sort_by_cached_key(|new_ext| {
            let seed = ((self.order_seed as u32) << 16) | (u16::from(*new_ext) as u32);
            low_quality_integer_hash(seed)
        });

        order
    }
}

impl<'a> Codec<'a> for ClientExtensions<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let order = self.used_extensions_in_encoding_order();

        if order.is_empty() {
            return;
        }

        let body = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        for item in order {
            self.encode_one(item, body.buf);
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();

        // extensions length can be absent if no extensions
        if !r.any_left() {
            return Ok(out);
        }

        let mut checker = DuplicateExtensionChecker::new();

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            let typ = out.read_one(&mut sub, |unknown| checker.check(unknown))?;

            // PreSharedKey offer must come last
            if typ == ExtensionType::PreSharedKey && sub.any_left() {
                return Err(InvalidMessage::PreSharedKeyIsNotFinalExtension);
            }
        }

        Ok(out)
    }
}

/// Representation of the `ECHClientHello` client extension specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub(crate) enum EncryptedClientHello {
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
pub(crate) struct EncryptedClientHelloOuter {
    /// The cipher suite used to encrypt ClientHelloInner. Must match a value from
    /// ECHConfigContents.cipher_suites list.
    pub cipher_suite: HpkeSymmetricCipherSuite,
    /// The ECHConfigContents.key_config.config_id for the chosen ECHConfig.
    pub config_id: u8,
    /// The HPKE encapsulated key, used by servers to decrypt the corresponding payload field.
    /// This field is empty in a ClientHelloOuter sent in response to a HelloRetryRequest.
    pub enc: SizedPayload<'static, u16, MaybeEmpty>,
    /// The serialized and encrypted ClientHelloInner structure, encrypted using HPKE.
    pub payload: SizedPayload<'static, u16, NonEmpty>,
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
            enc: SizedPayload::read(r)?.into_owned(),
            payload: SizedPayload::read(r)?.into_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ServerNamePayload<'a> {
    /// A successfully decoded value:
    SingleDnsName(DnsName<'a>),

    /// A DNS name which was actually an IP address
    IpAddress,

    /// A successfully decoded, but syntactically-invalid value.
    Invalid,
}

impl ServerNamePayload<'_> {
    pub(super) fn into_owned(self) -> ServerNamePayload<'static> {
        match self {
            Self::SingleDnsName(d) => ServerNamePayload::SingleDnsName(d.to_owned()),
            Self::IpAddress => ServerNamePayload::IpAddress,
            Self::Invalid => ServerNamePayload::Invalid,
        }
    }

    /// RFC6066: `ServerName server_name_list<1..2^16-1>`
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("ServerNames"),
    };

    /// Get the `DnsName` out of this `ServerNamePayload` if it contains one.
    /// The returned `DnsName` will be normalized (converted to lowercase).
    pub(crate) fn to_dns_name_normalized(&self) -> Option<DnsName<'static>> {
        match self {
            Self::SingleDnsName(dns_name) => Some(dns_name.to_lowercase_owned()),
            Self::IpAddress => None,
            Self::Invalid => None,
        }
    }
}

/// Simplified encoding/decoding for a `ServerName` extension payload to/from `DnsName`
///
/// This is possible because:
///
/// - the spec (RFC6066) disallows multiple names for a given name type
/// - name types other than ServerNameType::HostName are not defined, and they and
///   any data that follows them cannot be skipped over.
impl<'a> Codec<'a> for ServerNamePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let server_name_list = LengthPrefixedBuffer::new(Self::SIZE_LEN, bytes);

        let ServerNamePayload::SingleDnsName(dns_name) = self else {
            return;
        };

        ServerNameType::HostName.encode(server_name_list.buf);
        let name_slice = dns_name.as_ref().as_bytes();
        (name_slice.len() as u16).encode(server_name_list.buf);
        server_name_list
            .buf
            .extend_from_slice(name_slice);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut found = None;

        let len = Self::SIZE_LEN.read(r)?;
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            let typ = ServerNameType::read(&mut sub)?;

            let payload = match typ {
                ServerNameType::HostName => HostNamePayload::read(&mut sub)?,
                _ => {
                    // Consume remainder of extension bytes.  Since the length of the item
                    // is an unknown encoding, we cannot continue.
                    sub.rest();
                    break;
                }
            };

            // "The ServerNameList MUST NOT contain more than one name of
            // the same name_type." - RFC6066
            if found.is_some() {
                warn!("Illegal SNI extension: duplicate host_name received");
                return Err(InvalidMessage::InvalidServerName);
            }

            found = match payload {
                HostNamePayload::HostName(dns_name) => {
                    Some(Self::SingleDnsName(dns_name.to_owned()))
                }

                HostNamePayload::IpAddress(_invalid) => {
                    warn!("Illegal SNI extension: IP address presented as hostname ({_invalid:?})");
                    Some(Self::IpAddress)
                }

                HostNamePayload::Invalid(_invalid) => {
                    warn!(
                        "Illegal SNI hostname received {:?}",
                        String::from_utf8_lossy(_invalid.bytes())
                    );
                    Some(Self::Invalid)
                }
            };
        }

        Ok(found.unwrap_or(Self::Invalid))
    }
}

impl<'a> From<&DnsName<'a>> for ServerNamePayload<'static> {
    fn from(value: &DnsName<'a>) -> Self {
        Self::SingleDnsName(trim_hostname_trailing_dot_for_sni(value))
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

#[derive(Clone, Debug)]
pub(crate) enum HostNamePayload {
    HostName(DnsName<'static>),
    IpAddress(SizedPayload<'static, u16, NonEmpty>),
    Invalid(SizedPayload<'static, u16, NonEmpty>),
}

impl HostNamePayload {
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        use pki_types::ServerName;
        let raw = SizedPayload::<u16, NonEmpty>::read(r)?;

        match ServerName::try_from(raw.bytes()) {
            Ok(ServerName::DnsName(d)) => Ok(Self::HostName(d.to_owned())),
            Ok(ServerName::IpAddress(_)) => Ok(Self::IpAddress(raw.into_owned())),
            Ok(_) | Err(_) => Ok(Self::Invalid(raw.into_owned())),
        }
    }
}

// --- RFC6066 certificate status request ---

#[derive(Clone, Debug)]
pub(crate) enum CertificateStatusRequest {
    Ocsp(OcspCertificateStatusRequest),
    Unknown((CertificateStatusType, Payload<'static>)),
}

impl Codec<'_> for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ocsp(r) => r.encode(bytes),
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
            extensions: SizedPayload::from(Payload::new(Vec::new())),
        };
        Self::Ocsp(ocsp)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OcspCertificateStatusRequest {
    pub(crate) responder_ids: Vec<ResponderId>,
    pub(crate) extensions: SizedPayload<'static, u16, MaybeEmpty>,
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
            extensions: SizedPayload::read(r)?.into_owned(),
        })
    }
}

wrapped_payload!(pub(crate) struct ResponderId, SizedPayload<u16, MaybeEmpty>,);

/// RFC6066: `ResponderID responder_id_list<0..2^16-1>;`
impl TlsListElement for ResponderId {
    const SIZE_LEN: ListLength = ListLength::U16;
}

// --- TLS 1.3 PresharedKey offers ---

#[derive(Clone, Debug)]
pub(crate) struct PresharedKeyOffer {
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

#[derive(Clone, Debug)]
pub(crate) struct PresharedKeyIdentity {
    /// RFC8446: `opaque identity<1..2^16-1>;`
    pub(crate) identity: SizedPayload<'static, u16, NonEmpty>,
    pub(crate) obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity {
    pub(crate) fn new(id: Vec<u8>, age: u32) -> Self {
        Self {
            identity: SizedPayload::from(Payload::new(id)),
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
            identity: SizedPayload::read(r)?.into_owned(),
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

/// RFC8446: `PskIdentity identities<7..2^16-1>;`
impl TlsListElement for PresharedKeyIdentity {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("PskIdentities"),
    };
}

wrapped_payload!(
    /// RFC8446: `opaque PskBinderEntry<32..255>;`
    pub(crate) struct PresharedKeyBinder, SizedPayload<u8, NonEmpty>,
);

/// RFC8446: `PskBinderEntry binders<33..2^16-1>;`
impl TlsListElement for PresharedKeyBinder {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("PskBinders"),
    };
}

/// RFC8446: `PskKeyExchangeMode ke_modes<1..255>;`
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PskKeyExchangeModes {
    pub(crate) psk_dhe: bool,
    pub(crate) psk: bool,
}

impl Codec<'_> for PskKeyExchangeModes {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = LengthPrefixedBuffer::new(PskKeyExchangeMode::SIZE_LEN, bytes);
        if self.psk_dhe {
            PskKeyExchangeMode::PSK_DHE_KE.encode(inner.buf);
        }
        if self.psk {
            PskKeyExchangeMode::PSK_KE.encode(inner.buf);
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut psk_dhe = false;
        let mut psk = false;

        for ke in TlsListIter::<PskKeyExchangeMode>::new(reader)? {
            match ke? {
                PskKeyExchangeMode::PSK_DHE_KE => psk_dhe = true,
                PskKeyExchangeMode::PSK_KE => psk = true,
                _ => continue,
            };
        }

        Ok(Self { psk_dhe, psk })
    }
}

impl TlsListElement for PskKeyExchangeMode {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("PskKeyExchangeModes"),
    };
}

#[derive(Clone, Debug)]
pub(crate) enum ClientSessionTicket {
    Request,
    Offer(Payload<'static>),
}

impl<'a> Codec<'a> for ClientSessionTicket {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Request => (),
            Self::Offer(p) => p.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(match r.left() {
            0 => Self::Request,
            _ => Self::Offer(Payload::read(r).into_owned()),
        })
    }
}

fn low_quality_integer_hash(mut x: u32) -> u32 {
    x = x
        .wrapping_add(0x7ed55d16)
        .wrapping_add(x << 12);
    x = (x ^ 0xc761c23c) ^ (x >> 19);
    x = x
        .wrapping_add(0x165667b1)
        .wrapping_add(x << 5);
    x = x.wrapping_add(0xd3a2646c) ^ (x << 9);
    x = x
        .wrapping_add(0xfd7046c5)
        .wrapping_add(x << 3);
    x = (x ^ 0xb55a4f09) ^ (x >> 16);
    x
}
