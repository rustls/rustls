use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use core::{fmt, iter};

use pki_types::{CertificateDer, DnsName};

use super::client_hello::ClientHelloPayload;
use crate::crypto::cipher::Payload;
use crate::crypto::hpke::{HpkeKem, HpkeSymmetricCipherSuite};
use crate::crypto::kx::ffdhe::FfdheGroup;
use crate::crypto::kx::{ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup};
use crate::crypto::{
    CipherSuite, GetRandomFailed, SecureRandom, SelectedCredential, SignatureScheme,
};
use crate::enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CertificateType, HandshakeType,
    ProtocolVersion,
};
use crate::error::InvalidMessage;
use crate::log::warn;
use crate::msgs::base::{MaybeEmpty, NonEmpty, SizedPayload};
use crate::msgs::codec::{
    CERTIFICATE_MAX_SIZE_LIMIT, Codec, LengthPrefixedBuffer, ListLength, Reader, TlsListElement,
    TlsListIter, U24,
};
use crate::msgs::enums::{
    CertificateStatusType, ClientCertificateType, Compression, ECCurveType, ECPointFormat,
    EchVersion, ExtensionType, KeyUpdateRequest,
};
use crate::sync::Arc;
use crate::verify::{DigitallySignedStruct, DistinguishedName};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Random(pub(crate) [u8; 32]);

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
        let Some(bytes) = r.take(32) else {
            return Err(InvalidMessage::MissingData("Random"));
        };

        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);
        Ok(Self(opaque))
    }
}

impl Random {
    pub(crate) fn new(secure_random: &dyn SecureRandom) -> Result<Self, GetRandomFailed> {
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
pub(crate) struct SessionId {
    data: [u8; 32],
    len: usize,
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

        let Some(bytes) = r.take(len) else {
            return Err(InvalidMessage::MissingData("SessionID"));
        };

        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);
        Ok(Self { data: out, len })
    }
}

impl SessionId {
    pub(crate) fn random(secure_random: &dyn SecureRandom) -> Result<Self, GetRandomFailed> {
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
pub(crate) struct UnknownExtension {
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct SupportedEcPointFormats {
    pub(crate) uncompressed: bool,
}

impl Codec<'_> for SupportedEcPointFormats {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = LengthPrefixedBuffer::new(ECPointFormat::SIZE_LEN, bytes);

        if self.uncompressed {
            ECPointFormat::Uncompressed.encode(inner.buf);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut uncompressed = false;

        for pf in TlsListIter::<ECPointFormat>::new(r)? {
            if let ECPointFormat::Uncompressed = pf? {
                uncompressed = true;
            }
        }

        Ok(Self { uncompressed })
    }
}

impl Default for SupportedEcPointFormats {
    fn default() -> Self {
        Self { uncompressed: true }
    }
}

/// RFC8422: `ECPointFormat ec_point_format_list<1..2^8-1>`
impl TlsListElement for ECPointFormat {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("ECPointFormats"),
    };
}

/// RFC8422: `NamedCurve named_curve_list<2..2^16-1>`
impl TlsListElement for NamedGroup {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("NamedGroups"),
    };
}

/// RFC8446: `SignatureScheme supported_signature_algorithms<2..2^16-2>;`
impl TlsListElement for SignatureScheme {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::NoSignatureSchemes,
    };
}

/// RFC7301 encodes a single protocol name as `Vec<ProtocolName>`
#[derive(Clone, Debug)]
pub(crate) struct SingleProtocolName(ApplicationProtocol<'static>);

impl SingleProtocolName {
    pub(crate) fn new(single: ApplicationProtocol<'static>) -> Self {
        Self(single)
    }

    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("ProtocolNames"),
    };
}

impl Codec<'_> for SingleProtocolName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let body = LengthPrefixedBuffer::new(Self::SIZE_LEN, bytes);
        self.0.encode(body.buf);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = Self::SIZE_LEN.read(reader)?;
        let mut sub = reader.sub(len)?;

        let item = ApplicationProtocol::read(&mut sub)?;

        if sub.any_left() {
            Err(InvalidMessage::TrailingData("SingleProtocolName"))
        } else {
            Ok(Self(item.to_owned()))
        }
    }
}

impl AsRef<ApplicationProtocol<'static>> for SingleProtocolName {
    fn as_ref(&self) -> &ApplicationProtocol<'static> {
        &self.0
    }
}

// --- TLS 1.3 Key shares ---
#[derive(Clone, Debug)]
pub(crate) struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    /// RFC8446: `opaque key_exchange<1..2^16-1>;`
    pub(crate) payload: SizedPayload<'static, u16, NonEmpty>,
}

impl KeyShareEntry {
    pub(crate) fn new(group: NamedGroup, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            group,
            payload: SizedPayload::from(Payload::new(payload.into())),
        }
    }
}

impl Codec<'_> for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            group: NamedGroup::read(r)?,
            payload: SizedPayload::read(r)?.into_owned(),
        })
    }
}

// ---

/// RFC8446: `KeyShareEntry client_shares<0..2^16-1>;`
impl TlsListElement for KeyShareEntry {
    const SIZE_LEN: ListLength = ListLength::U16;
}

/// The body of the `SupportedVersions` extension when it appears in a
/// `ClientHello`
///
/// This is documented as a preference-order vector, but we (as a server)
/// ignore the preference of the client.
///
/// RFC8446: `ProtocolVersion versions<2..254>;`
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SupportedProtocolVersions {
    pub(crate) tls13: bool,
    pub(crate) tls12: bool,
}

impl SupportedProtocolVersions {
    /// Return true if `filter` returns true for any enabled version.
    pub(crate) fn any(&self, filter: impl Fn(ProtocolVersion) -> bool) -> bool {
        if self.tls13 && filter(ProtocolVersion::TLSv1_3) {
            return true;
        }
        if self.tls12 && filter(ProtocolVersion::TLSv1_2) {
            return true;
        }
        false
    }

    const LIST_LENGTH: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("ProtocolVersions"),
    };
}

impl Codec<'_> for SupportedProtocolVersions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let inner = LengthPrefixedBuffer::new(Self::LIST_LENGTH, bytes);
        if self.tls13 {
            ProtocolVersion::TLSv1_3.encode(inner.buf);
        }
        if self.tls12 {
            ProtocolVersion::TLSv1_2.encode(inner.buf);
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut tls12 = false;
        let mut tls13 = false;

        for pv in TlsListIter::<ProtocolVersion>::new(reader)? {
            match pv? {
                ProtocolVersion::TLSv1_3 => tls13 = true,
                ProtocolVersion::TLSv1_2 => tls12 = true,
                _ => continue,
            };
        }

        Ok(Self { tls13, tls12 })
    }
}

impl TlsListElement for ProtocolVersion {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("ProtocolVersions"),
    };
}

/// RFC7250: `CertificateType client_certificate_types<1..2^8-1>;`
///
/// Ditto `CertificateType server_certificate_types<1..2^8-1>;`
impl TlsListElement for CertificateType {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("CertificateTypes"),
    };
}

/// RFC8879: `CertificateCompressionAlgorithm algorithms<2..2^8-2>;`
impl TlsListElement for CertificateCompressionAlgorithm {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("CertificateCompressionAlgorithms"),
    };
}

/// A precursor to `ClientExtensions`, allowing customisation.
///
/// This is smaller than `ClientExtensions`, as it only contains the extensions
/// we need to vary between different protocols (eg, TCP-TLS versus QUIC).
#[derive(Clone, Default)]
pub(crate) struct ClientExtensionsInput {
    /// QUIC transport parameters
    pub(crate) transport_parameters: Option<TransportParameters>,

    /// ALPN protocols
    pub(crate) protocols: Option<Vec<ApplicationProtocol<'static>>>,
}

impl ClientExtensionsInput {
    pub(crate) fn from_alpn(alpn_protocols: Vec<ApplicationProtocol<'static>>) -> Self {
        let protocols = match alpn_protocols.is_empty() {
            true => None,
            false => Some(alpn_protocols),
        };

        Self {
            transport_parameters: None,
            protocols,
        }
    }
}

#[derive(Clone)]
pub(crate) enum TransportParameters {
    /// QUIC transport parameters (RFC9001)
    #[cfg_attr(not(feature = "std"), expect(dead_code))]
    Quic(Payload<'static>),
}

#[derive(Default)]
pub(crate) struct ServerExtensionsInput {
    /// QUIC transport parameters
    pub(crate) transport_parameters: Option<TransportParameters>,
}

extension_struct! {
    pub(crate) struct ServerExtensions<'a> {
        /// Supported EC point formats (RFC4492)
        ExtensionType::ECPointFormats =>
            pub(crate) ec_point_formats: Option<SupportedEcPointFormats>,

        /// Server name indication acknowledgement (RFC6066)
        ExtensionType::ServerName =>
            pub(crate) server_name_ack: Option<()>,

        /// Session ticket acknowledgement (RFC5077)
        ExtensionType::SessionTicket =>
            pub(crate) session_ticket_ack: Option<()>,

        ExtensionType::RenegotiationInfo =>
            pub(crate) renegotiation_info: Option<SizedPayload<'a, u8>>,

        /// Selected ALPN protocol (RFC7301)
        ExtensionType::ALProtocolNegotiation =>
            pub(crate) selected_protocol: Option<SingleProtocolName>,

        /// Key exchange server share (RFC8446)
        ExtensionType::KeyShare =>
            pub(crate) key_share: Option<KeyShareEntry>,

        /// Selected preshared key index (RFC8446)
        ExtensionType::PreSharedKey =>
            pub(crate) preshared_key: Option<u16>,

        /// Required client certificate type (RFC7250)
        ExtensionType::ClientCertificateType =>
            pub(crate) client_certificate_type: Option<CertificateType>,

        /// Selected server certificate type (RFC7250)
        ExtensionType::ServerCertificateType =>
            pub(crate) server_certificate_type: Option<CertificateType>,

        /// Extended master secret is in use (RFC7627)
        ExtensionType::ExtendedMasterSecret =>
            pub(crate) extended_master_secret_ack: Option<()>,

        /// Certificate status acknowledgement (RFC6066)
        ExtensionType::StatusRequest =>
            pub(crate) certificate_status_request_ack: Option<()>,

        /// Selected TLS version (RFC8446)
        ExtensionType::SupportedVersions =>
            pub(crate) selected_version: Option<ProtocolVersion>,

        /// QUIC transport parameters (RFC9001)
        ExtensionType::TransportParameters =>
            pub(crate) transport_parameters: Option<Payload<'a>>,

        /// Early data is accepted (RFC8446)
        ExtensionType::EarlyData =>
            pub(crate) early_data_ack: Option<()>,

        /// Encrypted inner client hello response (draft-ietf-tls-esni)
        ExtensionType::EncryptedClientHello =>
            pub(crate) encrypted_client_hello_ack: Option<ServerEncryptedClientHello>,
    } + {
        pub(crate) unknown_extensions: BTreeSet<u16>,
    }
}

impl ServerExtensions<'_> {
    fn into_owned(self) -> ServerExtensions<'static> {
        let Self {
            ec_point_formats,
            server_name_ack,
            session_ticket_ack,
            renegotiation_info,
            selected_protocol,
            key_share,
            preshared_key,
            client_certificate_type,
            server_certificate_type,
            extended_master_secret_ack,
            certificate_status_request_ack,
            selected_version,
            transport_parameters,
            early_data_ack,
            encrypted_client_hello_ack,
            unknown_extensions,
        } = self;
        ServerExtensions {
            ec_point_formats,
            server_name_ack,
            session_ticket_ack,
            renegotiation_info: renegotiation_info.map(|x| x.into_owned()),
            selected_protocol,
            key_share,
            preshared_key,
            client_certificate_type,
            server_certificate_type,
            extended_master_secret_ack,
            certificate_status_request_ack,
            selected_version,
            transport_parameters: transport_parameters.map(|x| x.into_owned()),
            early_data_ack,
            encrypted_client_hello_ack,
            unknown_extensions,
        }
    }
}

impl<'a> Codec<'a> for ServerExtensions<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);

        for ext in Self::ALL_EXTENSIONS {
            self.encode_one(*ext, extensions.buf);
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();
        let mut checker = DuplicateExtensionChecker::new();

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            out.read_one(&mut sub, |unknown| checker.check(unknown))?;
        }

        out.unknown_extensions = checker.0;
        Ok(out)
    }
}

/// RFC8446: `CipherSuite cipher_suites<2..2^16-2>;`
impl TlsListElement for CipherSuite {
    const SIZE_LEN: ListLength = ListLength::NonZeroU16 {
        empty_error: InvalidMessage::IllegalEmptyList("CipherSuites"),
    };
}

/// RFC5246: `CompressionMethod compression_methods<1..2^8-1>;`
impl TlsListElement for Compression {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("Compressions"),
    };
}

/// draft-ietf-tls-esni-17: `ExtensionType OuterExtensions<2..254>;`
impl TlsListElement for ExtensionType {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("ExtensionTypes"),
    };
}

extension_struct! {
    /// A representation of extensions present in a `HelloRetryRequest` message
    pub(crate) struct HelloRetryRequestExtensions<'a> {
        ExtensionType::KeyShare =>
            pub(crate) key_share: Option<NamedGroup>,

        ExtensionType::Cookie =>
            pub(crate) cookie: Option<SizedPayload<'a, u16, NonEmpty>>,

        ExtensionType::SupportedVersions =>
            pub(crate) supported_versions: Option<ProtocolVersion>,

        ExtensionType::EncryptedClientHello =>
            pub(crate) encrypted_client_hello: Option<Payload<'a>>,
    } + {
        /// Records decoding order of records, and controls encoding order.
        pub(crate) order: Option<Vec<ExtensionType>>,
    }
}

impl HelloRetryRequestExtensions<'_> {
    fn into_owned(self) -> HelloRetryRequestExtensions<'static> {
        let Self {
            key_share,
            cookie,
            supported_versions,
            encrypted_client_hello,
            order,
        } = self;
        HelloRetryRequestExtensions {
            key_share,
            cookie: cookie.map(|x| x.into_owned()),
            supported_versions,
            encrypted_client_hello: encrypted_client_hello.map(|x| x.into_owned()),
            order,
        }
    }
}

impl<'a> Codec<'a> for HelloRetryRequestExtensions<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);

        for ext in self
            .order
            .as_deref()
            .unwrap_or(Self::ALL_EXTENSIONS)
        {
            self.encode_one(*ext, extensions.buf);
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();

        // we must record order, so re-encoding round trips.  this is needed,
        // unfortunately, for ECH HRR confirmation
        let mut order = vec![];

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            let typ = out.read_one(&mut sub, |_unk| {
                Err(InvalidMessage::UnknownHelloRetryRequestExtension)
            })?;

            order.push(typ);
        }

        out.order = Some(order);
        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HelloRetryRequest {
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: HelloRetryRequestExtensions<'static>,
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
            extensions: HelloRetryRequestExtensions::read(r)?.into_owned(),
        })
    }
}

impl HelloRetryRequest {
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
            Encoding::EchConfirmation
                if self
                    .extensions
                    .encrypted_client_hello
                    .is_some() =>
            {
                let hrr_confirmation = [0u8; 8];
                HelloRetryRequestExtensions {
                    encrypted_client_hello: Some(Payload::Borrowed(&hrr_confirmation)),
                    ..self.extensions.clone()
                }
                .encode(bytes);
            }
            _ => self.extensions.encode(bytes),
        }
    }
}

impl Deref for HelloRetryRequest {
    type Target = HelloRetryRequestExtensions<'static>;
    fn deref(&self) -> &Self::Target {
        &self.extensions
    }
}

impl DerefMut for HelloRetryRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.extensions
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ServerHelloPayload {
    pub(crate) legacy_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: Compression,
    pub(crate) extensions: Box<ServerExtensions<'static>>,
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
        let extensions = Box::new(
            if r.any_left() {
                ServerExtensions::read(r)?
            } else {
                ServerExtensions::default()
            }
            .into_owned(),
        );

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

impl ServerHelloPayload {
    fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
        debug_assert!(
            !matches!(encoding, Encoding::EchConfirmation),
            "we cannot compute an ECH confirmation on a received ServerHello"
        );

        self.legacy_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
    }
}

impl Deref for ServerHelloPayload {
    type Target = ServerExtensions<'static>;
    fn deref(&self) -> &Self::Target {
        &self.extensions
    }
}

impl DerefMut for ServerHelloPayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.extensions
    }
}

#[derive(Clone, Default, Debug)]
pub(crate) struct CertificateChain<'a>(pub(crate) Vec<CertificateDer<'a>>);

impl<'a> CertificateChain<'a> {
    pub(crate) fn from_signer(signer: &'a SelectedCredential) -> Self {
        Self(
            signer
                .identity
                .as_certificates()
                .collect(),
        )
    }

    pub(crate) fn into_owned(self) -> CertificateChain<'static> {
        CertificateChain(
            self.0
                .into_iter()
                .map(CertificateDer::into_owned)
                .collect(),
        )
    }
}

impl<'a> Codec<'a> for CertificateChain<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Vec::encode(&self.0, bytes)
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut ret = Vec::new();
        for item in TlsListIter::<CertificateDer<'a>>::new(r)? {
            ret.push(item?);
        }

        Ok(Self(ret))
    }
}

impl<'a> Deref for CertificateChain<'a> {
    type Target = [CertificateDer<'a>];

    fn deref(&self) -> &[CertificateDer<'a>] {
        &self.0
    }
}

extension_struct! {
    pub(crate) struct CertificateExtensions<'a> {
        ExtensionType::StatusRequest =>
            pub(crate) status: Option<CertificateStatus<'a>>,
    }
}

impl CertificateExtensions<'_> {
    fn into_owned(self) -> CertificateExtensions<'static> {
        CertificateExtensions {
            status: self.status.map(|s| s.into_owned()),
        }
    }
}

impl<'a> Codec<'a> for CertificateExtensions<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);

        for ext in Self::ALL_EXTENSIONS {
            self.encode_one(*ext, extensions.buf);
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            out.read_one(&mut sub, |_unk| {
                Err(InvalidMessage::UnknownCertificateExtension)
            })?;
        }

        Ok(out)
    }
}

#[derive(Debug)]
pub(crate) struct CertificateEntry<'a> {
    pub(crate) cert: CertificateDer<'a>,
    pub(crate) extensions: CertificateExtensions<'a>,
}

impl<'a> Codec<'a> for CertificateEntry<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            cert: CertificateDer::read(r)?,
            extensions: CertificateExtensions::read(r)?.into_owned(),
        })
    }
}

impl<'a> CertificateEntry<'a> {
    pub(crate) fn new(cert: CertificateDer<'a>) -> Self {
        Self {
            cert,
            extensions: CertificateExtensions::default(),
        }
    }

    #[cfg(feature = "std")]
    fn into_owned(self) -> CertificateEntry<'static> {
        CertificateEntry {
            cert: self.cert.into_owned(),
            extensions: self.extensions.into_owned(),
        }
    }
}

impl TlsListElement for CertificateEntry<'_> {
    const SIZE_LEN: ListLength = ListLength::U24 {
        max: CERTIFICATE_MAX_SIZE_LIMIT,
        error: InvalidMessage::CertificatePayloadTooLarge,
    };
}

#[derive(Debug)]
pub(crate) struct CertificatePayloadTls13<'a> {
    pub(crate) context: SizedPayload<'a, u8>,
    pub(crate) entries: Vec<CertificateEntry<'a>>,
}

impl<'a> CertificatePayloadTls13<'a> {
    pub(crate) fn new(
        certs: impl Iterator<Item = CertificateDer<'a>>,
        ocsp_response: Option<&'a [u8]>,
    ) -> Self {
        let ocsp_response = match ocsp_response {
            Some([]) | None => None,
            Some(bytes) => Some(bytes),
        };

        Self {
            context: SizedPayload::from(Payload::Borrowed(&[])),
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
                        e.extensions.status = Some(CertificateStatus::new(ocsp));
                    }
                    e
                })
                .collect(),
        }
    }

    #[cfg(feature = "std")]
    fn into_owned(self) -> CertificatePayloadTls13<'static> {
        CertificatePayloadTls13 {
            context: self.context.into_owned(),
            entries: self
                .entries
                .into_iter()
                .map(CertificateEntry::into_owned)
                .collect(),
        }
    }

    pub(crate) fn end_entity_ocsp(&self) -> Vec<u8> {
        let Some(entry) = self.entries.first() else {
            return vec![];
        };
        entry
            .extensions
            .status
            .as_ref()
            .map(|status| status.ocsp_response.to_vec())
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

impl<'a> Codec<'a> for CertificatePayloadTls13<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.entries.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            context: SizedPayload::read(r)?.into_owned(),
            entries: Vec::read(r)?,
        })
    }
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

pub(crate) trait KxDecode<'a>: fmt::Debug + Sized {
    /// Decode a key exchange message given the key_exchange `algo`
    fn decode(r: &mut Reader<'a>, algo: KeyExchangeAlgorithm) -> Result<Self, InvalidMessage>;
}

#[derive(Debug)]
pub(crate) enum ClientKeyExchangeParams {
    Ecdh(ClientEcdhParams),
    Dh(ClientDhParams),
}

impl ClientKeyExchangeParams {
    pub(crate) fn pub_key(&self) -> &[u8] {
        match self {
            Self::Ecdh(ecdh) => ecdh.public.bytes(),
            Self::Dh(dh) => dh.public.bytes(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ecdh(ecdh) => ecdh.encode(buf),
            Self::Dh(dh) => dh.encode(buf),
        }
    }
}

impl KxDecode<'_> for ClientKeyExchangeParams {
    fn decode(r: &mut Reader<'_>, algo: KeyExchangeAlgorithm) -> Result<Self, InvalidMessage> {
        use KeyExchangeAlgorithm::*;
        Ok(match algo {
            ECDHE => Self::Ecdh(ClientEcdhParams::read(r)?),
            DHE => Self::Dh(ClientDhParams::read(r)?),
        })
    }
}

#[derive(Debug)]
pub(crate) struct ClientEcdhParams {
    /// RFC4492: `opaque point <1..2^8-1>;`
    pub(crate) public: SizedPayload<'static, u8, NonEmpty>,
}

impl Codec<'_> for ClientEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let pb = SizedPayload::read(r)?.into_owned();
        Ok(Self { public: pb })
    }
}

#[derive(Debug)]
pub(crate) struct ClientDhParams {
    /// RFC5246: `opaque dh_Yc<1..2^16-1>;`
    pub(crate) public: SizedPayload<'static, u16, NonEmpty>,
}

impl Codec<'_> for ClientDhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            public: SizedPayload::read(r)?.into_owned(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct ServerEcdhParams {
    pub(crate) curve_params: EcParameters,
    /// RFC4492: `opaque point <1..2^8-1>;`
    pub(crate) public: SizedPayload<'static, u8, NonEmpty>,
}

impl ServerEcdhParams {
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        Self {
            curve_params: EcParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group: kx.group(),
            },
            public: kx.pub_key().to_vec().into(),
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
        let pb = SizedPayload::read(r)?.into_owned();

        Ok(Self {
            curve_params: cp,
            public: pb,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ServerDhParams {
    /// RFC5246: `opaque dh_p<1..2^16-1>;`
    pub(crate) dh_p: SizedPayload<'static, u16, NonEmpty>,
    /// RFC5246: `opaque dh_g<1..2^16-1>;`
    pub(crate) dh_g: SizedPayload<'static, u16, NonEmpty>,
    /// RFC5246: `opaque dh_Ys<1..2^16-1>;`
    pub(crate) dh_ys: SizedPayload<'static, u16, NonEmpty>,
}

impl ServerDhParams {
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        let Some(params) = kx.ffdhe_group() else {
            panic!("invalid NamedGroup for DHE key exchange: {:?}", kx.group());
        };

        Self {
            dh_p: SizedPayload::from(Payload::new(params.p.to_vec())),
            dh_g: SizedPayload::from(Payload::new(params.g.to_vec())),
            dh_ys: SizedPayload::from(Payload::new(kx.pub_key().to_vec())),
        }
    }

    pub(crate) fn as_ffdhe_group(&self) -> FfdheGroup<'_> {
        FfdheGroup::from_params_trimming_leading_zeros(self.dh_p.bytes(), self.dh_g.bytes())
    }
}

impl Codec<'_> for ServerDhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.dh_p.encode(bytes);
        self.dh_g.encode(bytes);
        self.dh_ys.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            dh_p: SizedPayload::read(r)?.into_owned(),
            dh_g: SizedPayload::read(r)?.into_owned(),
            dh_ys: SizedPayload::read(r)?.into_owned(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum ServerKeyExchangeParams {
    Ecdh(ServerEcdhParams),
    Dh(ServerDhParams),
}

impl ServerKeyExchangeParams {
    pub(crate) fn new(kx: &dyn ActiveKeyExchange) -> Self {
        match kx.group().key_exchange_algorithm() {
            KeyExchangeAlgorithm::DHE => Self::Dh(ServerDhParams::new(kx)),
            KeyExchangeAlgorithm::ECDHE => Self::Ecdh(ServerEcdhParams::new(kx)),
        }
    }

    pub(crate) fn pub_key(&self) -> &[u8] {
        match self {
            Self::Ecdh(ecdh) => ecdh.public.bytes(),
            Self::Dh(dh) => dh.dh_ys.bytes(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Ecdh(ecdh) => ecdh.encode(buf),
            Self::Dh(dh) => dh.encode(buf),
        }
    }
}

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
pub(crate) struct ServerKeyExchange {
    pub(crate) params: ServerKeyExchangeParams,
    pub(crate) dss: DigitallySignedStruct,
}

impl ServerKeyExchange {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        self.params.encode(buf);
        self.dss.encode(buf);
    }
}

#[derive(Debug)]
pub(crate) enum ServerKeyExchangePayload {
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
        match self {
            Self::Known(x) => x.encode(bytes),
            Self::Unknown(x) => x.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        // read as Unknown, fully parse when we know the
        // KeyExchangeAlgorithm
        Ok(Self::Unknown(Payload::read(r).into_owned()))
    }
}

impl ServerKeyExchangePayload {
    pub(crate) fn unwrap_given_kxa(&self, kxa: KeyExchangeAlgorithm) -> Option<ServerKeyExchange> {
        if let Self::Unknown(unk) = self {
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

/// RFC5246: `ClientCertificateType certificate_types<1..2^8-1>;`
impl TlsListElement for ClientCertificateType {
    const SIZE_LEN: ListLength = ListLength::NonZeroU8 {
        empty_error: InvalidMessage::IllegalEmptyList("ClientCertificateTypes"),
    };
}

#[derive(Debug)]
pub(crate) struct CertificateRequestPayload {
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

extension_struct! {
    pub(crate) struct CertificateRequestExtensions {
        ExtensionType::SignatureAlgorithms =>
            pub(crate) signature_algorithms: Option<Vec<SignatureScheme>>,

        ExtensionType::CertificateAuthorities =>
            pub(crate) authority_names: Option<Vec<DistinguishedName>>,

        ExtensionType::CompressCertificate =>
            pub(crate) certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
    }
}

impl Codec<'_> for CertificateRequestExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);

        for ext in Self::ALL_EXTENSIONS {
            self.encode_one(*ext, extensions.buf);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();

        let mut checker = DuplicateExtensionChecker::new();

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            out.read_one(&mut sub, |unknown| checker.check(unknown))?;
        }

        if out
            .signature_algorithms
            .as_ref()
            .map(|algs| algs.is_empty())
            .unwrap_or_default()
        {
            return Err(InvalidMessage::NoSignatureSchemes);
        }

        Ok(out)
    }
}

#[derive(Debug)]
pub(crate) struct CertificateRequestPayloadTls13 {
    pub(crate) context: SizedPayload<'static, u8>,
    pub(crate) extensions: CertificateRequestExtensions,
}

impl Codec<'_> for CertificateRequestPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let context = SizedPayload::read(r)?.into_owned();
        let extensions = CertificateRequestExtensions::read(r)?;

        Ok(Self {
            context,
            extensions,
        })
    }
}

// -- NewSessionTicket --
#[derive(Debug)]
pub(crate) struct NewSessionTicketPayload {
    pub(crate) lifetime_hint: Duration,
    // Tickets can be large (KB), so we deserialise this straight
    // into an Arc, so it can be passed directly into the client's
    // session object without copying.
    pub(crate) ticket: Arc<SizedPayload<'static, u16, MaybeEmpty>>,
}

impl NewSessionTicketPayload {
    pub(crate) fn new(lifetime_hint: Duration, ticket: Vec<u8>) -> Self {
        Self {
            lifetime_hint,
            ticket: Arc::new(SizedPayload::from(Payload::new(ticket))),
        }
    }
}

impl Codec<'_> for NewSessionTicketPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.lifetime_hint.as_secs() as u32).encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            lifetime_hint: Duration::from_secs(u32::read(r)? as u64),
            ticket: Arc::new(SizedPayload::read(r)?.into_owned()),
        })
    }
}

// -- NewSessionTicket electric boogaloo --
extension_struct! {
    pub(crate) struct NewSessionTicketExtensions {
        ExtensionType::EarlyData =>
            pub(crate) max_early_data_size: Option<u32>,
    }
}

impl Codec<'_> for NewSessionTicketExtensions {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let extensions = LengthPrefixedBuffer::new(ListLength::U16, bytes);

        for ext in Self::ALL_EXTENSIONS {
            self.encode_one(*ext, extensions.buf);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut out = Self::default();

        let mut checker = DuplicateExtensionChecker::new();

        let len = usize::from(u16::read(r)?);
        let mut sub = r.sub(len)?;

        while sub.any_left() {
            out.read_one(&mut sub, |unknown| checker.check(unknown))?;
        }

        Ok(out)
    }
}

#[derive(Debug)]
pub(crate) struct NewSessionTicketPayloadTls13 {
    pub(crate) lifetime: Duration,
    pub(crate) age_add: u32,
    pub(crate) nonce: SizedPayload<'static, u8>,
    pub(crate) ticket: Arc<SizedPayload<'static, u16, MaybeEmpty>>,
    pub(crate) extensions: NewSessionTicketExtensions,
}

impl NewSessionTicketPayloadTls13 {
    pub(crate) fn new(lifetime: Duration, age_add: u32, nonce: [u8; 32], ticket: Vec<u8>) -> Self {
        Self {
            lifetime,
            age_add,
            nonce: nonce.to_vec().into(),
            ticket: Arc::new(SizedPayload::from(Payload::new(ticket))),
            extensions: NewSessionTicketExtensions::default(),
        }
    }
}

impl Codec<'_> for NewSessionTicketPayloadTls13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.lifetime.as_secs() as u32).encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let lifetime = Duration::from_secs(u32::read(r)? as u64);
        let age_add = u32::read(r)?;
        let nonce = SizedPayload::read(r)?.into_owned();
        // nb. RFC8446: `opaque ticket<1..2^16-1>;`
        let ticket = Arc::new(match SizedPayload::<u16, NonEmpty>::read(r) {
            Err(InvalidMessage::IllegalEmptyList(_)) => Err(InvalidMessage::EmptyTicketValue),
            Err(err) => Err(err),
            Ok(pl) => Ok(SizedPayload::from(Payload::new(pl.into_vec()))),
        }?);
        let extensions = NewSessionTicketExtensions::read(r)?;

        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }
}

// -- RFC6066 certificate status types

/// Only supports OCSP
#[derive(Clone, Debug)]
pub(crate) struct CertificateStatus<'a> {
    /// `opaque OCSPResponse<1..2^24-1>;`
    pub(crate) ocsp_response: SizedPayload<'a, U24, NonEmpty>,
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
                ocsp_response: SizedPayload::read(r)?,
            }),
            _ => Err(InvalidMessage::InvalidCertificateStatusType),
        }
    }
}

impl<'a> CertificateStatus<'a> {
    pub(crate) fn new(ocsp: &'a [u8]) -> Self {
        CertificateStatus {
            ocsp_response: SizedPayload::from(Payload::Borrowed(ocsp)),
        }
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.into_vec()
    }

    pub(crate) fn into_owned(self) -> CertificateStatus<'static> {
        CertificateStatus {
            ocsp_response: self.ocsp_response.into_owned(),
        }
    }
}

// -- RFC8879 compressed certificates

#[derive(Debug)]
pub(crate) struct CompressedCertificatePayload<'a> {
    pub(crate) alg: CertificateCompressionAlgorithm,
    pub(crate) uncompressed_len: u32,
    /// `opaque compressed_certificate_message<1..2^24-1>;`
    pub(crate) compressed: SizedPayload<'a, U24, NonEmpty>,
}

impl<'a> Codec<'a> for CompressedCertificatePayload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.alg.encode(bytes);
        U24(self.uncompressed_len).encode(bytes);
        self.compressed.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            alg: CertificateCompressionAlgorithm::read(r)?,
            uncompressed_len: U24::read(r)?.0,
            compressed: SizedPayload::read(r)?,
        })
    }
}

impl CompressedCertificatePayload<'_> {
    #[cfg(feature = "std")]
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
            compressed: SizedPayload::from(Payload::Borrowed(self.compressed.bytes())),
        }
    }
}

#[derive(Debug)]
pub(crate) enum HandshakePayload<'a> {
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
    EncryptedExtensions(Box<ServerExtensions<'a>>),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    MessageHash(Payload<'a>),
    Unknown((HandshakeType, Payload<'a>)),
}

impl HandshakePayload<'_> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        use self::HandshakePayload::*;
        match self {
            HelloRequest | ServerHelloDone | EndOfEarlyData => {}
            ClientHello(x) => x.encode(bytes),
            ServerHello(x) => x.encode(bytes),
            HelloRetryRequest(x) => x.encode(bytes),
            Certificate(x) => x.encode(bytes),
            CertificateTls13(x) => x.encode(bytes),
            CompressedCertificate(x) => x.encode(bytes),
            ServerKeyExchange(x) => x.encode(bytes),
            ClientKeyExchange(x) => x.encode(bytes),
            CertificateRequest(x) => x.encode(bytes),
            CertificateRequestTls13(x) => x.encode(bytes),
            CertificateVerify(x) => x.encode(bytes),
            NewSessionTicket(x) => x.encode(bytes),
            NewSessionTicketTls13(x) => x.encode(bytes),
            EncryptedExtensions(x) => x.encode(bytes),
            KeyUpdate(x) => x.encode(bytes),
            Finished(x) => x.encode(bytes),
            CertificateStatus(x) => x.encode(bytes),
            MessageHash(x) => x.encode(bytes),
            Unknown((_, x)) => x.encode(bytes),
        }
    }

    pub(crate) fn handshake_type(&self) -> HandshakeType {
        use self::HandshakePayload::*;
        match self {
            HelloRequest => HandshakeType::HelloRequest,
            ClientHello(_) => HandshakeType::ClientHello,
            ServerHello(_) => HandshakeType::ServerHello,
            HelloRetryRequest(_) => HandshakeType::HelloRetryRequest,
            Certificate(_) | CertificateTls13(_) => HandshakeType::Certificate,
            CompressedCertificate(_) => HandshakeType::CompressedCertificate,
            ServerKeyExchange(_) => HandshakeType::ServerKeyExchange,
            CertificateRequest(_) | CertificateRequestTls13(_) => HandshakeType::CertificateRequest,
            CertificateVerify(_) => HandshakeType::CertificateVerify,
            ServerHelloDone => HandshakeType::ServerHelloDone,
            EndOfEarlyData => HandshakeType::EndOfEarlyData,
            ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            NewSessionTicket(_) | NewSessionTicketTls13(_) => HandshakeType::NewSessionTicket,
            EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            KeyUpdate(_) => HandshakeType::KeyUpdate,
            Finished(_) => HandshakeType::Finished,
            CertificateStatus(_) => HandshakeType::CertificateStatus,
            MessageHash(_) => HandshakeType::MessageHash,
            Unknown((t, _)) => *t,
        }
    }

    fn wire_handshake_type(&self) -> HandshakeType {
        match self.handshake_type() {
            // A `HelloRetryRequest` appears on the wire as a `ServerHello` with a magic `random` value.
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            other => other,
        }
    }

    #[cfg(feature = "std")]
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
            EncryptedExtensions(x) => EncryptedExtensions(Box::new(x.into_owned())),
            KeyUpdate(x) => KeyUpdate(x),
            Finished(x) => Finished(x.into_owned()),
            CertificateStatus(x) => CertificateStatus(x.into_owned()),
            MessageHash(x) => MessageHash(x.into_owned()),
            Unknown((t, x)) => Unknown((t, x.into_owned())),
        }
    }
}

#[derive(Debug)]
pub struct HandshakeMessagePayload<'a>(pub(crate) HandshakePayload<'a>);

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
        let typ = HandshakeType::read(r)?;
        let len = U24::read(r)?.0 as usize;
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
                HandshakePayload::EncryptedExtensions(Box::new(ServerExtensions::read(&mut sub)?))
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
            _ => HandshakePayload::Unknown((typ, Payload::read(&mut sub))),
        };

        sub.expect_empty("HandshakeMessagePayload")
            .map(|_| Self(payload))
    }

    pub(crate) fn encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut ret = self.get_encoding();
        let ret_len = ret.len() - self.total_binder_length();
        ret.truncate(ret_len);
        ret
    }

    pub(crate) fn total_binder_length(&self) -> usize {
        match &self.0 {
            HandshakePayload::ClientHello(ch) => match &ch.preshared_key_offer {
                Some(offer) => {
                    let mut binders_encoding = Vec::new();
                    offer
                        .binders
                        .encode(&mut binders_encoding);
                    binders_encoding.len()
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    pub(crate) fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
        // output type, length, and encoded payload
        self.0
            .wire_handshake_type()
            .encode(bytes);

        let nested = LengthPrefixedBuffer::new(
            ListLength::U24 {
                max: usize::MAX,
                error: InvalidMessage::MessageTooLarge,
            },
            bytes,
        );

        match &self.0 {
            // for Server Hello and HelloRetryRequest payloads we need to encode the payload
            // differently based on the purpose of the encoding.
            HandshakePayload::ServerHello(payload) => payload.payload_encode(nested.buf, encoding),
            HandshakePayload::HelloRetryRequest(payload) => {
                payload.payload_encode(nested.buf, encoding)
            }

            // All other payload types are encoded the same regardless of purpose.
            _ => self.0.encode(nested.buf),
        }
    }

    pub(crate) fn build_handshake_hash(hash: &[u8]) -> Self {
        Self(HandshakePayload::MessageHash(Payload::new(hash.to_vec())))
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> HandshakeMessagePayload<'static> {
        HandshakeMessagePayload(self.0.into_owned())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct HpkeKeyConfig {
    pub config_id: u8,
    pub kem_id: HpkeKem,
    /// draft-ietf-tls-esni-24: `opaque HpkePublicKey<1..2^16-1>;`
    pub public_key: SizedPayload<'static, u16, NonEmpty>,
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
            public_key: SizedPayload::read(r)?.into_owned(),
            symmetric_cipher_suites: Vec::<HpkeSymmetricCipherSuite>::read(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EchConfigContents {
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
        SizedPayload::<u8, MaybeEmpty>::from(Payload::Borrowed(dns_name.as_ref().as_ref()))
            .encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            key_config: HpkeKeyConfig::read(r)?,
            maximum_name_length: u8::read(r)?,
            public_name: {
                DnsName::try_from(SizedPayload::<u8, MaybeEmpty>::read(r)?.bytes())
                    .map_err(|_| InvalidMessage::InvalidServerName)?
                    .to_owned()
            },
            extensions: Vec::read(r)?,
        })
    }
}

/// An encrypted client hello (ECH) config.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EchConfigPayload {
    /// A recognized V18 ECH configuration.
    V18(EchConfigContents),
    /// An unknown version ECH configuration.
    Unknown {
        version: EchVersion,
        contents: SizedPayload<'static, u16, MaybeEmpty>,
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
                // Note: we don't SizedPayload::read() here because we've already read the length prefix.
                let data = SizedPayload::from(Payload::new(contents.rest()));
                Self::Unknown {
                    version,
                    contents: data,
                }
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EchConfigExtension {
    Unknown(UnknownExtension),
}

impl EchConfigExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match self {
            Self::Unknown(r) => r.typ,
        }
    }
}

impl Codec<'_> for EchConfigExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match self {
            Self::Unknown(r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        #[expect(clippy::match_single_binding)] // Future-proofing.
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

/// Representation of the ECHEncryptedExtensions extension specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub(crate) struct ServerEncryptedClientHello {
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
/// the encoded message is being used for.
pub(crate) enum Encoding {
    /// Standard RFC 8446 encoding.
    Standard,
    /// Encoding for ECH confirmation for HRR.
    EchConfirmation,
    /// Encoding for ECH inner client hello.
    EchInnerHello { to_compress: Vec<ExtensionType> },
}

pub(super) fn has_duplicates<I: IntoIterator<Item = E>, E: Into<T>, T: Eq + Ord>(iter: I) -> bool {
    let mut seen = BTreeSet::new();

    for x in iter {
        if !seen.insert(x.into()) {
            return true;
        }
    }

    false
}

pub(super) struct DuplicateExtensionChecker(pub(super) BTreeSet<u16>);

impl DuplicateExtensionChecker {
    pub(super) fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub(super) fn check(&mut self, typ: ExtensionType) -> Result<(), InvalidMessage> {
        let u = u16::from(typ);
        match self.0.insert(u) {
            true => Ok(()),
            false => Err(InvalidMessage::DuplicateExtension(u)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hpke::{HpkeAead, HpkeKdf};

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
                public_key: SizedPayload::from(b"xxx".to_vec()),
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
