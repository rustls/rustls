use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use core::{fmt, iter};

use pki_types::CertificateDer;

use crate::crypto::cipher::Payload;
use crate::crypto::kx::ffdhe::FfdheGroup;
use crate::crypto::kx::{ActiveKeyExchange, KeyExchangeAlgorithm, NamedGroup};
use crate::crypto::{
    CipherSuite, GetRandomFailed, SecureRandom, SelectedCredential, SignatureScheme,
};
use crate::enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CertificateType, ProtocolVersion,
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
    ExtensionType,
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

pub(super) const HELLO_RETRY_REQUEST_RANDOM: Random = Random([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

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
    pub(super) fn payload_encode(&self, bytes: &mut Vec<u8>, purpose: Encoding) {
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
    pub(super) fn into_owned(self) -> CertificatePayloadTls13<'static> {
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
    pub(super) fn into_owned(self) -> CompressedCertificatePayload<'static> {
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
