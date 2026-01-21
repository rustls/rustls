use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use super::base::{NonEmpty, SizedPayload};
use super::codec::{Codec, LengthPrefixedBuffer, ListLength, Reader};
use super::enums::{Compression, ExtensionType};
use super::handshake::{
    CertificateStatusRequest, ClientSessionTicket, DuplicateExtensionChecker, EncryptedClientHello,
    KeyShareEntry, PresharedKeyOffer, PskKeyExchangeModes, ServerNamePayload,
    SupportedEcPointFormats, SupportedProtocolVersions, Encoding, Random, SessionId, has_duplicates,
};
use crate::crypto::cipher::Payload;
use crate::crypto::kx::NamedGroup;
use crate::crypto::{CipherSuite, SignatureScheme};
use crate::enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CertificateType, ProtocolVersion,
};
use crate::error::InvalidMessage;
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
