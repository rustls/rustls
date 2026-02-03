use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use pki_types::DnsName;

use super::codec::{
    Codec, LengthPrefixedBuffer, ListLength, MaybeEmpty, NonEmpty, Reader, SizedPayload,
    TlsListElement,
};
use super::enums::{Compression, EchVersion, ExtensionType};
use super::handshake::{
    DuplicateExtensionChecker, Encoding, KeyShareEntry, Random, SessionId, SingleProtocolName,
    SupportedEcPointFormats, has_duplicates,
};
use crate::crypto::CipherSuite;
use crate::crypto::cipher::Payload;
use crate::crypto::hpke::{HpkeKem, HpkeSymmetricCipherSuite};
use crate::enums::{CertificateType, ProtocolVersion};
use crate::error::InvalidMessage;

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
    pub(super) fn payload_encode(&self, bytes: &mut Vec<u8>, encoding: Encoding) {
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
    pub(super) fn into_owned(self) -> ServerExtensions<'static> {
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

static ZERO_RANDOM: Random = Random([0u8; 32]);

#[cfg(test)]
mod tests {
    use alloc::vec;

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
