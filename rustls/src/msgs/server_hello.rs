use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use super::base::SizedPayload;
use super::codec::{Codec, LengthPrefixedBuffer, ListLength, Reader};
use super::enums::{Compression, ExtensionType};
use super::handshake::{
    DuplicateExtensionChecker, Encoding, KeyShareEntry, Random, ServerEncryptedClientHello,
    SessionId, SingleProtocolName, SupportedEcPointFormats,
};
use crate::crypto::CipherSuite;
use crate::crypto::cipher::Payload;
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

static ZERO_RANDOM: Random = Random([0u8; 32]);
