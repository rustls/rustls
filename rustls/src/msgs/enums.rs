#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]

enum_builder! {
    /// The `ClientCertificateType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub(crate) struct ClientCertificateType(pub u8);

    enum ClientCertificateTypeName {
        RSASign => 0x01,
        ECDSASign => 0x40,
    }
}

enum_builder! {
    /// The `Compression` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub(crate) struct Compression(pub(crate) u8);

    pub(crate) enum CompressionName {
        Null => 0x00,
    }
}

enum_builder! {
    /// The `AlertLevel` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct AlertLevel(pub u8);

    pub(crate) enum AlertLevelName {
        Warning => 0x01,
        Fatal => 0x02,
    }
}

enum_builder! {
    /// The `ExtensionType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct ExtensionType(pub u16);

    enum ExtensionTypeName {
        ServerName => 0x0000,
        MaxFragmentLength => 0x0001,
        ClientCertificateUrl => 0x0002,
        TrustedCAKeys => 0x0003,
        TruncatedHMAC => 0x0004,
        StatusRequest => 0x0005,
        UserMapping => 0x0006,
        ClientAuthz => 0x0007,
        ServerAuthz => 0x0008,
        CertificateType => 0x0009,
        EllipticCurves => 0x000a,
        ECPointFormats => 0x000b,
        SRP => 0x000c,
        SignatureAlgorithms => 0x000d,
        UseSRTP => 0x000e,
        Heartbeat => 0x000f,
        ALProtocolNegotiation => 0x0010,
        SCT => 0x0012,
        ClientCertificateType => 0x0013,
        ServerCertificateType => 0x0014,
        Padding => 0x0015,
        ExtendedMasterSecret => 0x0017,
        CompressCertificate => 0x001b,
        SessionTicket => 0x0023,
        PreSharedKey => 0x0029,
        EarlyData => 0x002a,
        SupportedVersions => 0x002b,
        Cookie => 0x002c,
        PSKKeyExchangeModes => 0x002d,
        TicketEarlyDataInfo => 0x002e,
        CertificateAuthorities => 0x002f,
        OIDFilters => 0x0030,
        PostHandshakeAuth => 0x0031,
        SignatureAlgorithmsCert => 0x0032,
        KeyShare => 0x0033,
        TransportParameters => 0x0039,
        NextProtocolNegotiation => 0x3374,
        ChannelId => 0x754f,
        RenegotiationInfo => 0xff01,
        EncryptedClientHello => 0xfe0d, // https://datatracker.ietf.org/doc/html/rfc9849#section-11.1
        EncryptedClientHelloOuterExtensions => 0xfd00, // https://datatracker.ietf.org/doc/html/rfc9849#section-5.1
    }
}

impl ExtensionType {
    /// Returns true if the extension type can be compressed in an "inner" client hello for ECH.
    ///
    /// This function should only return true for extension types where the inner hello and outer
    /// hello extensions values will always be identical. Extensions that may be identical
    /// sometimes (e.g. server name, cert compression methods), but not always, SHOULD NOT be
    /// compressed.
    ///
    /// See [RFC 9849 §5](https://datatracker.ietf.org/doc/html/rfc9849#section-5)
    /// and [RFC 9849 §10.5](https://datatracker.ietf.org/doc/html/rfc9849#section-10.5)
    /// for more information.
    pub(crate) fn ech_compress(&self) -> bool {
        // We match which extensions we will compress with BoringSSL and Go's stdlib.
        matches!(
            *self,
            Self::StatusRequest
                | Self::EllipticCurves
                | Self::SignatureAlgorithms
                | Self::SignatureAlgorithmsCert
                | Self::ALProtocolNegotiation
                | Self::SupportedVersions
                | Self::Cookie
                | Self::KeyShare
                | Self::PSKKeyExchangeModes
        )
    }
}

enum_builder! {
    /// The `ServerNameType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub(crate) struct ServerNameType(pub u8);

    enum ServerNameTypeName {
        HostName => 0x00,
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct ECPointFormat(pub u8);

    enum ECPointFormatName {
        Uncompressed => 0x00,
    }
}

enum_builder! {
    /// The `ECCurveType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub(crate) struct ECCurveType(pub(crate) u8);

    enum ECCurveTypeName {
        NamedCurve => 0x03,
    }
}

enum_builder! {
    /// The `PskKeyExchangeMode` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct PskKeyExchangeMode(pub u8);

    enum PskKeyExchangeModeName {
        PSK_KE => 0x00,
        PSK_DHE_KE => 0x01,
    }
}

enum_builder! {
    /// The `KeyUpdateRequest` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct KeyUpdateRequest(pub u8);

     enum KeyUpdateRequestName {
        UpdateNotRequested => 0x00,
        UpdateRequested => 0x01,
    }
}

enum_builder! {
    /// The `CertificateStatusType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    pub struct CertificateStatusType(pub u8);

    enum CertificateStatusTypeName {
        OCSP => 0x01,
    }
}

enum_builder! {
    /// The Encrypted Client Hello protocol version (`EchVersion`).
    ///
    /// Specified in [RFC 9849 Section 4].
    ///
    /// [RFC 9849 Section 4]: <https://datatracker.ietf.org/doc/html/rfc9849#section-4>
    pub struct EchVersion(pub u16);

    enum EchVersionName {
        V18 => 0xfe0d,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // These tests are intended to provide coverage and
    // check panic-safety of relatively unused values.

    use alloc::vec::Vec;

    use super::*;
    use crate::msgs::codec::Codec;

    #[test]
    fn test_enums() {
        test_enum8::<ClientCertificateType>(
            ClientCertificateType::RSASign,
            ClientCertificateType::ECDSASign,
        );
        test_enum8::<Compression>(Compression::Null, Compression::Null);
        test_enum8::<AlertLevel>(AlertLevel::Warning, AlertLevel::Fatal);
        test_enum16::<ExtensionType>(ExtensionType::ServerName, ExtensionType::RenegotiationInfo);
        test_enum8::<ServerNameType>(ServerNameType::HostName, ServerNameType::HostName);
        test_enum8::<ECPointFormat>(ECPointFormat::Uncompressed, ECPointFormat::Uncompressed);
        test_enum8::<PskKeyExchangeMode>(
            PskKeyExchangeMode::PSK_KE,
            PskKeyExchangeMode::PSK_DHE_KE,
        );
        test_enum8::<KeyUpdateRequest>(
            KeyUpdateRequest::UpdateNotRequested,
            KeyUpdateRequest::UpdateRequested,
        );
        test_enum8::<CertificateStatusType>(
            CertificateStatusType::OCSP,
            CertificateStatusType::OCSP,
        );
    }

    pub(crate) fn test_enum8<T: for<'a> Codec<'a>>(first: T, last: T) {
        let first_v = get8(&first);
        let last_v = get8(&last);

        for val in first_v..last_v + 1 {
            let mut buf = Vec::new();
            val.encode(&mut buf);
            assert_eq!(buf.len(), 1);

            let t = T::read_bytes(&buf).unwrap();
            assert_eq!(val, get8(&t));
            std::println!("{val:?}");
        }
    }

    pub(crate) fn test_enum8_display<T: for<'a> Codec<'a> + core::fmt::Display + Copy + From<u8>>(
        first: T,
        last: T,
    ) where
        u8: From<T>,
    {
        test_enum8(first, last);

        for val in u8::from(first)..u8::from(last) + 1 {
            let t = T::from(val);
            std::println!("0x{val:02x} => {t}");
        }
    }

    pub(crate) fn test_enum16<T: for<'a> Codec<'a>>(first: T, last: T) {
        let first_v = get16(&first);
        let last_v = get16(&last);

        for val in first_v..last_v + 1 {
            let mut buf = Vec::new();
            val.encode(&mut buf);
            assert_eq!(buf.len(), 2);

            let t = T::read_bytes(&buf).unwrap();
            assert_eq!(val, get16(&t));
            std::println!("{val:?}");
        }
    }

    fn get8<T: for<'a> Codec<'a>>(enum_value: &T) -> u8 {
        let enc = enum_value.get_encoding();
        assert_eq!(enc.len(), 1);
        enc[0]
    }

    fn get16<T: for<'a> Codec<'a>>(enum_value: &T) -> u16 {
        let enc = enum_value.get_encoding();
        assert_eq!(enc.len(), 2);
        (enc[0] as u16 >> 8) | (enc[1] as u16)
    }
}
