#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
use crate::crypto::KeyExchangeAlgorithm;
use crate::enums::ProtocolVersion;
use crate::msgs::codec::{Codec, Reader};

enum_builder! {
    /// The `ClientCertificateType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum ClientCertificateType {
        RSASign => 0x01,
        DSSSign => 0x02,
        RSAFixedDH => 0x03,
        DSSFixedDH => 0x04,
        RSAEphemeralDH => 0x05,
        DSSEphemeralDH => 0x06,
        FortezzaDMS => 0x14,
        ECDSASign => 0x40,
        RSAFixedECDH => 0x41,
        ECDSAFixedECDH => 0x42,
    }
}

enum_builder! {
    /// The `Compression` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum Compression {
        Null => 0x00,
        Deflate => 0x01,
        LSZ => 0x40,
    }
}

enum_builder! {
    /// The `AlertLevel` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum AlertLevel {
        Warning => 0x01,
        Fatal => 0x02,
    }
}

enum_builder! {
    /// The `HeartbeatMessageType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum HeartbeatMessageType {
        Request => 0x01,
        Response => 0x02,
    }
}

enum_builder! {
    /// The `ExtensionType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum ExtensionType {
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
        EncryptedClientHello => 0xfe0d, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.1
        EncryptedClientHelloOuterExtensions => 0xfd00, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-5.1
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
    /// See [draft-ietf-tls-esni-18 §5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-5)
    /// and [draft-ietf-tls-esni-18 §10.5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-10.5)
    /// for more information.
    pub(crate) fn ech_compress(&self) -> bool {
        // We match which extensions we will compress with BoringSSL and Go's stdlib.
        matches!(
            self,
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
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum ServerNameType {
        HostName => 0x00,
    }
}

enum_builder! {
    /// The `NamedGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    ///
    /// This enum is used for recognizing key exchange groups advertised
    /// by a peer during a TLS handshake. It is **not** a list of groups that
    /// Rustls supports. The supported groups are determined via the
    /// [`CryptoProvider`][crate::crypto::CryptoProvider] interface.
    #[repr(u16)]
    pub enum NamedGroup {
        secp256r1 => 0x0017,
        secp384r1 => 0x0018,
        secp521r1 => 0x0019,
        X25519 => 0x001d,
        X448 => 0x001e,
        /// <https://www.iana.org/go/rfc8734>
        brainpoolP256r1tls13 => 0x001f,
        /// <https://www.iana.org/go/rfc8734>
        brainpoolP384r1tls13 => 0x0020,
        /// <https://www.iana.org/go/rfc8734>
        brainpoolP512r1tls13 => 0x0021,
        /// <https://www.iana.org/go/rfc8998>
        curveSM2 => 0x0029,
        FFDHE2048 => 0x0100,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/>
        MLKEM512 => 0x0200,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/>
        MLKEM768 => 0x0201,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/>
        MLKEM1024 => 0x0202,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
        secp256r1MLKEM768 => 0x11eb,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
        X25519MLKEM768 => 0x11ec,
        /// <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
        secp384r1MLKEM1024 => 0x11ed,
    }
}

impl NamedGroup {
    /// Return the key exchange algorithm associated with this `NamedGroup`
    pub fn key_exchange_algorithm(self) -> KeyExchangeAlgorithm {
        match u16::from(self) {
            x if (0x100..0x200).contains(&x) => KeyExchangeAlgorithm::DHE,
            _ => KeyExchangeAlgorithm::ECDHE,
        }
    }

    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => true,
            _ => !matches!(
                self,
                Self::MLKEM512
                    | Self::MLKEM768
                    | Self::MLKEM1024
                    | Self::X25519MLKEM768
                    | Self::secp256r1MLKEM768
                    | Self::secp384r1MLKEM1024
                    | Self::brainpoolP256r1tls13
                    | Self::brainpoolP384r1tls13
                    | Self::brainpoolP512r1tls13
                    | Self::curveSM2
            ),
        }
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

enum_builder! {
    /// The `HeartbeatMode` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum HeartbeatMode {
        PeerAllowedToSend => 0x01,
        PeerNotAllowedToSend => 0x02,
    }
}

enum_builder! {
    /// The `ECCurveType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub(crate) enum ECCurveType {
        ExplicitPrime => 0x01,
        ExplicitChar2 => 0x02,
        NamedCurve => 0x03,
    }
}

enum_builder! {
    /// The `PskKeyExchangeMode` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum PskKeyExchangeMode {
        PSK_KE => 0x00,
        PSK_DHE_KE => 0x01,
    }
}

enum_builder! {
    /// The `KeyUpdateRequest` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum KeyUpdateRequest {
        UpdateNotRequested => 0x00,
        UpdateRequested => 0x01,
    }
}

enum_builder! {
    /// The `CertificateStatusType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum CertificateStatusType {
        OCSP => 0x01,
    }
}

enum_builder! {
    /// The Key Encapsulation Mechanism (`Kem`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.1]
    ///
    /// [RFC 9180 Section 7.1]: <https://datatracker.ietf.org/doc/html/rfc9180#kemid-values>
    #[repr(u16)]
    pub enum HpkeKem {
        DHKEM_P256_HKDF_SHA256 => 0x0010,
        DHKEM_P384_HKDF_SHA384 => 0x0011,
        DHKEM_P521_HKDF_SHA512 => 0x0012,
        DHKEM_X25519_HKDF_SHA256 => 0x0020,
        DHKEM_X448_HKDF_SHA512 => 0x0021,
    }
}

enum_builder! {
    /// The Key Derivation Function (`Kdf`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.2]
    ///
    /// [RFC 9180 Section 7.2]: <https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd>
    #[repr(u16)]
    #[derive(Default)]
    pub enum HpkeKdf {
        // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
        #[default]
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

enum_builder! {
    /// The Authenticated Encryption with Associated Data (`Aead`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.3]
    ///
    /// [RFC 9180 Section 7.3]: <https://datatracker.ietf.org/doc/html/rfc9180#name-authenticated-encryption-wi>
    #[repr(u16)]
    #[derive(Default)]
    pub enum HpkeAead {
        // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
        #[default]
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        CHACHA20_POLY_1305 => 0x0003,
        EXPORT_ONLY => 0xFFFF,
    }
}

impl HpkeAead {
    /// Returns the length of the tag for the AEAD algorithm, or none if the AEAD is EXPORT_ONLY.
    pub(crate) fn tag_len(&self) -> Option<usize> {
        match self {
            // See RFC 9180 Section 7.3, column `Nt`, the length in bytes of the authentication tag
            // for the algorithm.
            // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
            Self::AES_128_GCM | Self::AES_256_GCM | Self::CHACHA20_POLY_1305 => Some(16),
            _ => None,
        }
    }
}

enum_builder! {
    /// The Encrypted Client Hello protocol version (`EchVersion`).
    ///
    /// Specified in [draft-ietf-tls-esni Section 4].
    /// TODO(XXX): Update reference once RFC is published.
    ///
    /// [draft-ietf-tls-esni Section 4]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-17.html#section-4>
    #[repr(u16)]
    pub enum EchVersion {
        V18 => 0xfe0d,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // These tests are intended to provide coverage and
    // check panic-safety of relatively unused values.

    use std::prelude::v1::*;

    use super::*;

    #[test]
    fn test_enums() {
        test_enum8::<ClientCertificateType>(
            ClientCertificateType::RSASign,
            ClientCertificateType::ECDSAFixedECDH,
        );
        test_enum8::<Compression>(Compression::Null, Compression::LSZ);
        test_enum8::<AlertLevel>(AlertLevel::Warning, AlertLevel::Fatal);
        test_enum8::<HeartbeatMessageType>(
            HeartbeatMessageType::Request,
            HeartbeatMessageType::Response,
        );
        test_enum16::<ExtensionType>(ExtensionType::ServerName, ExtensionType::RenegotiationInfo);
        test_enum8::<ServerNameType>(ServerNameType::HostName, ServerNameType::HostName);
        test_enum16::<NamedGroup>(NamedGroup::secp256r1, NamedGroup::FFDHE8192);
        test_enum8::<ECPointFormat>(
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedChar2,
        );
        test_enum8::<HeartbeatMode>(
            HeartbeatMode::PeerAllowedToSend,
            HeartbeatMode::PeerNotAllowedToSend,
        );
        test_enum8::<ECCurveType>(ECCurveType::ExplicitPrime, ECCurveType::NamedCurve);
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
