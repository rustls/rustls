#![expect(missing_docs)]

enum_builder! {
    /// The `HandshakeType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum HandshakeType {
        HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        HelloVerifyRequest => 0x03,
        NewSessionTicket => 0x04,
        EndOfEarlyData => 0x05,
        HelloRetryRequest => 0x06,
        EncryptedExtensions => 0x08,
        Certificate => 0x0b,
        ServerKeyExchange => 0x0c,
        CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14,
        CertificateURL => 0x15,
        CertificateStatus => 0x16,
        KeyUpdate => 0x18,
        CompressedCertificate => 0x19,
        MessageHash => 0xfe,
    }
}

enum_builder! {
    /// The `ContentType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum ContentType {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17,
        Heartbeat => 0x18,
    }
}

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum ProtocolVersion {
        SSLv2 => 0x0002,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

enum_builder! {
    /// The "TLS Certificate Compression Algorithm IDs" TLS protocol enum.
    /// Values in this enum are taken from [RFC8879].
    ///
    /// [RFC8879]: https://www.rfc-editor.org/rfc/rfc8879.html#section-7.3
    #[repr(u16)]
    pub enum CertificateCompressionAlgorithm {
        Zlib => 1,
        Brotli => 2,
        Zstd => 3,
    }
}

enum_builder! {
    /// The `CertificateType` enum sent in the cert_type extensions.
    /// Values in this enum are taken from the various RFCs covering TLS, and are listed by IANA.
    ///
    /// [RFC 6091 Section 5]: <https://datatracker.ietf.org/doc/html/rfc6091#section-5>
    /// [RFC 7250 Section 7]: <https://datatracker.ietf.org/doc/html/rfc7250#section-7>
    #[repr(u8)]
    #[derive(Default)]
    pub enum CertificateType {
        #[default]
        X509 => 0x00,
        RawPublicKey => 0x02,
    }
}

enum_builder! {
    /// The type of Encrypted Client Hello (`EchClientHelloType`).
    ///
    /// Specified in [draft-ietf-tls-esni Section 5].
    ///
    /// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
    #[repr(u8)]
    pub enum EchClientHelloType {
        ClientHelloOuter => 0,
        ClientHelloInner => 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::enums::tests::{test_enum8, test_enum16};

    #[test]
    fn test_enums() {
        test_enum8::<ContentType>(ContentType::ChangeCipherSpec, ContentType::Heartbeat);
        test_enum8::<HandshakeType>(HandshakeType::HelloRequest, HandshakeType::MessageHash);
        test_enum16::<CertificateCompressionAlgorithm>(
            CertificateCompressionAlgorithm::Zlib,
            CertificateCompressionAlgorithm::Zstd,
        );
        test_enum8::<CertificateType>(CertificateType::X509, CertificateType::RawPublicKey);
    }
}
