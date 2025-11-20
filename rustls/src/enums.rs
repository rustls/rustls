#![expect(non_camel_case_types)]
#![expect(missing_docs)]
use crate::crypto::hash;

enum_builder! {
    /// The `AlertDescription` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum AlertDescription {
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCa => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognizedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPskIdentity => 0x73,
        CertificateRequired => 0x74,
        NoApplicationProtocol => 0x78,
        EncryptedClientHelloRequired => 0x79, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.2
    }
}

impl core::fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // these should be:
        // - in past tense
        // - be syntactically correct if prefaced with 'the peer' to describe
        //   received alerts
        match self {
            // this is normal.
            Self::CloseNotify => write!(f, "cleanly closed the connection"),

            // these are abnormal.  they are usually symptomatic of an interop failure.
            // please file a bug report.
            Self::UnexpectedMessage => write!(f, "received an unexpected message"),
            Self::BadRecordMac => write!(f, "failed to verify a message"),
            Self::RecordOverflow => write!(f, "rejected an over-length message"),
            Self::IllegalParameter => write!(
                f,
                "rejected a message because a field was incorrect or inconsistent"
            ),
            Self::DecodeError => write!(f, "failed to decode a message"),
            Self::DecryptError => {
                write!(f, "failed to perform a handshake cryptographic operation")
            }
            Self::InappropriateFallback => {
                write!(f, "detected an attempted version downgrade")
            }
            Self::MissingExtension => {
                write!(f, "required a specific extension that was not provided")
            }
            Self::UnsupportedExtension => write!(f, "rejected an unsolicited extension"),

            // these are deprecated by TLS1.3 and should be very rare (but possible
            // with TLS1.2 or earlier peers)
            Self::DecryptionFailed => write!(f, "failed to decrypt a message"),
            Self::DecompressionFailure => write!(f, "failed to decompress a message"),
            Self::NoCertificate => write!(f, "found no certificate"),
            Self::ExportRestriction => write!(f, "refused due to export restrictions"),
            Self::NoRenegotiation => write!(f, "rejected an attempt at renegotiation"),
            Self::CertificateUnobtainable => {
                write!(f, "failed to retrieve its certificate")
            }
            Self::BadCertificateHashValue => {
                write!(f, "rejected the `certificate_hash` extension")
            }

            // this is fairly normal. it means a server cannot choose compatible parameters
            // given our offer.  please use ssllabs.com or similar to investigate what parameters
            // the server supports.
            Self::HandshakeFailure => write!(
                f,
                "failed to negotiate an acceptable set of security parameters"
            ),
            Self::ProtocolVersion => write!(f, "did not support a suitable TLS version"),
            Self::InsufficientSecurity => {
                write!(f, "required a higher security level than was offered")
            }

            // these usually indicate a local misconfiguration, either in certificate selection
            // or issuance.
            Self::BadCertificate => {
                write!(
                    f,
                    "rejected the certificate as corrupt or incorrectly signed"
                )
            }
            Self::UnsupportedCertificate => {
                write!(f, "did not support the certificate")
            }
            Self::CertificateRevoked => write!(f, "found the certificate to be revoked"),
            Self::CertificateExpired => write!(f, "found the certificate to be expired"),
            Self::CertificateUnknown => {
                write!(f, "rejected the certificate for an unspecified reason")
            }
            Self::UnknownCa => write!(f, "found the certificate was not issued by a trusted CA"),
            Self::BadCertificateStatusResponse => {
                write!(f, "rejected the certificate status response")
            }
            // typically this means client authentication is required, in TLS1.2...
            Self::AccessDenied => write!(f, "denied access"),
            // and in TLS1.3...
            Self::CertificateRequired => write!(f, "required a client certificate"),

            Self::InternalError => write!(f, "encountered an internal error"),
            Self::UserCanceled => write!(f, "canceled the handshake"),

            // rejection of SNI (uncommon; usually servers behave as if it was not sent)
            Self::UnrecognizedName => {
                write!(f, "did not recognize a name in the `server_name` extension")
            }

            // rejection of PSK connections (NYI in this library); indicates a local
            // misconfiguration.
            Self::UnknownPskIdentity => {
                write!(f, "did not recognize any offered PSK identity")
            }

            // rejection of ALPN (varying levels of support, but missing support is
            // often dangerous if the peers fail to agree on the same protocol)
            Self::NoApplicationProtocol => write!(
                f,
                "did not support any of the offered application protocols"
            ),

            // ECH requirement by clients, see
            // <https://datatracker.ietf.org/doc/draft-ietf-tls-esni/25/>
            Self::EncryptedClientHelloRequired => {
                write!(f, "required use of encrypted client hello")
            }

            Self::Unknown(n) => write!(f, "sent an unknown alert (0x{n:02x?})"),
        }
    }
}

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
    /// The `CipherSuite` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum CipherSuite {
        /// The `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5288>
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => 0x009e,

        /// The `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5288>
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => 0x009f,

        /// The `TLS_DHE_PSK_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => 0x00aa,

        /// The `TLS_DHE_PSK_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => 0x00ab,

        /// The `TLS_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8446>
        TLS13_AES_128_GCM_SHA256 => 0x1301,

        /// The `TLS_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8446>
        TLS13_AES_256_GCM_SHA384 => 0x1302,

        /// The `TLS_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8446>
        TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,

        /// The `TLS_AES_128_CCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8446>
        TLS13_AES_128_CCM_SHA256 => 0x1304,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,

        /// The `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,

        /// The `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,

        /// The `TLS_DHE_RSA_WITH_AES_128_CCM` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_RSA_WITH_AES_128_CCM => 0xc09e,

        /// The `TLS_DHE_RSA_WITH_AES_256_CCM` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_RSA_WITH_AES_256_CCM => 0xc09f,

        /// The `TLS_DHE_PSK_WITH_AES_128_CCM` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_PSK_WITH_AES_128_CCM => 0xc0a6,

        /// The `TLS_DHE_PSK_WITH_AES_256_CCM` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_PSK_WITH_AES_256_CCM => 0xc0a7,

        /// The `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,

        /// The `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,

        /// The `TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xccaa,

        /// The `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccac,

        /// The `TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccad,

        /// The `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8442>
        TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => 0xd001,

        /// The `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8442>
        TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => 0xd002,

        /// The `TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256` cipher suite.  Recommended=Y.  Defined in
        /// <https://www.iana.org/go/rfc8442>
        TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => 0xd005,

    !Debug:
        /// The `TLS_RSA_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_RSA_WITH_AES_128_CBC_SHA => 0x002f,

        /// The `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,

        /// The `TLS_RSA_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,

        /// The `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,

        /// The `TLS_RSA_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003c,

        /// The `TLS_RSA_WITH_AES_256_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003d,

        /// The `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => 0x0067,

        /// The `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5246>
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => 0x006b,

        /// The `TLS_PSK_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_PSK_WITH_AES_128_CBC_SHA => 0x008c,

        /// The `TLS_PSK_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_PSK_WITH_AES_256_CBC_SHA => 0x008d,

        /// The `TLS_DHE_PSK_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA => 0x0090,

        /// The `TLS_DHE_PSK_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA => 0x0091,

        /// The `TLS_RSA_PSK_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA => 0x0094,

        /// The `TLS_RSA_PSK_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc4279>
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA => 0x0095,

        /// The `TLS_RSA_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5288>
        TLS_RSA_WITH_AES_128_GCM_SHA256 => 0x009c,

        /// The `TLS_RSA_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5288>
        TLS_RSA_WITH_AES_256_GCM_SHA384 => 0x009d,

        /// The `TLS_PSK_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_PSK_WITH_AES_128_GCM_SHA256 => 0x00a8,

        /// The `TLS_PSK_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_PSK_WITH_AES_256_GCM_SHA384 => 0x00a9,

        /// The `TLS_RSA_PSK_WITH_AES_128_GCM_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => 0x00ac,

        /// The `TLS_RSA_PSK_WITH_AES_256_GCM_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => 0x00ad,

        /// The `TLS_PSK_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_PSK_WITH_AES_128_CBC_SHA256 => 0x00ae,

        /// The `TLS_PSK_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_PSK_WITH_AES_256_CBC_SHA384 => 0x00af,

        /// The `TLS_DHE_PSK_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => 0x00b2,

        /// The `TLS_DHE_PSK_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => 0x00b3,

        /// The `TLS_RSA_PSK_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => 0x00b6,

        /// The `TLS_RSA_PSK_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5487>
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => 0x00b7,

        /// The `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5746>
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,

        /// The `TLS_AES_128_CCM_8_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8446>
        TLS13_AES_128_CCM_8_SHA256 => 0x1305,

        /// The `TLS_FALLBACK_SCSV` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7507>
        TLS_FALLBACK_SCSV => 0x5600,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8422>
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8422>
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,

        /// The `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8422>
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,

        /// The `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8422>
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,

        /// The `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,

        /// The `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5289>
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,

        /// The `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5489>
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => 0xc035,

        /// The `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5489>
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => 0xc036,

        /// The `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5489>
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => 0xc037,

        /// The `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc5489>
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => 0xc038,

        /// The `TLS_RSA_WITH_AES_128_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_RSA_WITH_AES_128_CCM => 0xc09c,

        /// The `TLS_RSA_WITH_AES_256_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_RSA_WITH_AES_256_CCM => 0xc09d,

        /// The `TLS_RSA_WITH_AES_128_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_RSA_WITH_AES_128_CCM_8 => 0xc0a0,

        /// The `TLS_RSA_WITH_AES_256_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_RSA_WITH_AES_256_CCM_8 => 0xc0a1,

        /// The `TLS_DHE_RSA_WITH_AES_128_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_RSA_WITH_AES_128_CCM_8 => 0xc0a2,

        /// The `TLS_DHE_RSA_WITH_AES_256_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_DHE_RSA_WITH_AES_256_CCM_8 => 0xc0a3,

        /// The `TLS_PSK_WITH_AES_128_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_WITH_AES_128_CCM => 0xc0a4,

        /// The `TLS_PSK_WITH_AES_256_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_WITH_AES_256_CCM => 0xc0a5,

        /// The `TLS_PSK_WITH_AES_128_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_WITH_AES_128_CCM_8 => 0xc0a8,

        /// The `TLS_PSK_WITH_AES_256_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_WITH_AES_256_CCM_8 => 0xc0a9,

        /// The `TLS_PSK_DHE_WITH_AES_128_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_DHE_WITH_AES_128_CCM_8 => 0xc0aa,

        /// The `TLS_PSK_DHE_WITH_AES_256_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc6655>
        TLS_PSK_DHE_WITH_AES_256_CCM_8 => 0xc0ab,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_128_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7251>
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM => 0xc0ac,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_256_CCM` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7251>
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM => 0xc0ad,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7251>
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => 0xc0ae,

        /// The `TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7251>
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => 0xc0af,

        /// The `TLS_SHA256_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc9150>
        TLS_SHA256_SHA256 => 0xc0b4,

        /// The `TLS_SHA384_SHA384` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc9150>
        TLS_SHA384_SHA384 => 0xc0b5,

        /// The `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccab,

        /// The `TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc7905>
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccae,

        /// The `TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256` cipher suite.  Recommended=N.  Defined in
        /// <https://www.iana.org/go/rfc8442>
        TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 => 0xd003,
    }
}

enum_builder! {
    /// The `SignatureScheme` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u16)]
    pub enum SignatureScheme {
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        RSA_PKCS1_SHA256 => 0x0401,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,
        RSA_PSS_SHA512 => 0x0806,
        ED25519 => 0x0807,
        ED448 => 0x0808,
        // https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-00#name-iana-considerations
        ML_DSA_44 => 0x0904,
        ML_DSA_65 => 0x0905,
        ML_DSA_87 => 0x0906,
    }
}

impl SignatureScheme {
    pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
        match *self {
            Self::RSA_PKCS1_SHA1
            | Self::RSA_PKCS1_SHA256
            | Self::RSA_PKCS1_SHA384
            | Self::RSA_PKCS1_SHA512
            | Self::RSA_PSS_SHA256
            | Self::RSA_PSS_SHA384
            | Self::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
            Self::ECDSA_SHA1_Legacy
            | Self::ECDSA_NISTP256_SHA256
            | Self::ECDSA_NISTP384_SHA384
            | Self::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ECDSA,
            Self::ED25519 => SignatureAlgorithm::ED25519,
            Self::ED448 => SignatureAlgorithm::ED448,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }

    /// Whether a particular `SignatureScheme` is allowed for TLS protocol signatures
    /// in TLS1.3.
    ///
    /// This prevents (eg) RSA_PKCS1_SHA256 being offered or accepted, even if our
    /// verifier supports it for other protocol versions.
    ///
    /// See RFC8446 s4.2.3: <https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3>
    ///
    /// This is a denylist so that newly-allocated `SignatureScheme`s values are
    /// allowed in TLS1.3 by default.
    pub(crate) fn supported_in_tls13(&self) -> bool {
        let [hash, sign] = self.to_array();

        // This covers both disallowing SHA1 items in `SignatureScheme`, and
        // old hash functions.  See the section beginning "Legacy algorithms:"
        // and item starting "In TLS 1.2, the extension contained hash/signature
        // pairs" in RFC8446 section 4.2.3.
        match HashAlgorithm::from(hash) {
            HashAlgorithm::NONE
            | HashAlgorithm::MD5
            | HashAlgorithm::SHA1
            | HashAlgorithm::SHA224 => return false,
            _ => (),
        };

        // RSA-PKCS1 is also disallowed for TLS1.3, see the section beginning
        // "RSASSA-PKCS1-v1_5 algorithms:" in RFC8446 section 4.2.3.
        //
        // (nb. SignatureAlgorithm::RSA is RSA-PKCS1, and does not cover RSA-PSS
        // or RSAE-PSS.)
        //
        // This also covers the outlawing of DSA mentioned elsewhere in 4.2.3.
        !matches!(
            SignatureAlgorithm::from(sign),
            SignatureAlgorithm::Anonymous | SignatureAlgorithm::RSA | SignatureAlgorithm::DSA
        )
    }
}

enum_builder! {
    /// The `HashAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum HashAlgorithm {
        NONE => 0x00,
        MD5 => 0x01,
        SHA1 => 0x02,
        SHA224 => 0x03,
        SHA256 => 0x04,
        SHA384 => 0x05,
        SHA512 => 0x06,
    }
}

impl HashAlgorithm {
    /// Returns the hash of the empty input.
    ///
    /// This returns `None` for some hash algorithms, so the caller
    /// should be prepared to do the computation themselves in this case.
    pub(crate) fn hash_for_empty_input(&self) -> Option<hash::Output> {
        match self {
            Self::SHA256 => Some(hash::Output::new(
                b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\
                  \x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\
                  \x27\xae\x41\xe4\x64\x9b\x93\x4c\
                  \xa4\x95\x99\x1b\x78\x52\xb8\x55",
            )),
            Self::SHA384 => Some(hash::Output::new(
                b"\x38\xb0\x60\xa7\x51\xac\x96\x38\
                  \x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\
                  \x21\xfd\xb7\x11\x14\xbe\x07\x43\
                  \x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\
                  \x27\x4e\xde\xbf\xe7\x6f\x65\xfb\
                  \xd5\x1a\xd2\xf1\x48\x98\xb9\x5b",
            )),
            _ => None,
        }
    }
}

enum_builder! {
    /// The `SignatureAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognized ordinals.
    #[repr(u8)]
    pub enum SignatureAlgorithm {
        Anonymous => 0x00,
        RSA => 0x01,
        DSA => 0x02,
        ECDSA => 0x03,
        ED25519 => 0x07,
        ED448 => 0x08,
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
    use crate::msgs::enums::tests::{test_enum8, test_enum8_display, test_enum16};

    #[test]
    fn test_enums() {
        test_enum8::<HashAlgorithm>(HashAlgorithm::NONE, HashAlgorithm::SHA512);
        test_enum8::<SignatureAlgorithm>(SignatureAlgorithm::Anonymous, SignatureAlgorithm::ECDSA);
        test_enum8::<ContentType>(ContentType::ChangeCipherSpec, ContentType::Heartbeat);
        test_enum8::<HandshakeType>(HandshakeType::HelloRequest, HandshakeType::MessageHash);
        test_enum8_display::<AlertDescription>(
            AlertDescription::CloseNotify,
            AlertDescription::EncryptedClientHelloRequired,
        );
        test_enum16::<CertificateCompressionAlgorithm>(
            CertificateCompressionAlgorithm::Zlib,
            CertificateCompressionAlgorithm::Zstd,
        );
        test_enum8::<CertificateType>(CertificateType::X509, CertificateType::RawPublicKey);
    }

    #[test]
    fn tls13_signature_restrictions() {
        // rsa-pkcs1 denied
        assert!(!SignatureScheme::RSA_PKCS1_SHA1.supported_in_tls13());
        assert!(!SignatureScheme::RSA_PKCS1_SHA256.supported_in_tls13());
        assert!(!SignatureScheme::RSA_PKCS1_SHA384.supported_in_tls13());
        assert!(!SignatureScheme::RSA_PKCS1_SHA512.supported_in_tls13());

        // dsa denied
        assert!(!SignatureScheme::from(0x0201).supported_in_tls13());
        assert!(!SignatureScheme::from(0x0202).supported_in_tls13());
        assert!(!SignatureScheme::from(0x0203).supported_in_tls13());
        assert!(!SignatureScheme::from(0x0204).supported_in_tls13());
        assert!(!SignatureScheme::from(0x0205).supported_in_tls13());
        assert!(!SignatureScheme::from(0x0206).supported_in_tls13());

        // common
        assert!(SignatureScheme::ED25519.supported_in_tls13());
        assert!(SignatureScheme::ED448.supported_in_tls13());
        assert!(SignatureScheme::RSA_PSS_SHA256.supported_in_tls13());
        assert!(SignatureScheme::RSA_PSS_SHA384.supported_in_tls13());
        assert!(SignatureScheme::RSA_PSS_SHA512.supported_in_tls13());

        // rsa_pss_rsae_*
        assert!(SignatureScheme::from(0x0804).supported_in_tls13());
        assert!(SignatureScheme::from(0x0805).supported_in_tls13());
        assert!(SignatureScheme::from(0x0806).supported_in_tls13());

        // ecdsa_brainpool*
        assert!(SignatureScheme::from(0x081a).supported_in_tls13());
        assert!(SignatureScheme::from(0x081b).supported_in_tls13());
        assert!(SignatureScheme::from(0x081c).supported_in_tls13());
    }
}
