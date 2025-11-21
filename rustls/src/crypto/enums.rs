#![expect(non_camel_case_types)]
use crate::crypto::hash;
use crate::crypto::kx::KeyExchangeAlgorithm;
use crate::enums::ProtocolVersion;

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

    /// Returns whether this `NamedGroup` is usable for the given protocol version.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::enums::tests::{test_enum8, test_enum16};

    #[test]
    fn test_enums() {
        test_enum16::<NamedGroup>(NamedGroup::secp256r1, NamedGroup::FFDHE8192);
        test_enum8::<HashAlgorithm>(HashAlgorithm::NONE, HashAlgorithm::SHA512);
        test_enum8::<SignatureAlgorithm>(SignatureAlgorithm::Anonymous, SignatureAlgorithm::ECDSA);
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
