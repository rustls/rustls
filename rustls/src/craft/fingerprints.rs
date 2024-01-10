#![allow(missing_docs)]

use super::*;
use paste::paste;

macro_rules! define_fingerprint {
    ($fingerprint_name:ident { shuffle($extensions:expr), $cipher:expr }) => {
        define_fingerprint!($fingerprint_name, $extensions, true, $cipher);
    };
    ($fingerprint_name:ident { $extensions:expr, $cipher:expr }) => {
        define_fingerprint!($fingerprint_name, $extensions, false, $cipher);
    };
    ($fingerprint_name:ident, $extensions:expr, $shuffle_extensions:expr, $cipher:expr) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[dynamic]
            static [<$fingerprint_name _EXT_NO_ALPN>]: Vec<ExtensionSpec> = {
                use ExtensionSpec::*;
                ($extensions)
                    .iter()
                    .filter(|v| match v {
                        Craft(CraftExtension::Protocols(..)) => false,
                        _ => true,
                    })
                    .map(|v| v.clone())
                    .collect()
            };

            #[allow(non_camel_case_types)]
            #[dynamic]
            static [<$fingerprint_name _EXT_ALPN_HTTP1>]: Vec<ExtensionSpec> = {
                use ExtensionSpec::*;
                ($extensions)
                    .iter()
                    .map(|v| match v {
                        Craft(CraftExtension::Protocols(_)) => Craft(CraftExtension::Protocols(&[b"http/1.1"])),
                        v => v.clone(),
                    })
                    .collect()
            };

            #[allow(non_camel_case_types)]
            #[dynamic]
            /// Represents a set of [`Fingerprint`] configurations, each tailored for different ALPN extensions.
            ///
            /// Variants:
            /// - `main`: The default configuration for HTTP/2 (h2) clients, designed to emulate typical browser behavior.
            /// - `test_alpn_http1`: A configuration for testing HTTP/1 clients, with appropriate ALPN settings.
            /// - `test_no_alpn`: A configuration for testing clients that do not use ALPN, including HTTP/1 or non-HTTP clients.
            pub static $fingerprint_name: FingerprintSet = FingerprintSet {
                main: Fingerprint { extensions: $extensions, cipher: $cipher, shuffle_extensions: $shuffle_extensions },
                test_alpn_http1: Fingerprint { extensions: &[<$fingerprint_name _EXT_ALPN_HTTP1>], cipher: $cipher, shuffle_extensions: $shuffle_extensions },
                test_no_alpn: Fingerprint { extensions: &[<$fingerprint_name _EXT_NO_ALPN>], cipher: $cipher, shuffle_extensions: $shuffle_extensions },
            };
        }
    };
}

/// The default ocsp request of browsers
pub static OCSP_REQ: CertificateStatusRequest =
    CertificateStatusRequest::Ocsp(OcspCertificateStatusRequest {
        responder_ids: vec![],
        extensions: PayloadU16(vec![]),
    });

/// The signature algorithms of chrome 108
pub static CHROME_108_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

#[dynamic]
/// The extension list of chrome 108
pub static CHROME_108_EXT: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Craft(CraftExtension::Grease1),
        Keep(Must(ExtensionType::ServerName)),
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            Grease,
            GreaseOrCurve::T(NamedGroup::X25519),
            GreaseOrCurve::T(NamedGroup::secp256r1),
            GreaseOrCurve::T(NamedGroup::secp384r1),
        ])),
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        Keep(OrDefault(
            ExtensionType::SessionTicket,
            ClientExtension::SessionTicket(crate::msgs::handshake::ClientSessionTicket::Offer(
                Payload(vec![]),
            )),
        )),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Rustls(ClientExtension::CertificateStatusRequest(OCSP_REQ.clone())),
        Rustls(ClientExtension::SignatureAlgorithms(
            CHROME_108_SIGNATURE_ALGO.to_vec(),
        )),
        Craft(CraftExtension::SignedCertificateTimestamp),
        Craft(CraftExtension::KeyShare(&[
            Grease,
            GreaseOrCurve::T(NamedGroup::X25519),
        ])),
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        Craft(CraftExtension::SupportedVersions(&[
            Grease,
            GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
            GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
        ])),
        Keep(Optional(ExtensionType::Cookie)),
        crate::cert_compress_ext!(crate::CertificateCompressionAlgorithm::Brotli),
        Craft(CraftExtension::FakeApplicationSettings),
        Craft(CraftExtension::Grease2),
        Craft(CraftExtension::Padding),
        Keep(Optional(ExtensionType::PreSharedKey)),
    ]
};

/// The cipher list of chrome 108
///
/// This list includes \*CBC* and \*TLS_RSA* ciphers for correctness, even though they are not supported by Rustls due to security concerns and deprecation. As these older cipher suites are seldom used in modern secure communications, their absence in Rustls is unlikely to cause compatibility issues.
#[dynamic]
pub static CHROME_CIPHER: Vec<GreaseOrCipher> = {
    use CipherSuite::*;
    vec![
        GreaseOrCipher::Grease,
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
        TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_RSA_WITH_AES_256_CBC_SHA.into(),
    ]
};

define_fingerprint!(CHROME_108 { &CHROME_108_EXT, &CHROME_CIPHER });
define_fingerprint!(CHROME_112 { shuffle(&CHROME_108_EXT), &CHROME_CIPHER });

/// The cipher list of Safari 17.1
///
/// This list includes \*CBC* and \*TLS_RSA* ciphers for correctness, even though they are not supported by Rustls due to security concerns and deprecation. As these older cipher suites are seldom used in modern secure communications, their absence in Rustls is unlikely to cause compatibility issues.
#[dynamic]
pub static SAFARI_17_1_CIPHERS: Vec<GreaseOrCipher> = {
    use CipherSuite::*;
    vec![
        GreaseOrCipher::Grease,
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        TLS_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.into(),
        TLS_RSA_WITH_3DES_EDE_CBC_SHA.into(),
    ]
};

/// The signature algorithm list of Safari 17.1
pub static SAFARI_17_1_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];

/// The extension list of Safari 17.1
#[dynamic]
pub static SAFARI_17_1_EXT: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Craft(CraftExtension::Grease1),
        Keep(Must(ExtensionType::ServerName)),
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            Grease,
            GreaseOrCurve::T(NamedGroup::X25519),
            GreaseOrCurve::T(NamedGroup::secp256r1),
            GreaseOrCurve::T(NamedGroup::secp384r1),
            GreaseOrCurve::T(NamedGroup::secp521r1),
        ])),
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Rustls(ClientExtension::CertificateStatusRequest(OCSP_REQ.clone())),
        Rustls(ClientExtension::SignatureAlgorithms(
            SAFARI_17_1_SIGNATURE_ALGO.to_vec(),
        )),
        Craft(CraftExtension::SignedCertificateTimestamp),
        Craft(CraftExtension::KeyShare(&[
            Grease,
            GreaseOrCurve::T(NamedGroup::X25519),
        ])),
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        Craft(CraftExtension::SupportedVersions(&[
            Grease,
            GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
            GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
            GreaseOrVersion::T(ProtocolVersion::TLSv1_1),
            GreaseOrVersion::T(ProtocolVersion::TLSv1_0),
        ])),
        Keep(Optional(ExtensionType::Cookie)),
        crate::cert_compress_ext!(crate::CertificateCompressionAlgorithm::Zlib),
        Craft(CraftExtension::Grease2),
        Craft(CraftExtension::Padding),
    ]
};

define_fingerprint!(SAFARI_17_1 { &SAFARI_17_1_EXT, &SAFARI_17_1_CIPHERS });

/// The cipher list of firefox 105
///
/// This list includes \*CBC* and \*TLS_RSA* ciphers for correctness, even though they are not supported by Rustls due to security concerns and deprecation. As these older cipher suites are seldom used in modern secure communications, their absence in Rustls is unlikely to cause compatibility issues.
#[dynamic]
pub static FIREFOX_105_CIPHERS: Vec<GreaseOrCipher> = {
    use CipherSuite::*;
    vec![
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
        TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_RSA_WITH_AES_128_CBC_SHA.into(),
        TLS_RSA_WITH_AES_256_CBC_SHA.into(),
    ]
};

/// The signature algorithm list of firefox 105
pub static FIREFOX_105_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PKCS1_SHA1,
];

/// The extension list of firefox 105
#[dynamic]
pub static FIREFOX_105_EXT: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Keep(Must(ExtensionType::ServerName)),
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            GreaseOrCurve::T(NamedGroup::X25519),
            GreaseOrCurve::T(NamedGroup::secp256r1),
            GreaseOrCurve::T(NamedGroup::secp384r1),
            GreaseOrCurve::T(NamedGroup::secp521r1),
            GreaseOrCurve::T(NamedGroup::FFDHE2048),
            GreaseOrCurve::T(NamedGroup::FFDHE3072),
        ])),
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Rustls(ClientExtension::CertificateStatusRequest(OCSP_REQ.clone())),
        Craft(CraftExtension::FakeDelegatedCredentials(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ])),
        Craft(CraftExtension::KeyShare(&[
            GreaseOrCurve::T(NamedGroup::X25519),
            GreaseOrCurve::T(NamedGroup::secp256r1),
        ])),
        Craft(CraftExtension::SupportedVersions(&[
            GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
            GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
        ])),
        Rustls(ClientExtension::SignatureAlgorithms(
            FIREFOX_105_SIGNATURE_ALGO.to_vec(),
        )),
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        Craft(CraftExtension::FakeRecordSizeLimit(0x4001)),
        Craft(CraftExtension::Padding),
        Keep(Optional(ExtensionType::PreSharedKey)),
    ]
};

define_fingerprint!(FIREFOX_105 { &FIREFOX_105_EXT, &FIREFOX_105_CIPHERS });
