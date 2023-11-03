//! This is an example to show how to modify ClientHello to resist
//! TLS fingerprinting techniques.

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::ClientHelloCamouflager;
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use rustls::internal::msgs::handshake::ClientExtension::*;
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientSessionTicket, ProtocolName, UnknownExtension,
};
use rustls::CipherSuite::*;
use rustls::{CipherSuite, NamedGroup, ProtocolVersion};
use rustls::{RootCertStore, SignatureScheme};

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec!["http/1.1".as_bytes().to_vec()];

    struct Chrome102;
    impl ClientHelloCamouflager for Chrome102 {
        fn transform_cipher_suites(&self, _cipher_suites: Vec<CipherSuite>) -> Vec<CipherSuite> {
            vec![
                CipherSuite::Unknown(0x0a0a), // GREASE
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ]
        }

        fn transform_extensions(&self, extensions: Vec<ClientExtension>) -> Vec<ClientExtension> {
            let sni = extensions
                .iter()
                .find(|ext| matches!(ext, ClientExtension::ServerName(_)))
                .unwrap()
                .clone();
            let keyshare = extensions
                .iter()
                .find(|ext| matches!(ext, ClientExtension::KeyShare(_)))
                .unwrap()
                .clone();
            vec![
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(0x9a9a),
                    payload: Payload::new(vec![]),
                }),
                sni,
                // ExtendedMasterSecretRequest,
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(23),
                    payload: Payload::new(vec![]),
                }),
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::RenegotiationInfo,
                    payload: Payload::new(vec![0]),
                }),
                NamedGroups(vec![
                    NamedGroup::Unknown(0x7a7a),
                    NamedGroup::X25519,
                    NamedGroup::secp256r1,
                    NamedGroup::secp384r1,
                ]),
                EcPointFormats(vec![ECPointFormat::Uncompressed]),
                SessionTicket(ClientSessionTicket::Request),
                Protocols(vec![
                    // ProtocolName::from("h2".as_bytes().to_vec()),
                    ProtocolName::from("http/1.1".as_bytes().to_vec()),
                ]),
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::StatusRequest,
                    payload: Payload::new(vec![1, 0, 0, 0, 0]),
                }),
                SignatureAlgorithms(vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA512,
                ]),
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::SCT,
                    payload: Payload::new(vec![]),
                }),
                keyshare,
                PresharedKeyModes(vec![PSKKeyExchangeMode::PSK_DHE_KE]),
                SupportedVersions(vec![
                    ProtocolVersion::Unknown(0x5a5a),
                    ProtocolVersion::TLSv1_3,
                    ProtocolVersion::TLSv1_2,
                ]),
                // compress_certificate, RFC 8879
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(27),
                    payload: Payload::new([0x1, 0x0, 0x2]),
                }),
                // Application Settings, not IANA assigned
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(17513),
                    payload: Payload::new([0x0, 0x3, 0x2, 68, 32]),
                }),
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Unknown(0x6a6a),
                    payload: Payload::new(vec![0]),
                }),
                ClientExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::Padding,
                    payload: Payload::new(vec![]),
                }),
            ]
        }
    }

    config.client_hello_camouflager = Some(Arc::new(Chrome102));

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "tls.peet.ws".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("tls.peet.ws:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET /api/all HTTP/1.1\r\n",
            "Host: tls.peet.ws\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
