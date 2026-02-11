#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

#[cfg(feature = "zlib")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "zlib")]
use std::sync::Arc;

#[cfg(feature = "zlib")]
use rustls::ClientConfig;
#[cfg(feature = "zlib")]
use rustls::client::Resumption;
#[cfg(feature = "zlib")]
use rustls::crypto::{Credentials, Identity, SingleCredential};
use rustls::enums::CertificateCompressionAlgorithm;
use rustls::error::{AlertDescription, Error, InvalidMessage, PeerMisbehaved};
#[cfg(feature = "zlib")]
use rustls::pki_types::CertificateDer;
use rustls::{Connection, VecBuffer};
#[cfg(feature = "zlib")]
use rustls_test::{ClientConfigExt, make_pair_for_arc_configs};
use rustls_test::{
    ErrorFromPeer, KeyType, do_handshake, do_handshake_until_error, make_client_config,
    make_client_config_with_auth, make_pair_for_configs, make_server_config,
    make_server_config_with_mandatory_client_auth, transfer,
};

use super::provider;

#[cfg(feature = "zlib")]
#[test]
fn test_server_uses_cached_compressed_certificates() {
    static COMPRESS_COUNT: AtomicUsize = AtomicUsize::new(0);

    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&CountingCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.resumption = Resumption::disabled();

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);

    for _i in 0..10 {
        dbg!(_i);
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_buf = VecBuffer::default();
        let mut server_buf = VecBuffer::default();
        do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
        dbg!(client.handshake_kind());
    }

    assert_eq!(COMPRESS_COUNT.load(Ordering::SeqCst), 1);

    #[derive(Debug)]
    struct CountingCompressor;

    impl rustls::compress::CertCompressor for CountingCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: rustls::compress::CompressionLevel,
        ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
            dbg!(COMPRESS_COUNT.fetch_add(1, Ordering::SeqCst));
            rustls::compress::ZLIB_COMPRESSOR.compress(input, level)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[test]
fn test_server_uses_uncompressed_certificate_if_compression_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&FailingCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.cert_decompressors = vec![&NeverDecompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
}

#[test]
fn test_client_uses_uncompressed_certificate_if_compression_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&NeverDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&FailingCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
}

#[derive(Debug)]
struct FailingCompressor;

impl rustls::compress::CertCompressor for FailingCompressor {
    fn compress(
        &self,
        _input: Vec<u8>,
        _level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        println!("compress called but doesn't work");
        Err(rustls::compress::CompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct NeverDecompressor;

impl rustls::compress::CertDecompressor for NeverDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        panic!("NeverDecompressor::decompress should not be called");
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[cfg(feature = "zlib")]
#[test]
fn test_server_can_opt_out_of_compression_cache() {
    static COMPRESS_COUNT: AtomicUsize = AtomicUsize::new(0);

    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&AlwaysInteractiveCompressor];
    server_config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.resumption = Resumption::disabled();

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);

    for _i in 0..10 {
        dbg!(_i);
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        let mut client_buf = VecBuffer::default();
        let mut server_buf = VecBuffer::default();
        do_handshake(&mut client_buf, &mut client, &mut server_buf, &mut server);
        dbg!(client.handshake_kind());
    }

    assert_eq!(COMPRESS_COUNT.load(Ordering::SeqCst), 10);

    #[derive(Debug)]
    struct AlwaysInteractiveCompressor;

    impl rustls::compress::CertCompressor for AlwaysInteractiveCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: rustls::compress::CompressionLevel,
        ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
            dbg!(COMPRESS_COUNT.fetch_add(1, Ordering::SeqCst));
            assert_eq!(level, rustls::compress::CompressionLevel::Interactive);
            rustls::compress::ZLIB_COMPRESSOR.compress(input, level)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[test]
fn test_cert_decompression_by_client_produces_invalid_cert_payload() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config = make_server_config(KeyType::Rsa2048, &provider);
    server_config.cert_compressors = vec![&IdentityCompressor];
    let mut client_config = make_client_config(KeyType::Rsa2048, &provider);
    client_config.cert_decompressors = vec![&GarbageDecompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    assert_eq!(
        do_handshake_until_error(&mut client_buf, &mut client, &mut server_buf, &mut server),
        Err(ErrorFromPeer::Client(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut client, &mut server_buf);
    assert_eq!(
        server.process_new_packets(&mut server_buf),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[test]
fn test_cert_decompression_by_server_produces_invalid_cert_payload() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&GarbageDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&IdentityCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    assert_eq!(
        do_handshake_until_error(&mut client_buf, &mut client, &mut server_buf, &mut server),
        Err(ErrorFromPeer::Server(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut server, &mut client_buf);
    assert_eq!(
        client.process_new_packets(&mut client_buf),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[test]
fn test_cert_decompression_by_server_fails() {
    let provider = provider::DEFAULT_PROVIDER;
    let mut server_config =
        make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);
    server_config.cert_decompressors = vec![&FailingDecompressor];
    let mut client_config = make_client_config_with_auth(KeyType::Rsa2048, &provider);
    client_config.cert_compressors = vec![&IdentityCompressor];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    assert_eq!(
        do_handshake_until_error(&mut client_buf, &mut client, &mut server_buf, &mut server),
        Err(ErrorFromPeer::Server(Error::PeerMisbehaved(
            PeerMisbehaved::InvalidCertCompression
        )))
    );
    transfer(&mut server, &mut client_buf);
    assert_eq!(
        client.process_new_packets(&mut client_buf),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[cfg(feature = "zlib")]
#[test]
fn test_cert_decompression_by_server_would_result_in_excessively_large_cert() {
    let provider = provider::DEFAULT_PROVIDER;
    let server_config = make_server_config_with_mandatory_client_auth(KeyType::Rsa2048, &provider);

    let big_cert = CertificateDer::from(vec![0u8; 0xffff]);
    let key = provider::DEFAULT_PROVIDER
        .key_provider
        .load_private_key(KeyType::Rsa2048.client_key())
        .unwrap();
    let big_cert_and_key = Credentials::new_unchecked(
        Arc::new(Identity::from_cert_chain(vec![big_cert]).unwrap()),
        key,
    );
    let client_config = ClientConfig::builder(Arc::new(provider))
        .add_root_certs(KeyType::Rsa2048)
        .with_client_credential_resolver(Arc::new(SingleCredential::from(big_cert_and_key)))
        .unwrap();

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    let mut client_buf = VecBuffer::default();
    let mut server_buf = VecBuffer::default();
    assert_eq!(
        do_handshake_until_error(&mut client_buf, &mut client, &mut server_buf, &mut server),
        Err(ErrorFromPeer::Server(Error::InvalidMessage(
            InvalidMessage::CertificatePayloadTooLarge
        )))
    );
    transfer(&mut server, &mut client_buf);
    assert_eq!(
        client.process_new_packets(&mut client_buf),
        Err(Error::AlertReceived(AlertDescription::BadCertificate))
    );
}

#[derive(Debug)]
struct GarbageDecompressor;

impl rustls::compress::CertDecompressor for GarbageDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        output.fill(0xff);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct FailingDecompressor;

impl rustls::compress::CertDecompressor for FailingDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        Err(rustls::compress::DecompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
struct IdentityCompressor;

impl rustls::compress::CertCompressor for IdentityCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        Ok(input.to_vec())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}
