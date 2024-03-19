//! This is a simple example demonstrating how to use Encrypted Client Hello (ECH) with
//! rustls and hickory-dns.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use rustls::client::EchConfig;
use rustls::{version, RootCertStore};

fn main() {
    env_logger::Builder::new()
        .parse_filters("trace")
        .init();

    // Find raw ECH configs using DNS-over-HTTPS with Hickory DNS:
    let resolver = Resolver::new(ResolverConfig::google_https(), ResolverOpts::default()).unwrap();
    let ech_configs = lookup_ech(&resolver, "defo.ie");

    // Select a compatible ECH config.
    let ech_config = EchConfig::new(ech_configs, rustls_provider_example::HPKE_PROVIDER).unwrap();

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // Construct a rustls client config with a custom provider, and only TLS 1.3 support.
    let mut config =
        rustls::ClientConfig::builder_with_provider(rustls_provider_example::provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

    // Configure ECH.
    config.enable_ech(ech_config).unwrap();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    // The "inner" SNI that we're really trying to reach.
    let server_name = "www.defo.ie".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    // The "outer" server that we're connecting to.
    let mut sock = TcpStream::connect("defo.ie:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET /ech-check.php HTTP/1.1\r\n",
            "Host: defo.ie\r\n",
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

// TODO(@cpu): share code with connect test, return all configs not just first.
fn lookup_ech(resolver: &Resolver, domain: &str) -> Vec<u8> {
    resolver
        .lookup(domain, RecordType::HTTPS)
        .expect("failed to lookup HTTPS record type")
        .record_iter()
        .find_map(|r| match r.data() {
            Some(RData::HTTPS(svcb)) => svcb
                .svc_params()
                .iter()
                .find_map(|sp| match sp {
                    (SvcParamKey::EchConfig, SvcParamValue::EchConfig(e)) => Some(e.clone().0),
                    _ => None,
                }),
            _ => None,
        })
        .expect("missing expected HTTPS SvcParam EchConfig record")
}
