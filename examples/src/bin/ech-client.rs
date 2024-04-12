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
use rustls::crypto::aws_lc_rs;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::RootCertStore;

fn main() {
    // Find raw ECH configs using DNS-over-HTTPS with Hickory DNS:
    let resolver = Resolver::new(ResolverConfig::google_https(), ResolverOpts::default()).unwrap();
    let ech_config_list = lookup_ech_configs(&resolver, "defo.ie");

    // NOTE: we defer setting up env_logger and setting the trace default filter level until
    //       after doing the DNS-over-HTTPS lookup above - we don't want to muddy the output
    //       with the rustls debug logs from the lookup.
    env_logger::Builder::new()
        .parse_filters("trace")
        .init();

    // Select a compatible ECH config.
    let ech_config = EchConfig::new(ech_config_list, ALL_SUPPORTED_SUITES).unwrap();

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // Construct a rustls client config with a custom provider, and ECH enabled.
    let mut config =
        rustls::ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
            .with_ech(ech_config)
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

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

// TODO(@cpu): consider upstreaming to hickory-dns
fn lookup_ech_configs(resolver: &Resolver, domain: &str) -> pki_types::EchConfigListBytes<'static> {
    resolver
        .lookup(domain, RecordType::HTTPS)
        .expect("failed to lookup HTTPS record type")
        .record_iter()
        .find_map(|r| match r.data() {
            Some(RData::HTTPS(svcb)) => svcb
                .svc_params()
                .iter()
                .find_map(|sp| match sp {
                    (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                        Some(e.clone().0)
                    }
                    _ => None,
                }),
            _ => None,
        })
        .expect("missing expected HTTPS SvcParam EchConfig record")
        .into()
}
