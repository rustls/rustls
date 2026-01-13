//! This is a simple example demonstrating how to use Encrypted Client Hello (ECH) with
//! rustls and hickory-dns.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! It should be invoked providing the outer hostname you will make the initial connection
//! to, and then the inner hostname being protected with ECH. Example usage:
//! ```text
//! cargo run --package rustls-examples --bin ech-client -- \
//!   --host min-ng.test.defo.ie \
//!   --path "echstat.php?format=json" \
//!    public.test.defo.ie \
//!    min-ng.test.defo.ie
//! ```
//!
//! This will perform a DNS-over-HTTPS lookup for the "min-ng.test.defo.ie" server's ECH config.
//!
//! Afterward, a TLS connection will be made to "public.test.defo.ie" using the public name
//! specified in the ECH config as the outer client hello's SNI. The protected inner client
//! hello's encrypted SNI will be "min-ng.test.defo.ie".
//!
//! Once TLS with ECH is negotiated, an HTTP request for Host: "min-ng.test.defo.ie" and the
//! path "echstat.php?format=json" will be made.
//!
//! You should observe JSON output that contains the key/value:
//! ```
//! "SSL_ECH_STATUS": "success"
//! ```

use core::error::Error;
use std::fs;
use std::io::{BufReader, Read, Write, stdout};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use clap::Parser;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ResolveError, Resolver, TokioResolver};
use log::trace;
use rustls::RootCertStore;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode, EchStatus};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName};
use rustls_aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let server_ech_configs = match (args.grease, args.ech_config) {
        (true, Some(_)) => return Err("cannot specify both --grease and --ech-config".into()),
        (true, None) => {
            Vec::new() // Force the use of the GREASE ext by skipping ECH config lookup
        }
        (false, Some(path)) => {
            vec![read_ech(&path)?]
        }
        (false, None) => {
            // Find raw ECH configs using DNS-over-HTTPS with Hickory DNS.
            let resolver_config = if args.use_cloudflare_dns {
                ResolverConfig::cloudflare_https()
            } else {
                ResolverConfig::google_https()
            };
            lookup_ech_configs(
                &Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
                    .build(),
                &args.inner_hostname,
                args.port,
            )
            .await?
        }
    };

    // NOTE: we defer setting up env_logger and setting the trace default filter level until
    //       after doing the DNS-over-HTTPS lookup above - we don't want to muddy the output
    //       with the rustls debug logs from the lookup.
    env_logger::Builder::new()
        .parse_filters("trace")
        .init();

    let ech_mode = match server_ech_configs.is_empty() {
        false => EchMode::from(
            server_ech_configs
                .into_iter()
                .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
                .ok_or("no supported ECH configs")?,
        ),
        true => {
            let (public_key, _) = GREASE_HPKE_SUITE.generate_key_pair()?;
            EchMode::from(EchGreaseConfig::new(GREASE_HPKE_SUITE, public_key))
        }
    };

    let root_store = match args.cafile {
        Some(file) => {
            let mut root_store = RootCertStore::empty();
            root_store.add_parsable_certificates(
                CertificateDer::pem_file_iter(file)
                    .expect("Cannot open CA file")
                    .map(|result| result.unwrap()),
            );
            root_store
        }
        None => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        },
    };

    // Construct a rustls client config with a TLS1.3-only provider, and ECH enabled.
    let mut config = rustls::ClientConfig::builder(rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER.into())
        .with_ech(ech_mode)
        .with_root_certificates(root_store)
        .with_no_client_auth()?;

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    let config = Arc::new(config);

    // The "inner" SNI that we're really trying to reach.
    let server_name: ServerName<'static> = args.inner_hostname.clone().try_into()?;

    for i in 0..args.num_reqs {
        trace!("\nRequest {} of {}", i + 1, args.num_reqs);
        let mut conn = rustls::ClientConnection::new(config.clone(), server_name.clone())?;
        // The "outer" server that we're connecting to.
        let sock_addr = (args.outer_hostname.as_str(), args.port)
            .to_socket_addrs()?
            .next()
            .ok_or("cannot resolve hostname")?;
        let mut sock = TcpStream::connect(sock_addr)?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            args.path,
            args.host
                .as_ref()
                .unwrap_or(&args.inner_hostname),
        );
        dbg!(&request);
        tls.write_all(request.as_bytes())?;
        assert!(!tls.conn.is_handshaking());
        assert_eq!(
            tls.conn.ech_status(),
            match args.grease {
                true => EchStatus::Grease,
                false => EchStatus::Accepted,
            }
        );
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext)?;
        stdout().write_all(&plaintext)?;
    }
    Ok(())
}

/// Connects to the TLS server at hostname:PORT.  The default PORT
/// is 443. If an ECH config can be fetched for hostname using
/// DNS-over-HTTPS, ECH is enabled. Otherwise, a placeholder ECH
/// extension is sent for anti-ossification testing.
///
/// Example:
///   ech-client --host defo.ie defo.ie www.defo.ie
#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    /// Connect to this TCP port.
    #[clap(short, long, default_value = "443")]
    port: u16,

    /// Read root certificates from this file.
    ///
    /// If --cafile is not supplied, a built-in set of CA certificates
    /// are used from the webpki-roots crate.
    #[clap(long)]
    cafile: Option<String>,

    /// HTTP GET this PATH.
    #[clap(long, default_value = "ech-check.php")]
    path: String,

    /// HTTP HOST to use for GET request (defaults to value of inner-hostname).
    #[clap(long)]
    host: Option<String>,

    /// Use Google DNS for the DNS-over-HTTPS lookup (default).
    #[clap(long, group = "dns")]
    use_google_dns: bool,
    /// Use Cloudflare DNS for the DNS-over-HTTPS lookup.
    #[clap(long, group = "dns")]
    use_cloudflare_dns: bool,

    /// Skip looking up an ECH config and send a GREASE placeholder.
    #[clap(long)]
    grease: bool,

    /// Skip looking up an ECH config and read it from the provided file (in binary TLS encoding).
    #[clap(long)]
    ech_config: Option<String>,

    /// Number of requests to make.
    #[clap(long, default_value = "1")]
    num_reqs: usize,

    /// Outer hostname.
    outer_hostname: String,

    /// Inner hostname.
    inner_hostname: String,
}

/// Collect up all `EchConfigListBytes` found in the HTTPS record(s) for a given domain name/port.
///
/// The domain name should be the **inner** name used for Encrypted Client Hello (ECH). The
/// lookup is done using DNS-over-HTTPS to protect that inner name from being disclosed in
/// plaintext ahead of the TLS handshake that negotiates ECH for the inner name.
///
/// Returns an empty vec if no HTTPS records with ECH configs are found.
// TODO(@cpu): consider upstreaming to hickory-dns
async fn lookup_ech_configs(
    resolver: &TokioResolver,
    domain: &str,
    port: u16,
) -> Result<Vec<EchConfigListBytes<'static>>, ResolveError> {
    // For non-standard ports, lookup the ECHConfig using port-prefix naming
    // See: https://datatracker.ietf.org/doc/html/rfc9460#section-9.1
    let qname_to_lookup = match port {
        443 => domain.to_owned(),
        port => format!("_{port}._https.{domain}"),
    };

    let lookup = resolver
        .lookup(qname_to_lookup, RecordType::HTTPS)
        .await?;

    let mut ech_config_lists = Vec::new();
    for r in lookup.record_iter() {
        let RData::HTTPS(svcb) = r.data() else {
            continue;
        };

        ech_config_lists.extend(
            svcb.svc_params()
                .iter()
                .find_map(|sp| match sp {
                    (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                        Some(EchConfigListBytes::from(e.clone().0))
                    }
                    _ => None,
                }),
        )
    }

    Ok(ech_config_lists)
}

fn read_ech(path: &str) -> Result<EchConfigListBytes<'static>, Box<dyn Error>> {
    let file = fs::File::open(path).map_err(|err| format!("cannot open ECH file {path}: {err}"))?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("cannot read ECH file {path}: {err}"))?;
    Ok(EchConfigListBytes::from(bytes))
}

/// A HPKE suite to use for GREASE ECH.
///
/// A real implementation should vary this suite across all of the suites that are supported.
static GREASE_HPKE_SUITE: &dyn Hpke = rustls_aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
