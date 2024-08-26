//! This is a simple example demonstrating how to use Encrypted Client Hello (ECH) with
//! rustls and hickory-dns.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! Example usage:
//! ```
//! cargo run --package rustls-examples --bin ech-client -- --host defo.ie defo.ie www.defo.ie
//! ```
//!
//! This will perform a DNS-over-HTTPS lookup for the defo.ie ECH config, using it to determine
//! the plaintext SNI to send to the server. The protected encrypted SNI will be "www.defo.ie".
//! An HTTP request for Host: defo.ie will be made once the handshake completes. You should
//! observe output that contains:
//! ```
//!   <p>SSL_ECH_OUTER_SNI: cover.defo.ie <br />
//!   SSL_ECH_INNER_SNI: www.defo.ie <br />
//!   SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
//!   </p>
//! ```

use std::fs;
use std::io::{stdout, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use docopt::Docopt;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use log::trace;
use rustls::client::{EchConfig, EchGreaseConfig, EchStatus};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use serde_derive::Deserialize;

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let port = args.flag_port.unwrap_or(443);

    // Find raw ECH configs using DNS-over-HTTPS with Hickory DNS.
    let resolver_config = if args.flag_cloudflare_dns {
        ResolverConfig::cloudflare_https()
    } else {
        ResolverConfig::google_https()
    };
    let resolver = Resolver::new(resolver_config, ResolverOpts::default()).unwrap();
    let server_ech_config = match args.flag_grease {
        true => None, // Force the use of the GREASE ext by skipping ECH config lookup
        false => match args.flag_ech_config {
            Some(path) => Some(read_ech(&path)),
            None => lookup_ech_configs(&resolver, &args.arg_outer_hostname, port),
        },
    };

    // NOTE: we defer setting up env_logger and setting the trace default filter level until
    //       after doing the DNS-over-HTTPS lookup above - we don't want to muddy the output
    //       with the rustls debug logs from the lookup.
    env_logger::Builder::new()
        .parse_filters("trace")
        .init();

    let ech_mode = match server_ech_config {
        Some(ech_config_list) => EchConfig::new(ech_config_list, ALL_SUPPORTED_SUITES)
            .unwrap()
            .into(),
        None => {
            let (public_key, _) = GREASE_HPKE_SUITE
                .generate_key_pair()
                .unwrap();
            EchGreaseConfig::new(GREASE_HPKE_SUITE, public_key).into()
        }
    };

    let root_store = match args.flag_cafile {
        Some(file) => {
            let mut root_store = RootCertStore::empty();
            let certfile = fs::File::open(file).expect("Cannot open CA file");
            let mut reader = BufReader::new(certfile);
            root_store.add_parsable_certificates(
                rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
            );
            root_store
        }
        None => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        },
    };

    // Construct a rustls client config with a custom provider, and ECH enabled.
    let mut config =
        rustls::ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
            .with_ech(ech_mode)
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    let config = Arc::new(config);

    // The "inner" SNI that we're really trying to reach.
    let server_name: ServerName<'static> = args
        .arg_inner_hostname
        .clone()
        .try_into()
        .unwrap();

    for i in 0..args.flag_num_reqs {
        trace!("\nRequest {} of {}", i + 1, args.flag_num_reqs);
        let mut conn = rustls::ClientConnection::new(config.clone(), server_name.clone()).unwrap();
        // The "outer" server that we're connecting to.
        let sock_addr = (args.arg_outer_hostname.as_str(), port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut sock = TcpStream::connect(sock_addr).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        let request =
            format!(
                "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
                args.flag_path.clone()
                    .unwrap_or("ech-check.php".to_owned()),
                args.flag_host.as_ref().unwrap_or(&args.arg_inner_hostname),
            );
        dbg!(&request);
        tls.write_all(request.as_bytes())
            .unwrap();
        assert!(!tls.conn.is_handshaking());
        assert_eq!(
            tls.conn.ech_status(),
            match args.flag_grease {
                true => EchStatus::Grease,
                false => EchStatus::Accepted,
            }
        );
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        stdout().write_all(&plaintext).unwrap();
    }
}

const USAGE: &str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443. If an ECH config can be fetched for hostname using
DNS-over-HTTPS, ECH is enabled. Otherwise, a placeholder ECH
extension is sent for anti-ossification testing.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  ech-client [options] <outer-hostname> <inner-hostname>
  ech-client (--version | -v)
  ech-client (--help | -h)

Example:
  ech-client --host defo.ie defo.ie www.defo.ie

Options:
    -p, --port PORT       Connect to PORT [default: 443].
    --cafile CAFILE       Read root certificates from CAFILE.
    --path PATH           HTTP GET this PATH [default: ech-check.php].
    --host HOST           HTTP HOST to use for GET request (defaults to value of inner-hostname).
    --google-dns          Use Google DNS for the DNS-over-HTTPS lookup [default].
    --cloudflare-dns      Use Cloudflare DNS for the DNS-over-HTTPS lookup.
    --grease              Skip looking up an ECH config and send a GREASE placeholder.
    --ech-config ECHFILE  Skip looking up an ECH config and read it from the provided file (in binary TLS encoding).
    --num-reqs NUM        Number of requests to make [default: 1].
    --version, -v         Show tool version.
    --help, -h            Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_cafile: Option<String>,
    flag_path: Option<String>,
    flag_host: Option<String>,
    #[allow(dead_code)] // implied default
    flag_google_dns: bool,
    flag_cloudflare_dns: bool,
    flag_grease: bool,
    flag_ech_config: Option<String>,
    flag_num_reqs: usize,
    arg_outer_hostname: String,
    arg_inner_hostname: String,
}

// TODO(@cpu): consider upstreaming to hickory-dns
fn lookup_ech_configs(
    resolver: &Resolver,
    domain: &str,
    port: u16,
) -> Option<pki_types::EchConfigListBytes<'static>> {
    // For non-standard ports, lookup the ECHConfig using port-prefix naming
    // See: https://datatracker.ietf.org/doc/html/rfc9460#section-9.1
    let qname_to_lookup = match port {
        443 => domain.to_owned(),
        port => format!("_{port}._https.{domain}"),
    };

    resolver
        .lookup(qname_to_lookup, RecordType::HTTPS)
        .ok()?
        .record_iter()
        .find_map(|r| match r.data() {
            RData::HTTPS(svcb) => svcb
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
        .map(Into::into)
}

fn read_ech(path: &str) -> pki_types::EchConfigListBytes<'static> {
    let file = fs::File::open(path).unwrap_or_else(|_| panic!("Cannot open ECH file: {path}"));
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("Cannot read ECH file: {path}"));
    bytes.into()
}

/// A HPKE suite to use for GREASE ECH.
///
/// A real implementation should vary this suite across all of the suites that are supported.
static GREASE_HPKE_SUITE: &dyn Hpke = aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
