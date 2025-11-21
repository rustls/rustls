//! This is an example client that uses rustls for TLS, and [mio] for I/O.
//!
//! It uses command line flags to demonstrate configuring a TLS client that may:
//!  * Specify supported TLS protocol versions
//!  * Customize cipher suite selection
//!  * Perform client certificate authentication
//!  * Disable session tickets
//!  * Disable SNI
//!  * Disable certificate validation (insecure)
//!
//! See `--help` output for more details.
//!
//! You may set the `SSLKEYLOGFILE` env var when using this example to write a
//! log file with key material (insecure) for debugging purposes. See [`rustls::KeyLog`]
//! for more information.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! [mio]: https://docs.rs/mio/latest/mio/

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::{process, str};

use clap::Parser;
use mio::net::TcpStream;
use rustls::RootCertStore;
use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{CryptoProvider, Identity, aws_lc_rs as provider};
use rustls::enums::ProtocolVersion;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: ServerName<'static>,
        cfg: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn
            .writer()
            .write_all(&buf)
            .unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {error:?}");
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {err}");
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = vec![0u8; io_state.plaintext_bytes_to_read()];
            self.tls_conn
                .reader()
                .read_exact(&mut plaintext)
                .unwrap();
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

/// Connects to the TLS server at hostname:PORT.  The default PORT
/// is 443.  By default, this reads a request from stdin (to EOF)
/// before making the connection.  --http replaces this with a
/// basic HTTP GET request for /.
///
/// If --cafile is not supplied, a built-in set of CA certificates
/// are used from the webpki-roots crate.
#[derive(Debug, Parser)]
struct Args {
    /// Connect to this port
    #[clap(long, default_value = "443")]
    port: u16,

    /// Send a basic HTTP GET request for /
    #[clap(long)]
    http: bool,

    /// Emit log output
    #[clap(long)]
    verbose: bool,

    /// Disable default TLS version list, and use
    /// VERSION instead.  May be used multiple times.
    #[clap(long)]
    protover: Vec<String>,

    /// Disable default cipher suite list, and use
    /// SUITE instead.  May be used multiple times.
    #[clap(long)]
    suite: Vec<String>,

    /// Disable default key exchange list, and use KX instead. Maybe be used multiple times.
    #[clap(long)]
    key_exchange: Vec<String>,

    /// Send ALPN extension containing PROTOCOL.
    /// May be used multiple times to offer several protocols.
    #[clap(long)]
    proto: Vec<String>,

    /// Limit outgoing messages to this many bytes
    #[clap(long)]
    max_frag_size: Option<usize>,

    /// Read root certificates from this file
    #[clap(long)]
    cafile: Option<String>,

    /// Disable session ticket support
    #[clap(long)]
    no_tickets: bool,

    /// Disable server name indication support
    #[clap(long)]
    no_sni: bool,

    /// Disable certificate verification
    #[clap(long)]
    insecure: bool,

    /// Read client authentication key from KEY.
    #[clap(long)]
    auth_key: Option<String>,

    /// Read client authentication certificates from CERTS.
    /// CERTS must match up with KEY.
    #[clap(long)]
    auth_certs: Option<String>,

    /// Which hostname/address to connect to
    hostname: String,
}

impl Args {
    fn provider(&self) -> CryptoProvider {
        let kx_groups = match self.key_exchange.as_slice() {
            [] => Cow::Borrowed(provider::DEFAULT_KX_GROUPS),
            items => Cow::Owned(
                items
                    .iter()
                    .map(|kx| find_key_exchange(kx))
                    .collect::<Vec<&'static dyn SupportedKxGroup>>(),
            ),
        };

        let provider = match lookup_versions(&self.protover).as_slice() {
            [ProtocolVersion::TLSv1_2] => provider::DEFAULT_TLS12_PROVIDER,
            [ProtocolVersion::TLSv1_3] => provider::DEFAULT_TLS13_PROVIDER,
            _ => provider::DEFAULT_PROVIDER,
        };

        let provider = CryptoProvider {
            kx_groups,
            ..provider
        };

        match self.suite.as_slice() {
            [] => provider,
            _ => filter_suites(provider, &self.suite),
        }
    }
}

/// Find a key exchange with the given name
fn find_key_exchange(name: &str) -> &'static dyn SupportedKxGroup {
    for kx_group in provider::ALL_KX_GROUPS {
        let kx_name = format!("{:?}", kx_group.name()).to_lowercase();

        if kx_name == name.to_string().to_lowercase() {
            return *kx_group;
        }
    }

    panic!("cannot find key exchange with name '{name}'");
}

/// Alter `provider` to reduce the set of ciphersuites to just `suites`
fn filter_suites(mut provider: CryptoProvider, suites: &[String]) -> CryptoProvider {
    // first, check `suites` all name known suites, and will have some effect
    let known_suites = provider
        .tls12_cipher_suites
        .iter()
        .map(|cs| cs.common.suite)
        .chain(
            provider
                .tls13_cipher_suites
                .iter()
                .map(|cs| cs.common.suite),
        )
        .map(|cs| format!("{:?}", cs).to_lowercase())
        .collect::<Vec<String>>();

    for s in suites {
        if !known_suites.contains(&s.to_lowercase()) {
            panic!(
                "unsupported ciphersuite '{s}'; should be one of {known_suites}",
                known_suites = known_suites.join(", ")
            );
        }
    }

    // now discard non-named suites
    provider
        .tls12_cipher_suites
        .to_mut()
        .retain(|cs| {
            let name = format!("{:?}", cs.common.suite).to_lowercase();
            suites
                .iter()
                .any(|s| s.to_lowercase() == name)
        });
    provider
        .tls13_cipher_suites
        .to_mut()
        .retain(|cs| {
            let name = format!("{:?}", cs.common.suite).to_lowercase();
            suites
                .iter()
                .any(|s| s.to_lowercase() == name)
        });

    provider
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<ProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => ProtocolVersion::TLSv1_2,
            "1.3" => ProtocolVersion::TLSv1_3,
            _ => panic!("cannot look up version '{vname}', valid are '1.2' and '1.3'"),
        };
        if !out.contains(&version) {
            out.push(version);
        }
    }

    out
}

fn load_certs(filename: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(filename)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(filename).expect("cannot read private key file")
}

mod danger {
    use rustls::Error;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerIdentity, SignatureVerificationInput,
    };
    use rustls::crypto::{
        CryptoProvider, SignatureScheme, verify_tls12_signature, verify_tls13_signature,
    };

    #[derive(Debug)]
    pub struct NoCertificateVerification(CryptoProvider);

    impl NoCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self(provider)
        }
    }

    impl rustls::client::danger::ServerVerifier for NoCertificateVerification {
        fn verify_identity(
            &self,
            _identity: &ServerIdentity<'_>,
        ) -> Result<rustls::client::danger::PeerVerified, Error> {
            Ok(rustls::client::danger::PeerVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(input, &self.0.signature_verification_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(input, &self.0.signature_verification_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0
                .signature_verification_algorithms
                .supported_schemes()
        }

        fn request_ocsp_response(&self) -> bool {
            false
        }
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if let Some(cafile) = args.cafile.as_ref() {
        root_store.add_parsable_certificates(
            CertificateDer::pem_file_iter(cafile)
                .expect("Cannot open CA file")
                .map(|result| result.unwrap()),
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }

    let config =
        rustls::ClientConfig::builder(args.provider().into()).with_root_certificates(root_store);

    let mut config = match (&args.auth_key, &args.auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_client_auth_cert(Arc::new(Identity::from_cert_chain(certs).unwrap()), key)
                .expect("invalid client auth certs/key")
        }
        (None, None) => config.with_no_client_auth().unwrap(),
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.no_tickets {
        config.resumption = config
            .resumption
            .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOnly);
    }

    if args.no_sni {
        config.enable_sni = false;
    }

    config.alpn_protocols = args
        .proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    config.max_fragment_size = args.max_frag_size;

    if args.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
                provider::DEFAULT_PROVIDER,
            )));
    }

    Arc::new(config)
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {
    let args = Args::parse();

    if args.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let config = make_config(&args);

    let sock_addr = (args.hostname.as_str(), args.port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let sock = TcpStream::connect(sock_addr).unwrap();
    let server_name = ServerName::try_from(args.hostname.as_str())
        .expect("invalid DNS name")
        .to_owned();
    let mut tlsclient = TlsClient::new(sock, server_name, config);

    if args.http {
        let httpreq = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
            args.hostname
        );
        tlsclient
            .write_all(httpreq.as_bytes())
            .unwrap();
    } else {
        let mut stdin = io::stdin();
        tlsclient
            .read_source_to_end(&mut stdin)
            .unwrap();
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(poll.registry());

    loop {
        match poll.poll(&mut events, None) {
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {e:?}")
            }
        }

        for ev in events.iter() {
            tlsclient.ready(ev);
            tlsclient.reregister(poll.registry());
        }
    }
}
