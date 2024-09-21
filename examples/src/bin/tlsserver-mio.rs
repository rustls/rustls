//! This is an example server that uses rustls for TLS, and [mio] for I/O.
//!
//! It uses command line flags to demonstrate configuring a TLS server that may:
//!  * Specify supported TLS protocol versions
//!  * Customize cipher suite selection
//!  * Perform optional or mandatory client certificate authentication
//!  * Check client certificates for revocation status with CRLs
//!  * Support session tickets
//!  * Staple an OCSP response
//!
//! See [`USAGE`] for more details.
//!
//! You may set the `SSLKEYLOGFILE` env var when using this example to write a
//! log file with key material (insecure) for debugging purposes. See [`rustls::KeyLog`]
//! for more information.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! [mio]: https://docs.rs/mio/latest/mio/

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, net};

use clap::{Parser, Subcommand};
use log::{debug, error};
use mio::net::{TcpListener, TcpStream};
use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

// Which mode the server operates in.
#[derive(Clone, Debug, Subcommand)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward { port: u16 },
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> Self {
        Self {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
        }
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);

                    let tls_conn =
                        rustls::ServerConnection::new(Arc::clone(&self.tls_config)).unwrap();
                    let mode = self.mode.clone();

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = OpenConnection::new(socket, token, mode, tls_conn);
                    connection.register(registry);
                    self.connections
                        .insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level connection state, and some
/// other state/metadata.
struct OpenConnection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_conn: rustls::ServerConnection,
    back: Option<TcpStream>,
    sent_http_response: bool,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward { port } => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        mode: ServerMode,
        tls_conn: rustls::ServerConnection,
    ) -> Self {
        let back = open_back(&mode);
        Self {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_conn,
            back,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if let Some(back) = self.back.take() {
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {}
        };

        // Process newly-received TLS messages.
        if let Err(err) = self.tls_conn.process_new_packets() {
            error!("cannot process packet: {:?}", err);

            // last gasp write to send any alerts
            self.do_tls_write_and_handle_error();

            self.closing = true;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        if let Ok(io_state) = self.tls_conn.process_new_packets() {
            if let Some(mut early_data) = self.tls_conn.early_data() {
                let mut buf = Vec::new();
                early_data
                    .read_to_end(&mut buf)
                    .unwrap();

                if !buf.is_empty() {
                    debug!("early data read {:?}", buf.len());
                    self.incoming_plaintext(&buf);
                    return;
                }
            }

            if io_state.plaintext_bytes_to_read() > 0 {
                let mut buf = vec![0u8; io_state.plaintext_bytes_to_read()];

                self.tls_conn
                    .reader()
                    .read_exact(&mut buf)
                    .unwrap();

                debug!("plaintext read {:?}", buf.len());
                self.incoming_plaintext(&buf);
            }
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(0) => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_conn
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_conn
                    .writer()
                    .write_all(buf)
                    .unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward { .. } => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tls_conn
                .writer()
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_conn.send_close_notify();
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_conn
            .write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    self.token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.socket)
            .unwrap();

        if let Some(back) = self.back.as_mut() {
            registry.deregister(back).unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
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
        self.closed
    }
}

/// Runs a TLS server on :PORT. The default PORT is 443.
///
/// `echo` mode means the server echoes received data on each connection.
///
/// `http` mode means the server blindly sends a HTTP response on each connection.
///
/// `forward` means the server forwards plaintext to a connection made to `localhost:fport`.
///
/// `--certs` names the full certificate chain, `--key` provides the private key.
#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    mode: ServerMode,
    /// Listen on port.
    #[clap(short, long, default_value = "443")]
    port: u16,
    /// Emit log output.
    #[clap(short, long)]
    verbose: bool,
    /// Disable default TLS version list, and use the given versions instead.
    #[clap(long)]
    protover: Vec<String>,
    /// Disable default cipher suite list, and use the given suites instead.
    #[clap(long)]
    suite: Vec<String>,
    /// Negotiate the given protocols using ALPN.
    #[clap(long)]
    proto: Vec<Vec<u8>>,
    /// Read server certificates from the given file. This should contain PEM-format certificates
    /// in the right order (the first certificate should certify the end entity, matching the
    /// private key, the last should be a root CA).
    #[clap(long)]
    certs: PathBuf,
    /// Perform client certificate revocation checking using the DER-encoded CRLs from the given
    /// files.
    #[clap(long)]
    crl: Vec<PathBuf>,
    /// Read private key from the given file. This should be a private key in PEM format.
    #[clap(long)]
    key: PathBuf,
    /// Read DER-encoded OCSP response from the given file and staple to certificate.
    #[clap(long)]
    ocsp: Option<PathBuf>,
    /// Enable client authentication, and accept certificates signed by those roots provided in
    /// the given file.
    #[clap(long)]
    auth: Option<PathBuf>,
    /// Send a fatal alert if the client does not complete client authentication.
    #[clap(long)]
    require_auth: bool,
    /// Disable stateful session resumption.
    #[clap(long)]
    no_resumption: bool,
    /// Support tickets (stateless resumption).
    #[clap(long)]
    tickets: bool,
    /// Support receiving this many bytes with 0-RTT.
    #[clap(long, default_value = "0")]
    max_early_data: u32,
}

fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in provider::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &Path) -> Vec<CertificateDer<'static>> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &Path) -> PrivateKeyDer<'static> {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return key.into(),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn load_ocsp(filename: Option<&Path>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let Some(name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn load_crls(
    filenames: impl Iterator<Item = impl AsRef<Path>>,
) -> Vec<CertificateRevocationListDer<'static>> {
    filenames
        .map(|filename| {
            let mut der = Vec::new();
            fs::File::open(filename)
                .expect("cannot open CRL file")
                .read_to_end(&mut der)
                .unwrap();
            CertificateRevocationListDer::from(der)
        })
        .collect()
}

fn make_config(args: &Args) -> Arc<rustls::ServerConfig> {
    let client_auth = if let Some(auth) = &args.auth {
        let roots = load_certs(auth);
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(root).unwrap();
        }
        let crls = load_crls(args.crl.iter());
        if args.require_auth {
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .with_crls(crls)
                .build()
                .unwrap()
        } else {
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .with_crls(crls)
                .allow_unauthenticated()
                .build()
                .unwrap()
        }
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let suites = if !args.suite.is_empty() {
        lookup_suites(&args.suite)
    } else {
        provider::ALL_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.protover.is_empty() {
        lookup_versions(&args.protover)
    } else {
        rustls::ALL_VERSIONS.to_vec()
    };

    let certs = load_certs(&args.certs);
    let privkey = load_private_key(&args.key);
    let ocsp = load_ocsp(args.ocsp.as_deref());

    let mut config = rustls::ServerConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: suites,
            ..provider::default_provider()
        }
        .into(),
    )
    .with_protocol_versions(&versions)
    .expect("inconsistent cipher-suites/versions specified")
    .with_client_cert_verifier(client_auth)
    .with_single_cert_with_ocsp(certs, privkey, ocsp)
    .expect("bad certificates/private key");

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.no_resumption {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    }

    if args.tickets {
        config.ticketer = provider::Ticketer::new().unwrap();
    }

    if args.max_early_data > 0 {
        if !versions.contains(&&rustls::version::TLS13) {
            panic!("Early data is only available for servers supporting TLS1.3");
        }
        if args.no_resumption {
            panic!("Early data requires resumption.");
        }
        if args.tickets {
            panic!("Early data is not supported for stateless resumption (--tickets).");
        }
        config.max_early_data_size = args.max_early_data;
    }

    config.alpn_protocols = args.proto.clone();

    Arc::new(config)
}

fn main() {
    let args = Args::parse();
    if args.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    if !args.crl.is_empty() && args.auth.is_none() {
        println!("--crl can only be provided with --auth enabled");
        return;
    }

    let mut addr: net::SocketAddr = "[::]:443".parse().unwrap();
    addr.set_port(args.port);

    let config = make_config(&args);

    let mut listener = TcpListener::bind(addr).expect("cannot listen on port");
    println!("listening on {addr}");
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();

    let mut tlsserv = TlsServer::new(listener, args.mode, config);

    let mut events = mio::Events::with_capacity(256);
    loop {
        match poll.poll(&mut events, None) {
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {:?}", e)
            }
        }

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tlsserv
                        .accept(poll.registry())
                        .expect("error accepting socket");
                }
                _ => tlsserv.conn_event(poll.registry(), event),
            }
        }
    }
}
