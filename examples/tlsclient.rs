use std::sync::Arc;
use std::process;

extern crate mio;
use mio::tcp::TcpStream;

use std::net::SocketAddr;
use std::str;
use std::io;
use std::fs;
use std::collections;
use std::io::{Read, Write, BufReader};

extern crate env_logger;

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate rustls;

use rustls::Session;

const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
  socket: TcpStream,
  closing: bool,
  clean_closure: bool,
  tls_session: rustls::ClientSession
}

impl mio::Handler for TlsClient {
  type Timeout = ();
  type Message = ();

  /// Called by mio each time events we register() for happen.
  fn ready(&mut self,
           event_loop: &mut mio::EventLoop<TlsClient>,
           token: mio::Token,
           events: mio::EventSet) {
    assert_eq!(token, CLIENT);

    if events.is_readable() {
      self.do_read();
    }

    if events.is_writable() {
      self.do_write();
    }

    if self.is_closed() {
      println!("Connection closed");
      process::exit(if self.clean_closure { 0 } else { 1 });
    }

    self.reregister(event_loop);
  }

  /* XXX: this won't be called currently, but could be used in the future
   * to have timeout behaviour. */
  fn timeout(&mut self,
             _event_loop: &mut mio::EventLoop<TlsClient>,
             _timeout: <TlsClient as mio::Handler>::Timeout) {
    println!("connection timed out");
    process::exit(1);
  }
}

/// We implement io::Write and pass through to the TLS session
impl io::Write for TlsClient {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    self.tls_session.write(bytes)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.tls_session.flush()
  }
}

impl io::Read for TlsClient {
  fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
    self.tls_session.read(bytes)
  }
}

impl TlsClient {
  fn new(sock: TcpStream, hostname: &str, cfg: Arc<rustls::ClientConfig>) -> TlsClient {
    TlsClient {
      socket: sock,
      closing: false,
      clean_closure: false,
      tls_session: rustls::ClientSession::new(&cfg, hostname)
    }
  }

  fn read_source_to_end(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    let mut buf = Vec::new();
    let len = try!(rd.read_to_end(&mut buf));
    self.tls_session.write(&buf).unwrap();
    Ok(len)
  }

  /// We're ready to do a read.
  fn do_read(&mut self) {
    /* Read TLS data.  This fails if the underlying TCP connection
     * is broken. */
    let rc = self.tls_session.read_tls(&mut self.socket);
    if rc.is_err() {
      println!("TLS read error: {:?}", rc);
      self.closing = true;
      return;
    }

    /* If we're ready but there's no data: EOF. */
    if rc.unwrap() == 0 {
      println!("EOF");
      self.closing = true;
      self.clean_closure = true;
      return;
    }

    /* Reading some TLS data might have yielded new TLS
     * messages to process.  Errors from this indicate
     * TLS protocol problems and are fatal. */
    let processed = self.tls_session.process_new_packets();
    if processed.is_err() {
      println!("TLS error: {:?}", processed.unwrap_err());
      self.closing = true;
      return;
    }

    /* Having read some TLS data, and processed any new messages,
     * we might have new plaintext as a result.
     *
     * Read it and then write it to stdout. */
    let mut plaintext = Vec::new();
    let rc = self.tls_session.read_to_end(&mut plaintext);
    if plaintext.len() > 0 {
      io::stdout().write(&plaintext).unwrap();
    }

    /* If that fails, the peer might have started a clean TLS-level
     * session closure. */
    if rc.is_err() {
      let err = rc.unwrap_err();
      println!("Plaintext read error: {:?}", err);
      self.clean_closure = err.kind() == io::ErrorKind::ConnectionAborted;
      self.closing = true;
      return;
    }
  }

  fn do_write(&mut self) {
    self.tls_session.write_tls(&mut self.socket).unwrap();
  }

  fn register(&self, event_loop: &mut mio::EventLoop<TlsClient>) {
    event_loop.register(&self.socket,
                        CLIENT,
                        self.event_set(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
      .unwrap();
  }

  fn reregister(&self, event_loop: &mut mio::EventLoop<TlsClient>) {
    event_loop.reregister(&self.socket,
                          CLIENT,
                          self.event_set(),
                          mio::PollOpt::level() | mio::PollOpt::oneshot())
      .unwrap();
  }

  /* Use wants_read/wants_write to register for different mio-level
   * IO readiness events. */
  fn event_set(&self) -> mio::EventSet {
    let rd = self.tls_session.wants_read();
    let wr = self.tls_session.wants_write();

    if rd && wr {
      mio::EventSet::readable() | mio::EventSet::writable()
    } else if wr {
      mio::EventSet::writable()
    } else {
      mio::EventSet::readable()
    }
  }

  fn is_closed(&self) -> bool {
    self.closing
  }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
  cache: collections::HashMap<Vec<u8>, Vec<u8>>,
  filename: Option<String>
}

impl PersistCache {
  /// Make a new cache.  If filename is Some, load the cache
  /// from it and flush changes back to that file.
  fn new(filename: &Option<String>) -> PersistCache {
    let mut cache = PersistCache { cache: collections::HashMap::new(), filename: filename.clone() };
    if cache.filename.is_some() {
      cache.load();
    }
    cache
  }

  /// If we have a filename, save the cache contents to it.
  fn save(&mut self) {
    use rustls::internal::msgs::codec::Codec;
    use rustls::internal::msgs::base::PayloadU16;

    if self.filename.is_none() {
      return;
    }

    let mut file = fs::File::create(self.filename.as_ref().unwrap()).unwrap();

    for (key, val) in &self.cache {
      let mut item = Vec::new();
      let key_pl = PayloadU16 { body: key.clone().into_boxed_slice() };
      let val_pl = PayloadU16 { body: val.clone().into_boxed_slice() };
      key_pl.encode(&mut item);
      val_pl.encode(&mut item);
      file.write_all(&item).unwrap();
    }
  }

  /// We have a filename, so replace the cache contents from it.
  fn load(&mut self) {
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::base::PayloadU16;

    let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
      Ok(f) => f,
      Err(_) => return
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    self.cache.clear();
    let mut rd = Reader::init(&data);

    while rd.any_left() {
      let key_pl = PayloadU16::read(&mut rd).unwrap();
      let val_pl = PayloadU16::read(&mut rd).unwrap();
      self.cache.insert(key_pl.body.to_vec(), val_pl.body.to_vec());
    }
  }
}

impl rustls::StoresClientSessions for PersistCache {
  /// put: insert into in-memory cache, and perhaps persist to disk.
  fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> bool {
    self.cache.insert(key, value);
    self.save();
    true
  }

  /// get: from in-memory cache
  fn get(&mut self, key: &Vec<u8>) -> Option<Vec<u8>> {
    self.cache.get(key).map(|x| x.clone())
  }
}

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, CA certificates are read from
`/etc/ssl/certs/ca-certificates.crt'.

Usage:
  tlsclient [--verbose] [-p PORT] [--http] [--auth-key KEY --auth-certs CERTS] [--mtu MTU] [--cache CACHE] [--cafile CAFILE] [--suite SUITE...] [--proto PROTOCOL...] <hostname>
  tlsclient --version
  tlsclient --help

Options:
    -p, --port PORT     Connect to PORT. Default is 443.
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
    --cache CACHE       Save session cache to file CACHE.
    --verbose           Emit log output.
    --mtu MTU           Limit outgoing messages to MTU bytes.
    --version           Show tool version.
    --help              Show this screen.
";

#[derive(Debug, RustcDecodable)]
struct Args {
  flag_port: Option<u16>,
  flag_http: bool,
  flag_verbose: bool,
  flag_suite: Vec<String>,
  flag_proto: Vec<String>,
  flag_mtu: Option<usize>,
  flag_cafile: Option<String>,
  flag_cache: Option<String>,
  flag_auth_key: Option<String>,
  flag_auth_certs: Option<String>,
  arg_hostname: String
}

/* TODO: um, well, it turns out that openssl s_client/s_server
 * that we use for testing doesn't do ipv6.  So we can't actually
 * test ipv6 and hence kill this. */
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
  use std::net::ToSocketAddrs;

  let addrs = (host, port).to_socket_addrs().unwrap();
  for addr in addrs {
    if let SocketAddr::V4(_) = addr {
      return addr.clone();
    }
  }

  unreachable!("Cannot lookup address");
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
  for suite in rustls::ALL_CIPHERSUITES.iter() {
    let sname = format!("{:?}", suite.suite).to_lowercase();

    if sname == name.to_string().to_lowercase() {
      return Some(suite);
    }
  }

  None
}

/// Make a vector of ciphersuites named in `suites`
fn lookup_suites(suites: &Vec<String>) -> Vec<&'static rustls::SupportedCipherSuite> {
  let mut out = Vec::new();

  for csname in suites {
    let scs = find_suite(csname);
    match scs {
      Some(s) => out.push(s),
      None => panic!("cannot look up ciphersuite '{}'", csname)
    }
  }

  out
}

fn load_certs(filename: &str) -> Vec<Vec<u8>> {
  let certfile = fs::File::open(filename)
    .expect("cannot open certificate file");
  let mut reader = BufReader::new(certfile);
  rustls::internal::pemfile::certs(&mut reader)
    .unwrap()
}

fn load_private_key(filename: &str) -> Vec<u8> {
  let keyfile = fs::File::open(filename)
    .expect("cannot open private key file");
  let mut reader = BufReader::new(keyfile);
  let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
    .unwrap();
  assert!(keys.len() == 1);
  keys[0].clone()
}

fn load_key_and_cert(config: &mut rustls::ClientConfig,
                     keyfile: &str,
                     certsfile: &str)
{
  let certs = load_certs(certsfile);
  let privkey = load_private_key(keyfile);

  config.set_single_client_cert(certs, privkey);
}

/// Build a ClientConfig from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
  let mut config = rustls::ClientConfig::new();

  if args.flag_suite.len() != 0 {
    config.ciphersuites = lookup_suites(&args.flag_suite);
  }

  let cafile = match args.flag_cafile {
    Some(ref cafile) => cafile.clone(),
    None => "/etc/ssl/certs/ca-certificates.crt".to_string()
  };
  let certfile = match std::fs::File::open(&cafile) {
    Ok(file) => file,
    Err(e) => panic!("cannot open CA file '{}': {:?}\nConsider using the --cafile option to provide a valid CA file.", cafile, e)
  };
  let mut reader = BufReader::new(certfile);
  config.root_store.add_pem_file(&mut reader)
    .unwrap();

  let persist = Box::new(PersistCache::new(&args.flag_cache));

  config.set_protocols(&args.flag_proto);
  config.set_persistence(persist);
  config.set_mtu(&args.flag_mtu);

  if args.flag_auth_key.is_some() || args.flag_auth_certs.is_some() {
    load_key_and_cert(&mut config,
                      args.flag_auth_key.as_ref()
                        .expect("must provide --auth-key with --auth-certs"),
                      args.flag_auth_certs.as_ref()
                        .expect("must provide --auth-certs with --auth-key"));
  }

  Arc::new(config)
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {
  let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

  let args: Args = Docopt::new(USAGE)
    .and_then(|d| Ok(d.help(true)))
    .and_then(|d| Ok(d.version(Some(version))))
    .and_then(|d| d.decode())
    .unwrap_or_else(|e| e.exit());

  if args.flag_verbose {
    let mut logger = env_logger::LogBuilder::new();
    logger.parse("debug");
    logger.init().unwrap();
  }

  let port = args.flag_port.unwrap_or(443);
  let addr = lookup_ipv4(args.arg_hostname.as_str(), port);

  let config = make_config(&args);

  let sock = TcpStream::connect(&addr).unwrap();
  let mut tlsclient = TlsClient::new(sock, &args.arg_hostname, config);

  if args.flag_http {
    let httpreq = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n", args.arg_hostname);
    tlsclient.write(httpreq.as_bytes()).unwrap();
  } else {
    let mut stdin = io::stdin();
    tlsclient.read_source_to_end(&mut stdin).unwrap();
  }

  let mut event_loop = mio::EventLoop::new().unwrap();
  tlsclient.register(&mut event_loop);
  event_loop.run(&mut tlsclient).unwrap();
}
