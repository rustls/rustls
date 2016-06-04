use std::sync::Arc;
use std::process;

extern crate mio;
use mio::tcp::TcpStream;

use std::net::SocketAddr;
use std::str;
use std::io;
use std::io::{Read, Write, BufReader};

extern crate env_logger;

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate rustls;

const CLIENT: mio::Token = mio::Token(0);

struct TlsClient {
  socket: TcpStream,
  closing: bool,
  clean_closure: bool,
  tls_session: rustls::client::ClientSession
}

impl mio::Handler for TlsClient {
  type Timeout = ();
  type Message = ();

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

  fn timeout(&mut self,
             _event_loop: &mut mio::EventLoop<TlsClient>,
             _timeout: <TlsClient as mio::Handler>::Timeout) {
    println!("connection timed out");
    process::exit(1);
  }
}

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

fn find_suite(name: &str) -> Option<&'static rustls::suites::SupportedCipherSuite> {
  for suite in rustls::suites::DEFAULT_CIPHERSUITES.iter() {
    let sname = format!("{:?}", suite.suite).to_lowercase();

    if sname == name.to_string().to_lowercase() {
      return Some(suite);
    }
  }

  None
}

fn lookup_suites(suites: &Vec<String>) -> Vec<&'static rustls::suites::SupportedCipherSuite> {
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

impl TlsClient {
  fn new(sock: TcpStream, hostname: &str, cafile: &str, suites: &Vec<String>) -> TlsClient {
    let mut config = rustls::client::ClientConfig::default();

    if suites.len() != 0 {
      config.ciphersuites = lookup_suites(suites);
    }

    let certfile = std::fs::File::open(cafile)
      .unwrap();
    let mut reader = BufReader::new(certfile);
    config.root_store.add_pem_file(&mut reader)
      .unwrap();

    let cfg = Arc::new(config);

    TlsClient {
      socket: sock,
      closing: false,
      clean_closure: false,
      tls_session: rustls::client::ClientSession::new(&cfg, hostname)
    }
  }

  fn read_source_to_end(&mut self, rd: &mut io::Read) -> io::Result<usize> {
    let mut buf = Vec::new();
    let len = try!(rd.read_to_end(&mut buf));
    self.tls_session.write(&buf).unwrap();
    Ok(len)
  }

  fn do_read(&mut self) {
    let rc = self.tls_session.read_tls(&mut self.socket);
    if rc.is_err() {
      println!("TLS read error: {:?}", rc);
      self.closing = true;
      return;
    }

    if rc.unwrap() == 0 {
      println!("EOF");
      self.closing = true;
      self.clean_closure = true;
      return;
    }

    let processed = self.tls_session.process_new_packets();
    if processed.is_err() {
      println!("TLS error: {:?}", processed.unwrap_err());
      self.closing = true;
      return;
    }

    /* We might have new plaintext as a result. */
    let mut plaintext = Vec::new();
    let rc = self.tls_session.read_to_end(&mut plaintext);
    if plaintext.len() > 0 {
      io::stdout().write(&plaintext).unwrap();
    }

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

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

Usage:
  tlsclient [--verbose] [-p PORT] [--http] [--cafile CAFILE] [--suite SUITE...] <hostname>
  tlsclient --version
  tlsclient --help

Options:
    -p, --port PORT     Connect to PORT. Default is 443.
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.
    --verbose           Emit log output.
    --version           Show tool version.
    --help              Show this screen.
";

#[derive(Debug, RustcDecodable)]
struct Args {
  flag_port: Option<u16>,
  flag_http: bool,
  flag_verbose: bool,
  flag_suite: Vec<String>,
  flag_cafile: Option<String>,
  arg_hostname: String
}

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
  
  let cafile = args.flag_cafile.unwrap_or("/etc/ssl/certs/ca-certificates.crt".to_string());

  let sock = TcpStream::connect(&addr).unwrap();
  let mut tlsclient = TlsClient::new(sock, &args.arg_hostname, &cafile, &args.flag_suite);

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
