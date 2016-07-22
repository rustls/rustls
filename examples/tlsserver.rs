use std::sync::Arc;

extern crate mio;
use mio::util::Slab;
use mio::TryRead;
use mio::tcp::{TcpListener, TcpStream, Shutdown};

#[macro_use]
extern crate log;

use std::fs;
use std::io;
use std::net;
use std::io::{Write, Read, BufReader};

extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate env_logger;

extern crate rustls;

use rustls::Session;

/* Token for our listening socket. */
const LISTENER: mio::Token = mio::Token(0);

/* Which mode the server operates in. */
#[derive(Clone)]
enum ServerMode {
  /// Write back received bytes
  Echo,

  /// Do one read, then write a bodged HTTP response and
  /// cleanly close the connection.
  Http,

  /// Forward traffic to/from given port on localhost.
  Forward(u16)
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
  server: TcpListener,
  connections: Slab<Connection>,
  tls_config: Arc<rustls::ServerConfig>,
  mode: ServerMode
}

impl TlsServer {
  fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
    let slab = Slab::new_starting_at(mio::Token(1), 256);

    TlsServer {
      server: server,
      connections: slab,
      tls_config: cfg,
      mode: mode
    }
  }
}

impl mio::Handler for TlsServer {
  type Timeout = ();
  type Message = ();

  fn ready(&mut self,
           event_loop: &mut mio::EventLoop<TlsServer>,
           token: mio::Token,
           events: mio::EventSet) {
    match token {
      /* Our listening socket: we have a new connection. */
      LISTENER => {
        match self.server.accept() {
          Ok(Some((socket, addr))) => {
            info!("Accepting new connection from {:?}", addr);

            let tls_session = rustls::ServerSession::new(&self.tls_config);
            let mode = self.mode.clone();
            let token = self.connections
              .insert_with(|token| Connection::new(socket, token, mode, tls_session))
              .unwrap();

            self.connections[token].register(event_loop);
          }
          Ok(None) => {
          }
          Err(e) => {
            println!("encountered error while accepting connection; err={:?}", e);
            event_loop.shutdown();
          }
        }
      }

      /* A connection socket. */
      _ => {
        self.connections[token].ready(event_loop, events);

        if self.connections[token].is_closed() {
          self.connections[token].deregister(event_loop);
          self.connections.remove(token);
        }
      }
    }
  }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
  socket: TcpStream,
  token: mio::Token,
  closing: bool,
  mode: ServerMode,
  tls_session: rustls::ServerSession,
  back: Option<TcpStream>,
  sent_http_response: bool
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
  match *mode {
    ServerMode::Forward(ref port) => {
      let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
      let conn = TcpStream::connect(&net::SocketAddr::V4(addr)).unwrap();
      Some(conn)
    },
    _ => None
  }
}

impl Connection {
  fn new(socket: TcpStream, token: mio::Token,
         mode: ServerMode,
         tls_session: rustls::ServerSession) -> Connection {
    let back = open_back(&mode);
    Connection {
      socket: socket,
      token: token,
      closing: false,
      mode: mode,
      tls_session: tls_session,
      back: back,
      sent_http_response: false
    }
  }

  /// We're a connection, and we have something to do.
  fn ready(&mut self,
           event_loop: &mut mio::EventLoop<TlsServer>,
           events: mio::EventSet) {
    /* If we're readable: read some TLS.  Then
     * see if that yielded new plaintext.  Then
     * see if the backend is readable too. */
    if events.is_readable() {
      self.do_tls_read();
      self.try_plain_read();
      self.try_back_read();
    }

    if events.is_writable() {
      self.do_tls_write();
    }

    if self.closing && !self.tls_session.wants_write() {
      self.socket.shutdown(Shutdown::Both).unwrap();
      self.close_back();
    } else {
      self.reregister(event_loop);
    }
  }

  /// Close the backend connection for forwarded sessions.
  fn close_back(&mut self) {
    if self.back.is_some() {
      let back = self.back.as_mut().unwrap();
      back.shutdown(Shutdown::Both).unwrap();
    }
    self.back = None;
  }

  fn do_tls_read(&mut self) {
    /* Read some TLS data. */
    let rc = self.tls_session.read_tls(&mut self.socket);
    if rc.is_err() {
      let err = rc.unwrap_err();

      if let io::ErrorKind::WouldBlock = err.kind() {
        return;
      }

      error!("read error {:?}", err);
      self.closing = true;
      return;
    }

    if rc.unwrap() == 0 {
      info!("eof");
      self.closing = true;
      return;
    }

    /* Process newly-received TLS messages. */
    let processed = self.tls_session.process_new_packets();
    if processed.is_err() {
      error!("cannot process packet: {:?}", processed);
      self.closing = true;
      return;
    }
  }

  fn try_plain_read(&mut self) {
    /* Read and process all available plaintext. */
    let mut buf = Vec::new();

    let rc = self.tls_session.read_to_end(&mut buf);
    if rc.is_err() {
      error!("plaintext read failed: {:?}", rc);
      self.closing = true;
      return;
    }

    if buf.len() > 0 {
      info!("plaintext read {:?}", buf.len());
      self.incoming_plaintext(&buf);
    }
  }

  fn try_back_read(&mut self) {
    if self.back.is_none() {
      return;
    }

    /* Try a non-blocking read. */
    let mut buf = [0u8; 1024];
    let back = self.back.as_mut().unwrap();
    let rc = back.try_read(&mut buf);

    if rc.is_err() {
      error!("backend read failed: {:?}", rc);
      self.closing = true;
      return;
    }

    let maybe_len = rc.unwrap();

    /* If we have a successful but empty read, that's an EOF.
     * Otherwise, we shove the data into the TLS session. */
    match maybe_len {
      Some(len) if len == 0 => { info!("back eof"); self.closing = true; },
      Some(len) => { self.tls_session.write(&buf[..len]).unwrap(); },
      None => {}
    };
  }

  /// Process some amount of received plaintext.
  fn incoming_plaintext(&mut self, buf: &[u8]) {
    match self.mode {
      ServerMode::Echo => { self.tls_session.write(buf).unwrap(); },
      ServerMode::Http => { self.send_http_response_once(); },
      ServerMode::Forward(_) => { self.back.as_mut().unwrap().write(buf).unwrap(); }
    }
  }

  fn send_http_response_once(&mut self) {
    if !self.sent_http_response {
      self.tls_session
        .write(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n")
        .unwrap();
      self.sent_http_response = true;
      self.tls_session.send_close_notify();
    }
  }

  fn do_tls_write(&mut self) {
    let rc = self.tls_session.write_tls(&mut self.socket);
    if rc.is_err() {
      error!("write failed {:?}", rc);
      self.closing = true;
      return;
    }
  }

  fn register(&self, event_loop: &mut mio::EventLoop<TlsServer>) {
    event_loop.register(&self.socket,
                        self.token,
                        self.event_set(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
      .unwrap();

    if self.back.is_some() {
      event_loop.register(self.back.as_ref().unwrap(),
                          self.token,
                          mio::EventSet::readable(),
                          mio::PollOpt::level() | mio::PollOpt::oneshot())
        .unwrap();
    }
  }

  fn reregister(&self, event_loop: &mut mio::EventLoop<TlsServer>) {
    event_loop.reregister(&self.socket,
                          self.token,
                          self.event_set(),
                          mio::PollOpt::level() | mio::PollOpt::oneshot())
      .unwrap();

    if self.back.is_some() {
      event_loop.reregister(self.back.as_ref().unwrap(),
                            self.token,
                            mio::EventSet::readable(),
                            mio::PollOpt::level() | mio::PollOpt::oneshot())
        .unwrap();
    }
  }

  fn deregister(&self, event_loop: &mut mio::EventLoop<TlsServer>) {
    event_loop.deregister(&self.socket)
      .unwrap();

    if self.back.is_some() {
      event_loop.deregister(self.back.as_ref().unwrap())
        .unwrap();
    }
  }

  /// What IO events we're currently waiting for,
  /// based on wants_read/wants_write.
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
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the RSA private
key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] echo
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] http
  tlsserver --certs CERTFILE --key KEYFILE [--verbose] [-p PORT] [--suite SUITE...] [--proto PROTOCOL...] forward <fport>
  tlsserver --version
  tlsserver --help

Options:
    -p, --port PORT     Listen on PORT. Default is 443.
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA private key,
                        in PEM format.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
    --verbose           Emit log output.
    --version           Show tool version.
    --help              Show this screen.
";

#[derive(Debug, RustcDecodable)]
struct Args {
  cmd_echo: bool,
  cmd_http: bool,
  cmd_forward: bool,
  flag_port: Option<u16>,
  flag_verbose: bool,
  flag_suite: Vec<String>,
  flag_proto: Vec<String>,
  flag_certs: Option<String>,
  flag_key: Option<String>,
  arg_fport: Option<u16>
}

fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
  for suite in rustls::ALL_CIPHERSUITES.iter() {
    let sname = format!("{:?}", suite.suite).to_lowercase();

    if sname == name.to_string().to_lowercase() {
      return Some(suite);
    }
  }

  None
}

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

fn make_config(args: &Args) -> Arc<rustls::ServerConfig> {
  let mut config = rustls::ServerConfig::new();

  let certs = load_certs(&args.flag_certs.as_ref().expect("--certs option missing"));
  let privkey = load_private_key(&args.flag_key.as_ref().expect("--key option missing"));
  config.set_single_cert(certs, privkey);

  if args.flag_suite.len() != 0 {
    config.ciphersuites = lookup_suites(&args.flag_suite);
  }

  config.set_protocols(&args.flag_proto);

  Arc::new(config)
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

  let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
  addr.set_port(args.flag_port.unwrap_or(443));

  let config = make_config(&args);

  let listener = TcpListener::bind(&addr).expect("cannot listen on port");
  let mut event_loop = mio::EventLoop::new().unwrap();
  event_loop.register(&listener, LISTENER,
                      mio::EventSet::readable(),
                      mio::PollOpt::level()).unwrap();

  let mode = if args.cmd_echo {
    ServerMode::Echo
  } else if args.cmd_http {
    ServerMode::Http
  } else {
    ServerMode::Forward(args.arg_fport.expect("fport required"))
  };

  let mut tlsserv = TlsServer::new(listener, mode, config);
  event_loop.run(&mut tlsserv).unwrap();
}
