use std::sync::Arc;
use std::process;

extern crate mio;
use mio::tcp::TcpStream;

use std::str;
use std::io;
use std::io::{Read, Write, BufReader};

extern crate rustls;

const CLIENT: mio::Token = mio::Token(0);

struct TlsClient {
  socket: TcpStream,
  closing: bool,
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
      println!("closing connection");
      process::exit(1);
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

impl TlsClient {
  fn new(sock: TcpStream, hostname: &str) -> TlsClient {
    let mut config = rustls::client::ClientConfig::default();
    let certfile = std::fs::File::open("certs.pem")
      .unwrap();
    let mut reader = BufReader::new(certfile);
    config.root_store.add_pem_file(&mut reader)
      .unwrap();

    let cfg = Arc::new(config);

    TlsClient {
      socket: sock,
      closing: false,
      tls_session: rustls::client::ClientSession::new(&cfg, hostname)
    }
  }

  fn do_read(&mut self) {
    let rc = self.tls_session.read_tls(&mut self.socket);
    if rc.is_err() {
      println!("read error {:?}", rc);
      self.closing = true;
      return;
    }

    if rc.unwrap() == 0 {
      println!("eof");
      self.closing = true;
      return;
    }

    let processed = self.tls_session.process_new_packets();
    if processed.is_err() {
      println!("cannot process packet: {:?}", processed);
      self.closing = true;
      return;
    }

    /* We might have new plaintext as a result. */
    let mut plaintext = Vec::new();
    let rc = self.tls_session.read_to_end(&mut plaintext);
    if plaintext.len() > 0 {
      println!("got {}", str::from_utf8(&plaintext).unwrap());
    }

    if rc.is_err() {
      println!("plaintext read error {:?}", rc.unwrap_err());
      self.closing = true;
      return;
    }
  }

  fn do_write(&mut self) {
    let rc = self.tls_session.write_tls(&mut self.socket);
    println!("write rc={:?}", rc);
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

fn main() {
  use std::net::ToSocketAddrs;
  use std::env;
  use std::process;

  let args: Vec<String> = env::args().collect();

  if args.len() != 2 {
    println!("usage: {} hostname", args[0]);
    println!("connects to <hostname> port 443, and sends a trivial HTTP request");
    process::exit(1);
  }

  let hostname = &args[1];
  let port = 443;

  let addr = (hostname.as_str(), port).to_socket_addrs().unwrap().next().unwrap();
  let sock = TcpStream::connect(&addr).unwrap();
  let mut event_loop = mio::EventLoop::new().unwrap();
  let mut tlsclient = TlsClient::new(sock, &hostname);
  tlsclient.write(format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", hostname).as_bytes()).unwrap();
  tlsclient.register(&mut event_loop);
  event_loop.run(&mut tlsclient).unwrap();
}
