use std::sync::Arc;
use std::process;

extern crate mio;
use mio::tcp::TcpStream;

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
             event_loop: &mut mio::EventLoop<TlsClient>,
             timeout: <TlsClient as mio::Handler>::Timeout) {
    println!("connection timed out");
    process::exit(1);
  }
}

fn read_file(filename: &str) -> Vec<u8> {
  use std::io::Read;

  let mut r = Vec::new();
  let mut f = std::fs::File::open(filename).unwrap();
  f.read_to_end(&mut r).unwrap();
  r
}

impl TlsClient {
  fn new(sock: TcpStream) -> TlsClient {
    let mut config = rustls::client::ClientConfig::default();
    config.root_store.add(&read_file("test/ca.der"))
      .unwrap();

    let cfg = Arc::new(config);

    TlsClient {
      socket: sock,
      closing: false,
      tls_session: rustls::client::ClientSession::new(&cfg, "testserver.com")
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
  }

  fn do_write(&mut self) {
    let rc = self.tls_session.write_tls(&mut self.socket);
    println!("write rc {:?}", rc);
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
  let addr = "127.0.0.1:8443".parse().unwrap();
  let sock = TcpStream::connect(&addr).unwrap();
  let mut event_loop = mio::EventLoop::new().unwrap();
  let mut tlsclient = TlsClient::new(sock);
  tlsclient.register(&mut event_loop);
  event_loop.run(&mut tlsclient).unwrap();
}
