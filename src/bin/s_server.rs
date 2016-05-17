use std::sync::Arc;

extern crate mio;
use mio::util::Slab;
use mio::tcp::{TcpListener, TcpStream};

extern crate rustls;

const LISTENER: mio::Token = mio::Token(0);

struct TlsServer {
  server: TcpListener,
  connections: Slab<Connection>,
  tls_config: Arc<rustls::server::ServerConfig>
}

impl TlsServer {
  fn new(server: TcpListener) -> TlsServer {
    let slab = Slab::new_starting_at(mio::Token(1), 256);
    let mut config = rustls::server::ServerConfig::default();

    let cert_chain = vec![
      rustls::msgs::handshake::ASN1Cert { body: Box::new([0u8; 1]) }
    ];
    config.set_cert_chain(&cert_chain);

    TlsServer {
      server: server,
      connections: slab,
      tls_config: Arc::new(config)
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
      LISTENER => {
        match self.server.accept() {
          Ok(Some((socket, addr))) => {
            println!("accepting new connection from {:?}", addr);

            let tls_session = rustls::server::ServerSession::new(&self.tls_config);
            let token = self.connections
              .insert_with(|token| Connection::new(socket, token, tls_session))
              .unwrap();
            
            println!("token is {:?}", token);
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

      _ => {
        self.connections[token].ready(event_loop, events);

        if self.connections[token].is_closed() {
          self.connections.remove(token);
        }
      }
    }
  }
}

struct Connection {
  socket: TcpStream,
  token: mio::Token,
  closing: bool,
  tls_session: rustls::server::ServerSession
}

impl Connection {
  fn new(socket: TcpStream, token: mio::Token,
         tls_session: rustls::server::ServerSession) -> Connection {
    Connection {
      socket: socket,
      token: token,
      closing: false,
      tls_session: tls_session
    }
  }

  fn ready(&mut self,
           event_loop: &mut mio::EventLoop<TlsServer>,
           events: mio::EventSet) {
    if events.is_readable() {
      self.do_read();
    }

    if events.is_writable() {
      self.do_write();
    }

    self.reregister(event_loop);
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

  fn register(&self, event_loop: &mut mio::EventLoop<TlsServer>) {
    event_loop.register(&self.socket,
                        self.token,
                        self.event_set(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
      .unwrap();
  }

  fn reregister(&self, event_loop: &mut mio::EventLoop<TlsServer>) {
    event_loop.reregister(&self.socket,
                          self.token,
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
  let listener = TcpListener::bind(&addr).unwrap();
  let mut event_loop = mio::EventLoop::new().unwrap();
  event_loop.register(&listener, LISTENER,
                      mio::EventSet::readable(),
                      mio::PollOpt::level()).unwrap();

  let mut tlsserv = TlsServer::new(listener);
  event_loop.run(&mut tlsserv).unwrap();
}
