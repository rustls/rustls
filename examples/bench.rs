/* This program does assorted benchmarking of rustls.
 *
 * Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
 * etc. because it's unstable at the time of writing. */

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::fs;
use std::io::{self, Write};

extern crate rustls;
use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::ServerSessionMemoryCache;
use rustls::ClientSessionMemoryCache;
use rustls::Session;
use rustls::Ticketer;
use rustls::internal::pemfile;
use rustls::internal::msgs::enums::SignatureAlgorithm;

fn duration_nanos(d: Duration) -> f64 {
  (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

fn _bench<Fsetup, Ftest, S>(count: usize, name: &'static str, f_setup: Fsetup, f_test: Ftest)
  where Fsetup: Fn() -> S, Ftest: Fn(S) {
  let mut times = Vec::new();

  for _ in 0..count {
    let state = f_setup();
    let start = Instant::now();
    f_test(state);
    times.push(
      duration_nanos(Instant::now().duration_since(start))
    );
  }

  println!("{}", name);
  println!("{:?}", times);
}

fn time<F>(mut f: F) -> f64
  where F: FnMut() {
  let start = Instant::now();
  f();
  let end = Instant::now();
  let dur = duration_nanos(end.duration_since(start));
  dur as f64
}

fn transfer(left: &mut Session, right: &mut Session) {
  let mut buf = [0u8; 262144];

  while left.wants_write() {
    let sz = left.write_tls(&mut buf.as_mut()).unwrap();
    if sz == 0 {
      return;
    }

    let mut offs = 0;
    loop {
      offs += right.read_tls(&mut buf[offs..sz].as_ref()).unwrap();
      if sz == offs {
        break;
      }
    }
  }
}

fn drain(d: &mut Session, expect_len: usize) {
  let mut left = expect_len;
  let mut buf = [0u8; 8192];
  loop {
    let sz = d.read(&mut buf).unwrap();
    left -= sz;
    if left == 0 {
      break;
    }
  }
}

fn get_chain() -> Vec<rustls::Certificate> {
  pemfile::certs(
    &mut io::BufReader::new(
      fs::File::open("test-ca/rsa/end.fullchain").unwrap()
    )
  ).unwrap()
}

fn get_key() -> rustls::PrivateKey {
  pemfile::rsa_private_keys(
    &mut io::BufReader::new(
      fs::File::open("test-ca/rsa/end.rsa").unwrap()
    )
  ).unwrap()[0].clone()
}

#[derive(PartialEq, Clone)]
enum ClientAuth {
  No,
  Yes
}

#[derive(PartialEq, Clone)]
enum Resumption {
  No,
  SessionID,
  Tickets
}

impl Resumption {
  fn label(&self) -> &'static str {
    match *self {
      Resumption::No => "no-resume",
      Resumption::SessionID => "sessionid",
      Resumption::Tickets => "tickets"
    }
  }
}

fn make_server_config(clientauth: &ClientAuth, resume: &Resumption) -> ServerConfig {
  let mut cfg = ServerConfig::new();
  
  cfg.set_single_cert(get_chain(), get_key());

  if clientauth == &ClientAuth::Yes {
    cfg.set_client_auth_roots(get_chain(), true);
  }

  if resume == &Resumption::SessionID {
    cfg.set_persistence(ServerSessionMemoryCache::new(128));
  } else if resume == &Resumption::Tickets {
    cfg.ticketer = Ticketer::new();
  }

  cfg
}

fn make_client_config(suite: &'static rustls::SupportedCipherSuite,
                      clientauth: &ClientAuth,
                      resume: &Resumption) -> ClientConfig {
  let mut cfg = ClientConfig::new();
  let mut rootbuf = io::BufReader::new(
    fs::File::open("test-ca/rsa/ca.cert").unwrap()
  );
  cfg.root_store.add_pem_file(&mut rootbuf).unwrap();
  cfg.ciphersuites.clear();
  cfg.ciphersuites.push(suite);

  if clientauth == &ClientAuth::Yes {
    cfg.set_single_client_cert(get_chain(), get_key());
  }

  if resume != &Resumption::No {
    cfg.set_persistence(ClientSessionMemoryCache::new(128));
  }

  cfg
}

fn bench_handshake(suite: &'static rustls::SupportedCipherSuite, clientauth: ClientAuth, resume: Resumption) {
  let client_config = Arc::new(make_client_config(suite, &clientauth, &resume));
  let server_config = Arc::new(make_server_config(&clientauth, &resume));

  let rounds = 512;
  let mut client_time = 0f64;
  let mut server_time = 0f64;

  for _ in 0..rounds {
    let mut client = ClientSession::new(&client_config, "localhost");
    let mut server = ServerSession::new(&server_config);

    server_time += time(|| {
      transfer(&mut client, &mut server);
      server.process_new_packets().unwrap()
    });
    client_time += time(|| {
      transfer(&mut server, &mut client);
      client.process_new_packets().unwrap()
    });
    server_time += time(|| {
      transfer(&mut client, &mut server);
      server.process_new_packets().unwrap()
    });
    client_time += time(|| {
      transfer(&mut server, &mut client);
      client.process_new_packets().unwrap()
    });
  }

  println!("handshakes\t{:?}\tclient\t{}\t{}\t{:.2}\thandshake/s",
           suite.suite,
           if clientauth == ClientAuth::Yes { "mutual" } else { "server-auth" },
           resume.label(),
           rounds as f64 / client_time);
  println!("handshakes\t{:?}\tserver\t{}\t{}\t{:.2}\thandshake/s",
           suite.suite,
           if clientauth == ClientAuth::Yes { "mutual" } else { "server-auth" },
           resume.label(),
           rounds as f64 / server_time);
}

fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) {
  assert_eq!(server.is_handshaking(), true);
  assert_eq!(client.is_handshaking(), true);
  transfer(client, server);
  server.process_new_packets().unwrap();
  assert_eq!(server.is_handshaking(), true);
  assert_eq!(client.is_handshaking(), true);
  transfer(server, client);
  client.process_new_packets().unwrap();
  assert_eq!(server.is_handshaking(), true);
  assert_eq!(client.is_handshaking(), true);
  transfer(client, server);
  server.process_new_packets().unwrap();
  assert_eq!(server.is_handshaking(), false);
  assert_eq!(client.is_handshaking(), true);
  transfer(server, client);
  client.process_new_packets().unwrap();
  assert_eq!(server.is_handshaking(), false);
  assert_eq!(client.is_handshaking(), false);
}

fn bench_bulk(suite: &'static rustls::SupportedCipherSuite) {
  let client_config = Arc::new(make_client_config(suite, &ClientAuth::No, &Resumption::No));
  let server_config = Arc::new(make_server_config(&ClientAuth::No, &Resumption::No));

  let mut client = ClientSession::new(&client_config, "localhost");
  let mut server = ServerSession::new(&server_config);

  do_handshake(&mut client, &mut server);

  let mut buf = Vec::new();
  buf.resize(1024 * 1024, 0u8);

  let total_mb = 512;
  let mut time_send = 0f64;
  let mut time_recv = 0f64;

  for _ in 0..total_mb {
    time_send += time(|| { server.write(&buf).unwrap(); () });
    time_recv += time(|| {
      transfer(&mut server, &mut client);
      client.process_new_packets().unwrap()
    });
    drain(&mut client, buf.len());
  }

  println!("bulk\t{:?}\tsend\t{:.2}\tMB/s", suite.suite, total_mb as f64 / time_send);
  println!("bulk\t{:?}\trecv\t{:.2}\tMB/s", suite.suite, total_mb as f64 / time_recv);
}

fn main() {
  for suite in rustls::ALL_CIPHERSUITES.iter() {
    if suite.sign != SignatureAlgorithm::RSA {
      /* TODO: Need ECDSA server support for this. */
      continue;
    }

    bench_bulk(suite);
    bench_handshake(suite, ClientAuth::No, Resumption::No);
    bench_handshake(suite, ClientAuth::Yes, Resumption::No);
    bench_handshake(suite, ClientAuth::No, Resumption::SessionID);
    bench_handshake(suite, ClientAuth::Yes, Resumption::SessionID);
    bench_handshake(suite, ClientAuth::No, Resumption::Tickets);
    bench_handshake(suite, ClientAuth::Yes, Resumption::Tickets);
  }
}
