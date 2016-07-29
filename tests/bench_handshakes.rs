/* Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
 * etc. because it's unstable at the time of writing. */

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::fs;
use std::io::{self, Write, Read};

extern crate rustls;
use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::Session;
use rustls::internal::pemfile;

fn duration_nanos(d: Duration) -> f64 {
  (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

fn dumphex(why: &str, buf: &[u8]) {
  print!("{}: ", why);

  for byte in buf {
    print!("{:02x}", byte);
  }
  println!("");
}

fn bench<Fsetup, Ftest, S>(count: usize, name: &'static str, f_setup: Fsetup, f_test: Ftest)
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

fn time<F>(what: &str, mut f: F) where F: FnMut() {
  let start = Instant::now();
  f();
  let dur = duration_nanos(Instant::now().duration_since(start));
  println!("{}: {}", what, dur);
}

fn transfer(left: &mut Session, right: &mut Session) {
  let mut buf = [0u8; 32768];

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

fn make_server_config() -> ServerConfig {
  let mut cfg = ServerConfig::new();

  let chain = pemfile::certs(
    &mut io::BufReader::new(
      fs::File::open("test-ca/rsa/end.fullchain").unwrap()
    )
  ).unwrap();

  let key = pemfile::rsa_private_keys(
    &mut io::BufReader::new(
      fs::File::open("test-ca/rsa/end.rsa").unwrap()
    )
  ).unwrap()[0].clone();
  
  cfg.set_single_cert(chain, key);
  cfg
}

fn make_client_config() -> ClientConfig {
  let mut cfg = ClientConfig::new();
  let mut rootbuf = io::BufReader::new(
    fs::File::open("test-ca/rsa/ca.cert").unwrap()
  );
  cfg.root_store.add_pem_file(&mut rootbuf);
  cfg
}

#[test]
fn bench_hs() {
  let client_config = Arc::new(make_client_config());
  let server_config = Arc::new(make_server_config());

  let mut client = ClientSession::new(&client_config, "localhost");
  let mut server = ServerSession::new(&server_config);

  transfer(&mut client, &mut server);
  time("process ClientHello", || server.process_new_packets().unwrap());
  transfer(&mut server, &mut client);
  time("process ServerHello", || client.process_new_packets().unwrap());
  transfer(&mut client, &mut server);
  time("process ClientKX", || server.process_new_packets().unwrap());
  transfer(&mut server, &mut client);
  time("process Finished", || client.process_new_packets().unwrap());
  transfer(&mut client, &mut server);

  let buf = [0u8; 1024 * 1024];
  for _ in 0..4 {
    server.write(&buf).unwrap();
    transfer(&mut server, &mut client);
    time("process 1MB data", || client.process_new_packets().unwrap());
    drain(&mut client, buf.len());
  }
}
