/*
 * This is a test shim for the BoringSSL-Go ('bogo') TLS
 * test suite. See bogo/ for this in action.
 *
 * https://boringssl.googlesource.com/boringssl/+/master/ssl/test
 */

extern crate rustls;
extern crate webpki;
extern crate env_logger;

use std::env;
use std::process;
use std::net;
use std::fs;
use std::io;
use std::io::BufReader;
use std::io::{Write, Read};
use std::sync::Arc;

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
  ($($arg:tt)*) => { {
    writeln!(&mut ::std::io::stderr(), $($arg)*).unwrap();
  } }
);

#[derive(Debug)]
struct Options {
  port: u16,
  server: bool,
  resume: bool,
  require_client_cert: bool,
  queue_data: bool,
  host_name: String,
  key_file: String,
  cert_file: String
}

impl Options {
  fn new() -> Options {
    Options {
      port: 0,
      server: false,
      resume: false,
      host_name: "example.com".to_string(),
      queue_data: false,
      require_client_cert: false,
      key_file: "".to_string(),
      cert_file: "".to_string()
    }
  }
}

fn load_cert(filename: &str) -> Vec<Vec<u8>> {
  let certfile = fs::File::open(filename)
    .expect("cannot open certificate file");
  let mut reader = BufReader::new(certfile);
  rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_key(filename: &str) -> Vec<u8> {
  if filename.contains("ecdsa") {
    println_err!("No ECDSA key support");
    process::exit(BOGO_NACK);
  }

  let keyfile = fs::File::open(filename)
    .expect("cannot open private key file");
  let mut reader = BufReader::new(keyfile);
  let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
    .unwrap();
  assert!(keys.len() == 1);
  keys[0].clone()
}

fn make_server_cfg(opts: &Options) -> Arc<rustls::ServerConfig> {
  let mut cfg = rustls::ServerConfig::new();

  let cert = load_cert(&opts.cert_file);
  let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
  cfg.set_single_cert(cert.clone(), key);

  if opts.require_client_cert {
    cfg.set_client_auth_roots(cert, opts.require_client_cert);
  }

  Arc::new(cfg)
}

fn make_client_cfg(opts: &Options) -> Arc<rustls::ClientConfig> {
  let mut cfg = rustls::ClientConfig::new();
  let persist = rustls::ClientSessionMemoryCache::new(32);
  cfg.set_persistence(persist);
  cfg.root_store.add(&load_cert("cert.pem")[0]).unwrap();

  if opts.cert_file.len() > 0 && opts.key_file.len() > 0 {
    let cert = load_cert(&opts.cert_file);
    let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
    cfg.set_single_client_cert(cert, key);
  }

  Arc::new(cfg)
}

fn quit(why: &str) -> ! {
  println_err!("{}", why);
  process::exit(0)
}

fn handle_err(err: rustls::TLSError) -> ! {
  use rustls::TLSError;
  use rustls::internal::msgs::enums::{AlertDescription, ContentType};
  
  match err {
    TLSError::InappropriateHandshakeMessage{..} |
      TLSError::InappropriateMessage{..} => quit(":UNEXPECTED_MESSAGE:"),
    TLSError::AlertReceived(AlertDescription::RecordOverflow) => quit(":TLSV1_ALERT_RECORD_OVERFLOW:"),
    TLSError::CorruptMessagePayload(ContentType::Alert) => quit(":BAD_ALERT:"),
    TLSError::CorruptMessagePayload(ContentType::ChangeCipherSpec) => quit(":BAD_CHANGE_CIPHER_SPEC:"),
    TLSError::CorruptMessage => quit(":GARBAGE:"),
    TLSError::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
    TLSError::NoCertificatesPresented => quit(":NO_CERTS:"),
    TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey) => quit(":BAD_SIGNATURE:"),
    _ => {
      println_err!("unhandled error: {:?}", err);
      quit(":FIXME:")
    }
  }
}

fn exec(opts: &Options, sess: &mut Box<rustls::Session>) {
  if opts.queue_data {
    sess.write(b"hello world")
      .unwrap();
  }

  let mut conn = net::TcpStream::connect(("127.0.0.1", opts.port))
    .expect("cannot connect");

  loop {
    while sess.wants_write() {
      sess.write_tls(&mut conn)
        .expect("write failed");
    }
    
    if sess.wants_read() {
      let len = sess.read_tls(&mut conn)
        .expect("read failed");

      if len == 0 {
        println!("EOF (plain)");
        return;
      }

      match sess.process_new_packets() {
        Err(err) => handle_err(err),
        Ok(_) => {}
      }
    }

    let mut buf = [0u8; 128];
    let len = match sess.read(&mut buf) {
      Ok(len) => len,
      Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
        println!("EOF (tls)");
        return;
      },
      Err(err) => panic!("unhandled read error {:?}", err)
    };

    for i in 0..len {
      buf[i] ^= 0xff;
    }

    sess.write(&buf[..len]).unwrap();
  }
}

fn main() {
  let mut args: Vec<_> = env::args().collect();
  env_logger::init().unwrap();

  args.remove(0);
  println!("options: {:?}", args);

  let mut opts = Options::new();

  while args.len() > 0 {
    let arg = args.remove(0);
    match arg.as_ref() {
      "-port" => {
        opts.port = args.remove(0).parse::<u16>().unwrap();
      },
      "-server" => {
        opts.server = true;
      },
      "-key-file" => {
        opts.key_file = args.remove(0);
      },
      "-cert-file" => {
        opts.cert_file = args.remove(0);
      },
      "-resume" => {
        opts.resume = true;
      },
      "-require-any-client-certificate" => {
        opts.require_client_cert = true;
      },
      "-shim-writes-first" => {
        opts.queue_data = true;
      },
      "-host-name" => {
        opts.host_name = args.remove(0);
      },
      "-enable-all-curves" => {}, /* the default */

      _ => {
        process::exit(BOGO_NACK);
      }
    }
  }

  println!("opts {:?}", opts);

  let server_cfg = if opts.server { Some(make_server_cfg(&opts)) } else { None };
  let client_cfg = if !opts.server { Some(make_client_cfg(&opts)) } else { None };

  let make_session = || {
    if opts.server {
      let s = Box::new(rustls::ServerSession::new(server_cfg.as_ref().unwrap()));
      s as Box<rustls::Session>
    } else {
      let s = Box::new(rustls::ClientSession::new(client_cfg.as_ref().unwrap(), &opts.host_name));
      s as Box<rustls::Session>
    }
  };

  let mut sess1 = make_session();
  exec(&opts, &mut sess1);

  if opts.resume {
    let mut sess2 = make_session();
    exec(&opts, &mut sess2);
  }
}
