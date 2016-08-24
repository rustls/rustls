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
  resumes: usize,
  require_any_client_cert: bool,
  offer_no_client_cas: bool,
  queue_data: bool,
  host_name: String,
  key_file: String,
  cert_file: String,
  protocols: Vec<String>,
  expect_curve: u16
}

impl Options {
  fn new() -> Options {
    Options {
      port: 0,
      server: false,
      resumes: 0,
      host_name: "example.com".to_string(),
      queue_data: false,
      require_any_client_cert: false,
      offer_no_client_cas: false,
      key_file: "".to_string(),
      cert_file: "".to_string(),
      protocols: vec![],
      expect_curve: 0
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

fn split_protocols(protos: &str) -> Vec<String> {
  let mut ret = Vec::new();

  let mut offs = 0;
  while offs < protos.len() {
    let len = protos.as_bytes()[offs] as usize;
    let item = protos[offs+1..offs+1+len].to_string();
    ret.push(item);
    offs += 1 + len;
  }

  ret
}

fn make_server_cfg(opts: &Options) -> Arc<rustls::ServerConfig> {
  let mut cfg = rustls::ServerConfig::new();

  let cert = load_cert(&opts.cert_file);
  let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
  cfg.set_single_cert(cert.clone(), key);

  if opts.offer_no_client_cas {
    cfg.client_auth_offer = true;
  } else if opts.require_any_client_cert {
    cfg.client_auth_offer = true;
    cfg.client_auth_mandatory = true;
  }
  
  if opts.protocols.len() > 0 {
    cfg.set_protocols(&opts.protocols);
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

  if opts.protocols.len() > 0 {
    cfg.set_protocols(&opts.protocols);
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

  println!("TLS error: {:?}", err);
  
  match err {
    TLSError::InappropriateHandshakeMessage{..} |
      TLSError::InappropriateMessage{..} => quit(":UNEXPECTED_MESSAGE:"),
    TLSError::AlertReceived(AlertDescription::RecordOverflow) => quit(":TLSV1_ALERT_RECORD_OVERFLOW:"),
    TLSError::AlertReceived(AlertDescription::HandshakeFailure) => quit(":HANDSHAKE_FAILURE:"),
    TLSError::CorruptMessagePayload(ContentType::Alert) => quit(":BAD_ALERT:"),
    TLSError::CorruptMessagePayload(ContentType::ChangeCipherSpec) => quit(":BAD_CHANGE_CIPHER_SPEC:"),
    TLSError::CorruptMessage => quit(":GARBAGE:"),
    TLSError::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
    TLSError::PeerIncompatibleError(_) => quit(":INCOMPATIBLE:"),
    TLSError::PeerMisbehavedError(_) => quit(":PEER_MISBEHAVIOUR:"),
    TLSError::NoCertificatesPresented => quit(":NO_CERTS:"),
    TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey) => quit(":BAD_SIGNATURE:"),
    TLSError::WebPKIError(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => quit(":WRONG_SIGNATURE_TYPE:"),
    _ => {
      println_err!("unhandled error: {:?}", err);
      quit(":FIXME:")
    }
  }
}

fn flush(sess: &mut Box<rustls::Session>, conn: &mut net::TcpStream) {
  while sess.wants_write() {
    sess.write_tls(conn)
      .expect("write failed");
  }
  conn.flush().unwrap();
}

fn exec(opts: &Options, sess: &mut Box<rustls::Session>) {
  if opts.queue_data {
    sess.write(b"hello world")
      .unwrap();
  }

  let mut conn = net::TcpStream::connect(("127.0.0.1", opts.port))
    .expect("cannot connect");

  loop {
    flush(sess, &mut conn);
    
    if sess.wants_read() {
      let len = sess.read_tls(&mut conn)
        .expect("read failed");

      if len == 0 {
        println!("EOF (plain)");
        return;
      }

      match sess.process_new_packets() {
        Err(err) => {
          flush(sess, &mut conn); /* send any alerts before exiting */
          handle_err(err)
        },
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
      "-resume-count" => {
        opts.resumes = args.remove(0).parse::<usize>().unwrap();
      },
      "-expect-curve-id" | "-expect-peer-signature-algorithm" |
        "-expect-advertised-alpn" | "-expect-alpn" |
        "-expect-server-name" | "-expect-certificate-types" => {
        println!("not checking {} {}; NYI", arg, args.remove(0));
      },
      "-expect-no-session" | "-expect-session-miss" => {},

      "-select-alpn" => {
        opts.protocols.push(args.remove(0));
      }
      "-require-any-client-certificate" => {
        opts.require_any_client_cert = true;
      },
      "-shim-writes-first" => {
        opts.queue_data = true;
      },
      "-host-name" => {
        opts.host_name = args.remove(0);
      },
      "-advertise-alpn" => {
        opts.protocols = split_protocols(&args.remove(0));
      },
      "-use-null-client-ca-list" => {
        opts.offer_no_client_cas = true;
      },

      /* defaults: */
      "-enable-all-curves" | "-renegotiate-ignore" |
        "-decline-alpn" => {},

      /* Not implemented things */
      "-dtls" | "-enable-ocsp-stapling" | "-cipher" |
        "-no-tls13" | "-no-ssl3" | "-max-version" | "-min-version" |
        "-psk" | "-renegotiate-freely" | "-false-start" |
        "-fallback-scsv" | "-implicit-handshake" |
        "-fail-early-callback" | "-install-ddos-callback" |
        "-enable-signed-cert-timestamps" | "-ocsp-response" |
        "-async" | "-advertise-npn" | "-use-early-callback" |
        "-use-old-client-cert-callback" | "-verify-fail" |
        "-verify-peer" | "-expect-channel-id" |
        "-shim-shuts-down" | "-check-close-notify" |
        "-send-channel-id" | "-select-next-proto" |
        "-p384-only" | "-expect-verify-result" | "-send-alert" |
        "-signing-prefs" | "-digest-prefs" |
        "-export-keying-material" | "-tls-unique" |
        "-enable-server-custom-extension" |
        "-enable-client-custom-extension" |
        "-expect-dhe-group-size" | "-use-ticket-callback" |
        "-signed-cert-timestamps" => {
        println!("NYI option {:?}", arg);
        process::exit(BOGO_NACK);
      }

      _ => {
        println!("unhandled option {:?}", arg);
        process::exit(BOGO_NACK + 10);
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

  if opts.server && opts.resumes > 0 {
    println!("server resumption NYI");
    process::exit(BOGO_NACK);
  }

  for _ in 0..opts.resumes+1 {
    let mut sess = make_session();
    exec(&opts, &mut sess);
  }
}
