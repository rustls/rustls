// This is a test shim for the BoringSSL-Go ('bogo') TLS
// test suite. See bogo/ for this in action.
//
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

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
use rustls::internal::msgs::enums::ProtocolVersion;

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
    tickets: bool,
    queue_data: bool,
    host_name: String,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>,
    support_tls13: bool,
    support_tls12: bool,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
    expect_curve: u16,
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resumes: 0,
            tickets: true,
            host_name: "example.com".to_string(),
            queue_data: false,
            require_any_client_cert: false,
            offer_no_client_cas: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            protocols: vec![],
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            expect_curve: 0,
        }
    }

    fn version_allowed(&self, vers: ProtocolVersion) -> bool {
        (self.min_version.is_none() || vers.get_u16() >= self.min_version.unwrap().get_u16()) &&
        (self.max_version.is_none() || vers.get_u16() <= self.max_version.unwrap().get_u16())
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && (self.version_allowed(ProtocolVersion::TLSv1_3) ||
                               self.version_allowed(ProtocolVersion::Unknown(0x7f12)))
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(ProtocolVersion::TLSv1_2)
    }
}

fn load_cert(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_key(filename: &str) -> rustls::PrivateKey {
    if filename.contains("ecdsa") {
        println_err!("No ECDSA key support");
        process::exit(BOGO_NACK);
    }

    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
}

fn split_protocols(protos: &str) -> Vec<String> {
    let mut ret = Vec::new();

    let mut offs = 0;
    while offs < protos.len() {
        let len = protos.as_bytes()[offs] as usize;
        let item = protos[offs + 1..offs + 1 + len].to_string();
        ret.push(item);
        offs += 1 + len;
    }

    ret
}

struct NoVerification {}

impl rustls::ClientCertVerifier for NoVerification {
    fn verify_client_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate]) -> Result<(), rustls::TLSError> {
        Ok(())
    }
}

impl rustls::ServerCertVerifier for NoVerification {
    fn verify_server_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate],
                          _hostname: &str) -> Result<(), rustls::TLSError> {
        Ok(())
    }
}

fn make_server_cfg(opts: &Options) -> Arc<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::new();
    let persist = rustls::ServerSessionMemoryCache::new(32);
    cfg.set_persistence(persist);

    let cert = load_cert(&opts.cert_file);
    let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
    cfg.set_single_cert(cert.clone(), key);

    if opts.offer_no_client_cas || opts.require_any_client_cert {
        cfg.client_auth_offer = true;
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(NoVerification {}));
    }

    if opts.require_any_client_cert {
        cfg.client_auth_mandatory = true;
    }

    if opts.tickets {
        cfg.ticketer = rustls::Ticketer::new();
    }

    if !opts.protocols.is_empty() {
        cfg.set_protocols(&opts.protocols);
    }

    cfg.versions.clear();

    if opts.tls12_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_2);
    }

    if opts.tls13_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_3);
    }

    Arc::new(cfg)
}

fn make_client_cfg(opts: &Options) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::new();
    let persist = rustls::ClientSessionMemoryCache::new(32);
    cfg.set_persistence(persist);
    cfg.root_store.add(&load_cert("cert.pem")[0]).unwrap();

    if !opts.cert_file.is_empty() && !opts.key_file.is_empty() {
        let cert = load_cert(&opts.cert_file);
        let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
        cfg.set_single_client_cert(cert, key);
    }

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoVerification {}));

    if !opts.protocols.is_empty() {
        cfg.set_protocols(&opts.protocols);
    }

    cfg.versions.clear();

    if opts.tls12_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_2);
    }

    if opts.tls13_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_3);
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
        TLSError::InappropriateHandshakeMessage { .. } |
        TLSError::InappropriateMessage { .. } => quit(":UNEXPECTED_MESSAGE:"),
        TLSError::AlertReceived(AlertDescription::RecordOverflow) => {
            quit(":TLSV1_ALERT_RECORD_OVERFLOW:")
        }
        TLSError::AlertReceived(AlertDescription::HandshakeFailure) => quit(":HANDSHAKE_FAILURE:"),
        TLSError::CorruptMessagePayload(ContentType::Alert) => quit(":BAD_ALERT:"),
        TLSError::CorruptMessagePayload(ContentType::ChangeCipherSpec) => {
            quit(":BAD_CHANGE_CIPHER_SPEC:")
        }
        TLSError::CorruptMessagePayload(ContentType::Handshake) => quit(":BAD_HANDSHAKE_MSG:"),
        TLSError::CorruptMessagePayload(ContentType::Unknown(42)) => {
            quit(":GARBAGE:")
        }
        TLSError::CorruptMessage => quit(":GARBAGE:"),
        TLSError::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        TLSError::PeerIncompatibleError(_) => quit(":INCOMPATIBLE:"),
        TLSError::PeerMisbehavedError(_) => quit(":PEER_MISBEHAVIOUR:"),
        TLSError::NoCertificatesPresented => quit(":NO_CERTS:"),
        TLSError::AlertReceived(AlertDescription::UnexpectedMessage) => {
            quit(":BAD_ALERT:")
        }
        TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey) => {
            quit(":BAD_SIGNATURE:")
        }
        TLSError::WebPKIError(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => {
            quit(":WRONG_SIGNATURE_TYPE:")
        }
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
        sess.write_all(b"hello world")
            .unwrap();
    }

    let mut conn = net::TcpStream::connect(("127.0.0.1", opts.port)).expect("cannot connect");

    loop {
        flush(sess, &mut conn);

        if sess.wants_read() {
            let len = sess.read_tls(&mut conn)
                .expect("read failed");

            if len == 0 {
                println!("EOF (plain)");
                return;
            }

            if let Err(err) = sess.process_new_packets() {
                flush(sess, &mut conn); /* send any alerts before exiting */
                handle_err(err);
            }
        }

        let mut buf = [0u8; 128];
        let len = match sess.read(&mut buf) {
            Ok(len) => len,
            Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                println!("EOF (tls)");
                return;
            }
            Err(err) => panic!("unhandled read error {:?}", err),
        };

        for b in buf.iter_mut() {
            *b ^= 0xff;
        }

        sess.write_all(&buf[..len]).unwrap();
    }
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init().unwrap();

    args.remove(0);
    println!("options: {:?}", args);

    let mut opts = Options::new();

    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0);
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);
            }
            "-resume-count" => {
                opts.resumes = args.remove(0).parse::<usize>().unwrap();
            }
            "-no-tls13" => {
                opts.support_tls13 = false;
            }
            "-no-tls12" => {
                opts.support_tls12 = false;
            }
            "-min-version" => {
                let min = args.remove(0).parse::<u16>().unwrap();
                opts.min_version = Some(ProtocolVersion::Unknown(min));
            }
            "-max-version" => {
                let max = args.remove(0).parse::<u16>().unwrap();
                opts.max_version = Some(ProtocolVersion::Unknown(max));
            }
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-certificate-types" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }

            "-select-alpn" => {
                opts.protocols.push(args.remove(0));
            }
            "-require-any-client-certificate" => {
                opts.require_any_client_cert = true;
            }
            "-shim-writes-first" => {
                opts.queue_data = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
            }
            "-advertise-alpn" => {
                opts.protocols = split_protocols(&args.remove(0));
            }
            "-use-null-client-ca-list" => {
                opts.offer_no_client_cas = true;
            }

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" |
            "-enable-ocsp-stapling" |
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |
            "-false-start" |
            "-fallback-scsv" |
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-enable-signed-cert-timestamps" |
            "-ocsp-response" |
            "-advertise-npn" |
            "-verify-fail" |
            "-verify-peer" |
            "-expect-channel-id" |
            "-shim-shuts-down" |
            "-check-close-notify" |
            "-send-channel-id" |
            "-select-next-proto" |
            "-p384-only" |
            "-expect-verify-result" |
            "-send-alert" |
            "-signing-prefs" |
            "-digest-prefs" |
            "-export-keying-material" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-expect-resume-curve-id" |
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-enable-early-data" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-expect-peer-cert-file" |
            "-signed-cert-timestamps" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                process::exit(1);
            }
        }
    }

    println!("opts {:?}", opts);

    let server_cfg = if opts.server {
        Some(make_server_cfg(&opts))
    } else {
        None
    };
    let client_cfg = if !opts.server {
        Some(make_client_cfg(&opts))
    } else {
        None
    };

    let make_session = || {
        if opts.server {
            let s = Box::new(rustls::ServerSession::new(server_cfg.as_ref().unwrap()));
            s as Box<rustls::Session>
        } else {
            let s = Box::new(rustls::ClientSession::new(client_cfg.as_ref().unwrap(),
                                                        &opts.host_name));
            s as Box<rustls::Session>
        }
    };

    for _ in 0..opts.resumes + 1 {
        let mut sess = make_session();
        exec(&opts, &mut sess);
    }
}
