// This is a test shim for the BoringSSL-Go ('bogo') TLS
// test suite. See bogo/ for this in action.
//
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

extern crate rustls;
extern crate webpki;
extern crate env_logger;
extern crate base64;

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
    verify_peer: bool,
    require_any_client_cert: bool,
    offer_no_client_cas: bool,
    tickets: bool,
    queue_data: bool,
    shut_down_after_handshake: bool,
    check_close_notify: bool,
    host_name: String,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>,
    support_tls13: bool,
    support_tls12: bool,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
    server_ocsp_response: Vec<u8>,
    server_sct_list: Vec<u8>,
    expect_curve: u16,
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resumes: 0,
            verify_peer: false,
            tickets: true,
            host_name: "example.com".to_string(),
            queue_data: false,
            shut_down_after_handshake: false,
            check_close_notify: false,
            require_any_client_cert: false,
            offer_no_client_cas: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            protocols: vec![],
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            server_ocsp_response: vec![],
            server_sct_list: vec![],
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
    let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader).unwrap();
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

struct DummyClientAuth {
    mandatory: bool,
}

impl rustls::ClientCertVerifier for DummyClientAuth {
    fn offer_client_auth(&self) -> bool { true }

    fn client_auth_mandatory(&self) -> bool { self.mandatory }

    fn client_auth_root_subjects<'a>(&'a self) -> rustls::DistinguishedNames {
        rustls::DistinguishedNames::new()
    }

    fn verify_client_cert(&self,
                          _certs: &[rustls::Certificate]) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        Ok(rustls::ClientCertVerified::assertion())
    }
}

struct DummyServerAuth {}

impl rustls::ServerCertVerifier for DummyServerAuth {
    fn verify_server_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate],
                          _hostname: webpki::DNSNameRef,
                          _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn make_server_cfg(opts: &Options) -> Arc<rustls::ServerConfig> {
    let client_auth =
        if opts.verify_peer || opts.offer_no_client_cas || opts.require_any_client_cert {
            Arc::new(DummyClientAuth { mandatory: opts.require_any_client_cert })
        } else {
            rustls::NoClientAuth::new()
        };

    let mut cfg = rustls::ServerConfig::new(client_auth);
    let persist = rustls::ServerSessionMemoryCache::new(32);
    cfg.set_persistence(persist);

    let cert = load_cert(&opts.cert_file);
    let key = load_key(&opts.key_file);
    cfg.set_single_cert_with_ocsp_and_sct(cert.clone(), key,
                                          opts.server_ocsp_response.clone(),
                                          opts.server_sct_list.clone());

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
        let key = load_key(&opts.key_file);
        cfg.set_single_client_cert(cert, key);
    }

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(DummyServerAuth {}));

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

fn quit_err(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(1)
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
        TLSError::AlertReceived(AlertDescription::DecompressionFailure) => {
            quit_err(":SSLV3_ALERT_DECOMPRESSION_FAILURE:")
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
        match sess.write_tls(conn) {
            Err(err) => {
                println!("IO error: {:?}", err);
                process::exit(0);
            }
            Ok(_) => {}
        }
    }
    conn.flush().unwrap();
}

fn exec(opts: &Options, sess: &mut Box<rustls::Session>) {
    if opts.queue_data {
        sess.write_all(b"hello world")
            .unwrap();
    }

    let mut conn = net::TcpStream::connect(("127.0.0.1", opts.port)).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut seen_eof = false;

    loop {
        flush(sess, &mut conn);

        if sess.wants_read() {
            let len = sess.read_tls(&mut conn)
                .expect("read failed");

            if len == 0 {
                if opts.check_close_notify {
                    if !seen_eof {
                        seen_eof = true;
                    } else {
                        quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                    }
                } else {
                    println!("EOF (plain)");
                    return;
                }
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
                if opts.check_close_notify {
                    println!("close notify ok");
                }
                println!("EOF (tls)");
                return;
            }
            Err(err) => panic!("unhandled read error {:?}", err),
        };

        if len > 0 &&
            opts.shut_down_after_handshake &&
            !sent_shutdown &&
            !sess.is_handshaking() {
            sess.send_close_notify();
            sent_shutdown = true;
        }

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
            "-expect-resume-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-ocsp-response" |
            "-expect-signed-cert-timestamps" |
            "-expect-certificate-types" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }

            "-ocsp-response" => {
                opts.server_ocsp_response = base64::decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
            }
            "-signed-cert-timestamps" => {
                opts.server_sct_list = base64::decode(args.remove(0).as_bytes())
                    .expect("invalid base64");

                if opts.server_sct_list.len() == 2 &&
                    opts.server_sct_list[0] == 0x00 &&
                    opts.server_sct_list[1] == 0x00 {
                    quit(":INVALID_SCT_LIST:");
                }
            }
            "-select-alpn" => {
                opts.protocols.push(args.remove(0));
            }
            "-require-any-client-certificate" => {
                opts.require_any_client_cert = true;
            }
            "-verify-peer" => {
                opts.verify_peer = true;
            }
            "-shim-writes-first" => {
                opts.queue_data = true;
            }
            "-shim-shuts-down" => {
                opts.shut_down_after_handshake = true;
            }
            "-check-close-notify" => {
                opts.check_close_notify = true;
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
            "-enable-ocsp-stapling" |
            "-enable-signed-cert-timestamps" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" |
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |
            "-false-start" |
            "-fallback-scsv" |
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-advertise-npn" |
            "-verify-fail" |
            "-expect-channel-id" |
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
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-enable-early-data" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-expect-peer-cert-file" => {
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
            let s: Box<rustls::Session> =
                Box::new(rustls::ServerSession::new(server_cfg.as_ref().unwrap()));
            s
        } else {
            let dns_name =
                webpki::DNSNameRef::try_from_ascii_str(&opts.host_name).unwrap();
            let s: Box<rustls::Session> =
                Box::new(rustls::ClientSession::new(client_cfg.as_ref().unwrap(),
                                                    dns_name));
            s
        }
    };

    for _ in 0..opts.resumes + 1 {
        let mut sess = make_session();
        exec(&opts, &mut sess);
    }
}
