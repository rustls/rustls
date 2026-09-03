// This is a test shim for the BoringSSL-Go ('bogo') TLS
// test suite. See bogo/ for this in action.
//
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

use core::any::Any;
use core::fmt::{Debug, Formatter};
use core::hash::Hasher;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::{env, net, process, thread, time};

#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use rustls::client::danger::{HandshakeSignatureValid, ServerIdentity, ServerVerifier};
use rustls::client::{
    self, ClientConfig, ClientConnection, ClientSessionKey, CredentialRequest, EchConfig,
    EchGreaseConfig, EchMode, EchStatus, Resumption, Tls12Resumption, Tls13Session,
    WebPkiServerVerifier,
};
use rustls::crypto::hpke::{Hpke, HpkePublicKey};
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{
    Credentials, CryptoProvider, Identity, SelectedCredential, SignatureScheme, Signer, SigningKey,
    SingleCredential, VerifiedIdentity, WebPkiSupportedAlgorithms,
};
use rustls::enums::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CertificateType, ProtocolVersion,
};
use rustls::error::{
    AlertDescription, ApiMisuse, CertificateError, EncryptedClientHelloError, Error,
    InvalidMessage, PeerIncompatible, PeerMisbehaved,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer};
use rustls::server::danger::{ClientIdentity, ClientVerifier, SignatureVerificationInput};
use rustls::server::{
    self, ClientHello, PreferClientOrder, PreferServerOrder, ServerConfig, ServerConnection,
    ServerSessionKey, Tls13Tickets, WebPkiClientVerifier,
};
use rustls::{
    Connection, DistinguishedName, HandshakeKind, IoState, RootCertStore, TlsInputBuffer, VecInput,
    compress,
};
use rustls_aws_lc_rs::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P256_SHA512, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
    ECDSA_P384_SHA512, ECDSA_P521_SHA256, ECDSA_P521_SHA384, ECDSA_P521_SHA512, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY, hpke,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

mod opts;
use opts::Options;

pub fn main() {
    let mut args: Vec<_> = env::args().collect();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    args.remove(0);

    if !args.is_empty() && args[0] == "-is-handshaker-supported" {
        println!("No");
        process::exit(0);
    }
    println!("options: {args:?}");

    let mut opts = Options::new();

    while !args.is_empty() {
        opts.parse_one(&mut args);
    }

    if opts.side == Side::Client
        && opts.on_initial_expect_curve_id != opts.on_resume_expect_curve_id
    {
        // expecting server to HRR us to its desired curve
        opts.expect_handshake_kind_resumed =
            Some(vec![HandshakeKind::ResumedWithHelloRetryRequest]);
    }

    println!("opts {opts:?}");

    #[cfg(unix)]
    if opts.wait_for_debugger {
        // On Unix systems when -wait-for-debugger is passed from the BoGo runner
        // we should SIGSTOP ourselves to allow a debugger to attach to the shim to
        // continue the testing process.
        signal::kill(Pid::from_raw(process::id() as i32), Signal::SIGSTOP).unwrap();
    }

    let key_log = Arc::new(KeyLogMemo::default());
    let mut config = match opts.side {
        Side::Client => SideConfig::Client(make_client_cfg(&opts, &key_log)),
        Side::Server => SideConfig::Server(make_server_cfg(&opts, &key_log)),
    };

    for i in 0..opts.resumes + 1 {
        assert!(opts.quic_transport_params.is_empty());
        assert!(
            opts.expect_quic_transport_params
                .is_empty()
        );

        match &config {
            SideConfig::Client(config) => {
                let server_name = ServerName::try_from(opts.host_name.as_str())
                    .unwrap()
                    .to_owned();
                let mut output = Vec::new();
                let sess = config
                    .connect(server_name)
                    .build(&mut output)
                    .unwrap();
                exec(&opts, sess, output, &key_log, i);
            }
            SideConfig::Server(config) => {
                let sess = ServerConnection::new(config.clone()).unwrap();
                exec(&opts, sess, Vec::new(), &key_log, i);
            }
        }

        if opts.resume_with_tickets_disabled {
            opts.tickets = false;

            match &mut config {
                SideConfig::Server(server) => *server = make_server_cfg(&opts, &key_log),
                SideConfig::Client(client) => *client = make_client_cfg(&opts, &key_log),
            };
        }

        if opts.on_resume_ech_config_list.is_some() {
            opts.ech_config_list
                .clone_from(&opts.on_resume_ech_config_list);
            opts.expect_ech_accept = opts.on_resume_expect_ech_accept;
            if let SideConfig::Client(client_cfg) = &mut config {
                *client_cfg = make_client_cfg(&opts, &key_log);
            }
        }

        opts.expect_handshake_kind
            .clone_from(&opts.expect_handshake_kind_resumed);
    }
}

fn exec(
    opts: &Options,
    mut sess: impl Connection + 'static,
    mut output: Vec<u8>,
    key_log: &KeyLogMemo,
    count: usize,
) {
    let mut sent_message = false;

    let addrs = [
        net::SocketAddr::from((net::Ipv6Addr::LOCALHOST, opts.port)),
        net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, opts.port)),
    ];
    let mut conn = net::TcpStream::connect(&addrs[..]).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut sent_exporter = false;
    let mut sent_key_update = false;
    let mut quench_writes = false;
    let mut pending = Vec::new();

    conn.write_all(&opts.shim_id.to_le_bytes())
        .unwrap();

    let mut input = VecInput::default();
    loop {
        let mut buf = Vec::with_capacity(1024);
        let mut state = None;
        if !sent_message && (opts.queue_data || (opts.queue_data_on_resume && count > 0)) {
            if !opts
                .queue_early_data_after_received_messages
                .is_empty()
            {
                flush(&mut output, &mut conn);
                for message_size_estimate in &opts.queue_early_data_after_received_messages {
                    state = read_n_bytes(
                        &mut buf,
                        opts,
                        &mut input,
                        &mut output,
                        &mut pending,
                        &mut sess,
                        &mut conn,
                        *message_size_estimate,
                    );
                }
                println!("now ready for early data");
            }

            let (message, repeat) = opts.initial_write(count);

            if count > 0 && opts.enable_early_data {
                for _ in 0..repeat {
                    let len = client(&mut sess)
                        .early_data()
                        .expect("0rtt not available")
                        .write(message.into(), &mut output);
                    write_or_queue(&mut sess, &message[len..], &mut pending, &mut output).unwrap();
                }
                sent_message = true;
            } else if !opts.only_write_one_byte_after_handshake {
                for _ in 0..repeat {
                    let _ = write_or_queue(&mut sess, message, &mut pending, &mut output);
                }
                sent_message = true;
            }
        }

        if !quench_writes {
            flush(&mut output, &mut conn);
        }

        if sess.wants_read() {
            state = read_all_bytes(
                &mut buf,
                opts,
                &mut input,
                &mut output,
                &mut pending,
                &mut sess,
                &mut conn,
            );
        }

        if let Some(state) = state {
            if state.peer_has_closed() {
                if opts.check_close_notify {
                    println!("close notify ok");
                }
                println!("EOF (tls)");
                return;
            } else if input.has_seen_eof() {
                if opts.check_close_notify {
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                }
                println!("EOF (tcp)");
                return;
            }
        }

        if opts.side == Side::Server
            && opts.enable_early_data
            && let Some(ed) = &mut server(&mut sess).early_data()
        {
            let mut data = Vec::new();
            let data_len = ed
                .read_to_end(&mut data)
                .expect("cannot read early_data");

            for b in data.iter_mut() {
                *b ^= 0xff;
            }

            write_or_queue(&mut sess, &data[..data_len], &mut pending, &mut output)
                .expect("cannot echo early_data in 1rtt data");
        }

        if !sess.is_handshaking() && opts.export_keying_material > 0 && !sent_exporter {
            let mut export = vec![0; opts.export_keying_material];
            sess.exporter()
                .unwrap()
                .derive(
                    opts.export_keying_material_label
                        .as_bytes(),
                    if opts.export_keying_material_context_used {
                        Some(
                            opts.export_keying_material_context
                                .as_bytes(),
                        )
                    } else {
                        None
                    },
                    &mut export,
                )
                .unwrap();
            sess.write((&export).into(), &mut output)
                .unwrap();
            sent_exporter = true;
        }

        if !sess.is_handshaking() && opts.export_traffic_secrets && !sent_exporter {
            let secrets = key_log.clone_inner();
            assert_eq!(
                secrets.client_traffic_secret.len(),
                secrets.server_traffic_secret.len()
            );
            sess.write(
                (&(secrets.client_traffic_secret.len() as u16).to_le_bytes()).into(),
                &mut output,
            )
            .unwrap();
            sess.write((&secrets.server_traffic_secret).into(), &mut output)
                .unwrap();
            sess.write((&secrets.client_traffic_secret).into(), &mut output)
                .unwrap();
            sent_exporter = true;
        }

        if opts.send_key_update && !sent_key_update && !sess.is_handshaking() {
            sess.refresh_traffic_keys(&mut output)
                .unwrap();
            sent_key_update = true;
        }

        if !sess.is_handshaking() && opts.only_write_one_byte_after_handshake && !sent_message {
            println!("writing message and then only one byte of its tls frame");
            flush(&mut output, &mut conn);

            sess.write(b"hello".into(), &mut output)
                .unwrap();
            sent_message = true;

            conn.write_all(&output[..1])
                .expect("IO error");
            output.drain(..1);

            quench_writes = true;
        }

        if opts.enable_early_data
            && opts.side == Side::Client
            && !sess.is_handshaking()
            && count > 0
        {
            if opts.expect_accept_early_data && !client(&mut sess).is_early_data_accepted() {
                quit_err("Early data was not accepted, but we expect the opposite");
            } else if opts.expect_reject_early_data && client(&mut sess).is_early_data_accepted() {
                quit_err("Early data was accepted, but we expect the opposite");
            }
            if opts.expect_version == 0x0304 {
                match sess.protocol_version() {
                    Some(ProtocolVersion::TLSv1_3) | Some(ProtocolVersion(0x7f17)) => {}
                    _ => quit_err("wrong protocol version"),
                }
            }
        }

        if let (Some(expected_options), false) =
            (opts.expect_handshake_kind.as_ref(), sess.is_handshaking())
        {
            let actual = sess.handshake_kind().unwrap();
            assert!(
                expected_options.contains(&actual),
                "wanted to see {expected_options:?} but got {actual:?}"
            );
        }

        if let Some(curve_id) = &opts.expect_curve_id {
            // unlike openssl/boringssl's API, `negotiated_key_exchange_group`
            // works for the connection, not session.  this means TLS1.2
            // resumptions never have a value for `negotiated_key_exchange_group`
            let tls12_resumed = sess.protocol_version() == Some(ProtocolVersion::TLSv1_2)
                && sess.handshake_kind() == Some(HandshakeKind::Resumed);
            let negotiated_key_exchange_group_ready = !(sess.is_handshaking() || tls12_resumed);

            if negotiated_key_exchange_group_ready {
                let actual = sess
                    .negotiated_key_exchange_group()
                    .expect("no kx with -expect-curve-id");
                assert_eq!(curve_id, &actual.name());
            }
        }

        if let Some(curve_id) = &opts.on_initial_expect_curve_id
            && !sess.is_handshaking()
            && count == 0
        {
            assert_eq!(sess.handshake_kind().unwrap(), HandshakeKind::Full);
            assert_eq!(
                sess.negotiated_key_exchange_group()
                    .expect("no kx with -on-initial-expect-curve-id")
                    .name(),
                *curve_id
            );
        }

        if let Some(curve_id) = &opts.on_resume_expect_curve_id
            && !sess.is_handshaking()
            && count > 0
        {
            assert!(matches!(
                sess.handshake_kind().unwrap(),
                HandshakeKind::Resumed | HandshakeKind::ResumedWithHelloRetryRequest
            ));
            assert_eq!(
                sess.negotiated_key_exchange_group()
                    .expect("no kx with -on-resume-expect-curve-id")
                    .name(),
                *curve_id
            );
        }

        {
            let ech_accept_required =
                (count == 0 && opts.on_initial_expect_ech_accept) || opts.expect_ech_accept;
            if ech_accept_required
                && !sess.is_handshaking()
                && client(&mut sess).ech_status() != EchStatus::Accepted
            {
                quit_err("ECH was not accepted, but we expect the opposite");
            }
        }

        if opts.shut_down_after_handshake && !sent_shutdown && !sess.is_handshaking() {
            sess.send_close_notify(&mut output);
            sent_shutdown = true;
        }

        if quench_writes && !buf.is_empty() {
            println!("unquenching writes after {:?}", buf.len());
            quench_writes = false;
        }

        for b in buf.iter_mut() {
            *b ^= 0xff;
        }

        write_or_queue(&mut sess, &buf, &mut pending, &mut output).unwrap();
    }
}

enum SideConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

fn client(conn: &mut dyn Any) -> &mut ClientConnection {
    conn.downcast_mut::<ClientConnection>()
        .unwrap()
}

fn server(conn: &mut dyn Any) -> &mut ServerConnection {
    conn.downcast_mut::<ServerConnection>()
        .unwrap()
}

/// Encrypt `plaintext` into `output`, or queue it in `pending` if the handshake
/// is still in progress.
///
/// Queued plaintext is sent by `after_read()` once the handshake completes.
fn write_or_queue(
    sess: &mut impl Connection,
    plaintext: &[u8],
    pending: &mut Vec<u8>,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if plaintext.is_empty() {
        return Ok(());
    }

    match sess.write(plaintext.into(), output) {
        Err(Error::ApiMisuse(ApiMisuse::WriteTlsBeforeHandshakeComplete)) => {
            pending.extend_from_slice(plaintext);
            Ok(())
        }
        rc => rc,
    }
}

fn read_n_bytes(
    buf: &mut Vec<u8>,
    opts: &Options,
    input: &mut VecInput,
    output: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    sess: &mut impl Connection,
    conn: &mut net::TcpStream,
    n: usize,
) -> Option<IoState> {
    let mut bytes = [0u8; MAX_MESSAGE_SIZE];
    match conn.read(&mut bytes[..n]) {
        Ok(count) => {
            println!("read {count:?} bytes");
            input
                .read(&mut io::Cursor::new(&mut bytes[..count]))
                .expect("failed reading from buffer");
        }
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("invalid read: {err}"),
    };

    after_read(buf, opts, input, output, pending, sess, conn)
}

fn read_all_bytes(
    buf: &mut Vec<u8>,
    opts: &Options,
    input: &mut VecInput,
    output: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    sess: &mut impl Connection,
    conn: &mut net::TcpStream,
) -> Option<IoState> {
    match input.read(conn) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("invalid read: {err}"),
    };

    after_read(buf, opts, input, output, pending, sess, conn)
}

fn after_read(
    buf: &mut Vec<u8>,
    opts: &Options,
    input: &mut VecInput,
    output: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    sess: &mut impl Connection,
    conn: &mut net::TcpStream,
) -> Option<IoState> {
    let state = match sess
        .read_tls(input, output)
        .handle_all(buf)
    {
        Ok(state) => state,
        Err(error) => {
            flush(output, conn); /* send any alerts before exiting */
            orderly_close(conn);
            handle_err(opts, error);
        }
    };

    if !pending.is_empty() {
        match sess.write(pending.as_slice().into(), output) {
            Ok(()) => pending.clear(),
            Err(Error::ApiMisuse(ApiMisuse::WriteTlsBeforeHandshakeComplete)) => {}
            Err(err) => panic!("cannot send queued plaintext: {err:?}"),
        }
    }

    Some(state)
}

fn flush(output: &mut Vec<u8>, conn: &mut net::TcpStream) {
    if !output.is_empty() {
        if let Err(err) = conn.write_all(output) {
            println!("IO error: {err:?}");
            process::exit(0);
        }
        output.clear();
    }
    conn.flush().unwrap();
}

fn orderly_close(conn: &mut net::TcpStream) {
    // assuming we just flush()'d, we will write no more.
    let _ = conn.shutdown(net::Shutdown::Write);

    // wait for EOF
    let mut buf = [0u8; 32];
    while let Ok(p @ 1..) = conn.peek(&mut buf) {
        let _ = conn.read(&mut buf[..p]).unwrap();
    }

    let _ = conn.shutdown(net::Shutdown::Read);
}

#[derive(Debug, Default)]
struct CredentialSet {
    default: Credential,
    additional: Vec<Credential>,
    /// Some(-1) means `default`, otherwise index into `additional`
    expect_selected: Option<isize>,
}

impl CredentialSet {
    fn last_mut(&mut self) -> &mut Credential {
        self.additional
            .last_mut()
            .unwrap_or(&mut self.default)
    }

    fn configured(&self) -> bool {
        self.default.configured()
            || self
                .additional
                .iter()
                .any(|cred| cred.configured())
    }
}

#[derive(Clone, Debug, Default)]
struct Credential {
    key_file: String,
    cert_file: String,
    use_signing_scheme: Option<u16>,
    must_match_issuer: bool,
}

impl Credential {
    fn load_from_file(&self, provider: &CryptoProvider) -> Credentials {
        let certs = CertificateDer::pem_file_iter(&self.cert_file)
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect::<Vec<_>>();
        let key = PrivateKeyDer::from_pem_file(&self.key_file).unwrap();
        Credentials::from_der(
            Arc::from(Identity::from_cert_chain(certs).unwrap()),
            key,
            provider,
        )
        .unwrap()
    }

    fn configured(&self) -> bool {
        !self.cert_file.is_empty() && !self.key_file.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SelectedProvider {
    AwsLcRs,
    #[cfg_attr(not(feature = "fips"), allow(dead_code))]
    AwsLcRsFips,
    Ring,
}

impl SelectedProvider {
    fn provider(&self) -> CryptoProvider {
        match self {
            Self::AwsLcRs | Self::AwsLcRsFips => {
                // ensure all suites and kx groups are included (even in fips builds)
                // as non-fips test cases require them.  runner activates fips mode via -fips-202205 option
                // this includes rustls-post-quantum, which just returns an altered
                // version of `aws_lc_rs::default_provider()`
                CryptoProvider {
                    kx_groups: Cow::Borrowed(rustls_aws_lc_rs::ALL_KX_GROUPS),
                    tls12_cipher_suites: Cow::Borrowed(rustls_aws_lc_rs::ALL_TLS12_CIPHER_SUITES),
                    tls13_cipher_suites: Cow::Borrowed(rustls_aws_lc_rs::ALL_TLS13_CIPHER_SUITES),
                    signature_verification_algorithms: SUPPORTED_SIG_ALGS,
                    ..rustls_aws_lc_rs::DEFAULT_PROVIDER
                }
            }

            Self::Ring => rustls_ring::DEFAULT_PROVIDER,
        }
    }

    fn supports_ech(&self) -> bool {
        match *self {
            Self::AwsLcRs | Self::AwsLcRsFips => true,
            Self::Ring => false,
        }
    }
}

// aws-lc-rs signature algorithms, with ML-DSA disabled
pub(crate) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms =
    match WebPkiSupportedAlgorithms::new(
        &[
            ECDSA_P256_SHA256,
            ECDSA_P256_SHA384,
            ECDSA_P256_SHA512,
            ECDSA_P384_SHA256,
            ECDSA_P384_SHA384,
            ECDSA_P384_SHA512,
            ECDSA_P521_SHA256,
            ECDSA_P521_SHA384,
            ECDSA_P521_SHA512,
            ED25519,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
            RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
            RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
        ],
        &[
            // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
            ),
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                &[ECDSA_P521_SHA512, ECDSA_P384_SHA512, ECDSA_P256_SHA512],
            ),
            (SignatureScheme::ED25519, &[ED25519]),
            (
                SignatureScheme::RSA_PSS_SHA512,
                &[RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA384,
                &[RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA256,
                &[RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA512,
                &[RSA_PKCS1_2048_8192_SHA512],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                &[RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                &[RSA_PKCS1_2048_8192_SHA256],
            ),
        ],
    ) {
        Ok(algs) => algs,
        Err(_) => panic!("bad WebPkiSupportedAlgorithms"),
    };

fn load_root_certs(filename: &str) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();

    // -verify-peer can be used without specifying a root cert,
    // to test (eg) client auth without actually looking at the certs.
    //
    // but WebPkiClientVerifier requires a non-empty set of roots.
    //
    // use an unrelated cert we have lying around.
    let filename = match filename {
        "" => "../../../../../test-ca/rsa-2048/ca.cert",
        filename => filename,
    };

    roots.add_parsable_certificates(
        CertificateDer::pem_file_iter(filename)
            .unwrap()
            .map(|item| item.unwrap()),
    );
    Arc::new(roots)
}

#[derive(Debug)]
struct DummyClientAuth {
    mandatory: bool,
    root_hint_subjects: Arc<[DistinguishedName]>,
    parent: Arc<dyn ClientVerifier>,
}

impl DummyClientAuth {
    fn new(
        trusted_cert_file: &str,
        mandatory: bool,
        root_hint_subjects: Arc<[DistinguishedName]>,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            mandatory,
            root_hint_subjects,
            parent: Arc::new(
                WebPkiClientVerifier::builder(load_root_certs(trusted_cert_file), provider)
                    .build()
                    .unwrap(),
            ),
        }
    }
}

impl ClientVerifier for DummyClientAuth {
    fn verify_identity<'a>(
        &self,
        identity: &ClientIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, Error> {
        Ok(VerifiedIdentity::assertion(identity.identity.clone()))
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(input)
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        self.root_hint_subjects.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct DummyServerAuth {
    parent: Arc<dyn ServerVerifier>,
    ocsp: OcspValidation,
    expect_server_names: Vec<ServerName<'static>>,
    server_name_index: AtomicUsize,
}

impl DummyServerAuth {
    fn new(
        trusted_cert_file: &str,
        ocsp: OcspValidation,
        expect_server_names: Vec<ServerName<'static>>,
        provider: &CryptoProvider,
    ) -> Self {
        Self {
            parent: Arc::new(
                WebPkiServerVerifier::builder(load_root_certs(trusted_cert_file), provider)
                    .build()
                    .unwrap(),
            ),
            ocsp,
            expect_server_names,
            server_name_index: AtomicUsize::new(0),
        }
    }
}

impl ServerVerifier for DummyServerAuth {
    fn verify_identity<'a>(
        &self,
        identity: &ServerIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, Error> {
        if !self.expect_server_names.is_empty() {
            let expect_server_name = &self.expect_server_names[self
                .server_name_index
                .fetch_add(1, Ordering::SeqCst)];
            assert_eq!(identity.server_name, expect_server_name);
        }
        if let OcspValidation::Reject = self.ocsp {
            return Err(CertificateError::InvalidOcspResponse.into());
        }
        Ok(VerifiedIdentity::assertion(identity.identity.clone()))
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(input)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        true
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        self.parent.hash_config(h)
    }
}

#[derive(Clone, Copy, Debug, Default)]
enum OcspValidation {
    /// Totally ignore `ocsp_response` value
    #[default]
    None,

    /// Return an error (irrespective of `ocsp_response` value)
    Reject,
}

#[derive(Debug)]
struct FixedSignatureSchemeSigningKey {
    key: Box<dyn SigningKey>,
    scheme: SignatureScheme,
}

impl SigningKey for FixedSignatureSchemeSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            self.key.choose_scheme(&[self.scheme])
        } else {
            self.key.choose_scheme(&[])
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.key.public_key()
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeServerCertResolver {
    credentials: Credentials,
    scheme: SignatureScheme,
}

impl server::ServerCredentialResolver for FixedSignatureSchemeServerCertResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        if !client_hello
            .signature_schemes()
            .contains(&self.scheme)
        {
            return Err(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }

        self.credentials
            .signer(&[self.scheme])
            .ok_or(Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ))
    }
}

#[derive(Debug, Default)]
struct MultipleClientCredentialResolver {
    additional: Vec<ClientCert>,
    default: Option<ClientCert>,
    expect_selected: Option<isize>,
}

impl MultipleClientCredentialResolver {
    fn add(&mut self, key: Credentials, meta: &Credential) {
        self.additional
            .push(ClientCert::new(key, meta));
    }

    fn set_default(&mut self, key: Credentials, meta: &Credential) {
        self.default = Some(ClientCert::new(key, meta));
    }
}

impl client::ClientCredentialResolver for MultipleClientCredentialResolver {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        // `sig_schemes` is in server preference order, so respect that.
        let sig_schemes = request.signature_schemes();
        let root_hint_subjects = request.root_hint_subjects();
        for sig_scheme in sig_schemes.iter().copied() {
            for (i, cert) in self.additional.iter().enumerate() {
                // if the server sends any issuer hints, respect them
                if cert.must_match_issuer && !cert.any_issuer_matches_hints(root_hint_subjects) {
                    continue;
                }

                if let Some(signer) = cert.certkey.signer(&[sig_scheme]) {
                    assert!(
                        Some(i as isize) == self.expect_selected || self.expect_selected.is_none()
                    );
                    return Some(signer);
                }
            }
        }

        if let Some(cert) = &self.default
            && let Some(signer) = cert.certkey.signer(sig_schemes)
        {
            assert!(matches!(self.expect_selected, Some(-1) | None));
            return Some(signer);
        }

        assert_eq!(self.expect_selected, None);

        let all_must_match_issuer = self
            .additional
            .iter()
            .chain(self.default.iter())
            .all(|item| item.must_match_issuer);

        quit(match all_must_match_issuer {
            true => ":NO_MATCHING_ISSUER:",
            false => ":NO_COMMON_SIGNATURE_ALGORITHMS:",
        })
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        match self.default.is_some() || !self.additional.is_empty() {
            true => &[CertificateType::X509],
            false => &[],
        }
    }

    fn hash_config(&self, _: &mut dyn Hasher) {}
}

#[derive(Debug)]
struct ClientCert {
    certkey: Credentials,
    issuer_names: Vec<DistinguishedName>,
    must_match_issuer: bool,
}

impl ClientCert {
    fn new(mut certkey: Credentials, meta: &Credential) -> Self {
        let Identity::X509(id) = &*certkey.identity else {
            panic!("only X.509 client certs supported");
        };

        let mut issuer_names = Vec::new();
        for cert in [&id.end_entity]
            .into_iter()
            .chain(id.intermediates.iter())
        {
            let parsed_cert = webpki::EndEntityCert::try_from(cert).unwrap();
            issuer_names.push(DistinguishedName::in_sequence(parsed_cert.issuer()));
        }

        if let Some(scheme) = meta.use_signing_scheme {
            certkey.key = Box::new(FixedSignatureSchemeSigningKey {
                key: certkey.key,
                scheme: lookup_scheme(scheme),
            });
        }

        Self {
            certkey,
            issuer_names,
            must_match_issuer: meta.must_match_issuer,
        }
    }

    fn any_issuer_matches_hints(&self, hints: &[DistinguishedName]) -> bool {
        hints.iter().any(|dn| {
            self.issuer_names
                .iter()
                .any(|issuer| dn.as_ref() == issuer.as_ref())
        })
    }
}

fn lookup_scheme(scheme: u16) -> SignatureScheme {
    match scheme {
        0x0401 => SignatureScheme::RSA_PKCS1_SHA256,
        0x0501 => SignatureScheme::RSA_PKCS1_SHA384,
        0x0601 => SignatureScheme::RSA_PKCS1_SHA512,
        0x0403 => SignatureScheme::ECDSA_NISTP256_SHA256,
        0x0503 => SignatureScheme::ECDSA_NISTP384_SHA384,
        0x0603 => SignatureScheme::ECDSA_NISTP521_SHA512,
        0x0804 => SignatureScheme::RSA_PSS_SHA256,
        0x0805 => SignatureScheme::RSA_PSS_SHA384,
        0x0806 => SignatureScheme::RSA_PSS_SHA512,
        0x0807 => SignatureScheme::ED25519,
        0x0904 => SignatureScheme::ML_DSA_44,
        0x0905 => SignatureScheme::ML_DSA_65,
        0x0906 => SignatureScheme::ML_DSA_87,
        // TODO: add support for Ed448
        // 0x0808 => SignatureScheme::ED448,
        _ => {
            eprintln!("Unsupported signature scheme {:04x}", scheme);
            process::exit(BOGO_NACK);
        }
    }
}

#[derive(Debug)]
struct ServerCacheWithResumptionDelay {
    delay: u32,
    storage: Arc<dyn server::StoresServerSessions>,
}

impl ServerCacheWithResumptionDelay {
    fn new(delay: u32) -> Arc<Self> {
        Arc::new(Self {
            delay,
            storage: server::ServerSessionMemoryCache::new(32),
        })
    }
}

fn align_time() {
    /* we don't have an injectable clock source in rustls' public api, and
     * resumption timing is in seconds resolution, so tests that use
     * resumption_delay tend to be flickery if the seconds time ticks
     * during this.
     *
     * this function delays until a fresh second ticks, which alleviates
     * this. gross!
     */
    fn sample() -> u64 {
        time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    let start_secs = sample();
    while start_secs == sample() {
        thread::sleep(time::Duration::from_millis(20));
    }
}

impl server::StoresServerSessions for ServerCacheWithResumptionDelay {
    fn put(&self, key: ServerSessionKey<'_>, mut value: Vec<u8>) -> bool {
        // The creation time should be stored directly after the 2-byte version discriminant.
        let creation_time_sec = &mut value[2..10];
        let original = u64::from_be_bytes(creation_time_sec.try_into().unwrap());
        let delayed = original - self.delay as u64;
        creation_time_sec.copy_from_slice(&delayed.to_be_bytes());
        self.storage.put(key, value)
    }

    fn get(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    fn take(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        self.storage.can_cache()
    }
}

fn make_server_cfg(opts: &Options, key_log: &Arc<KeyLogMemo>) -> Arc<ServerConfig> {
    let provider = opts.provider();
    let client_auth =
        if opts.verify_peer || opts.offer_no_client_cas || opts.require_any_client_cert {
            Arc::new(DummyClientAuth::new(
                &opts.trusted_cert_file,
                opts.require_any_client_cert,
                Arc::from(opts.root_hint_subjects.clone()),
                &provider,
            ))
        } else {
            WebPkiClientVerifier::no_client_auth()
        };

    assert!(
        opts.credentials.additional.is_empty(),
        "TODO: server certificate switching not implemented yet"
    );
    let cred = &opts.credentials.default;
    let mut credentials = cred.load_from_file(&provider);
    credentials.ocsp = Some(opts.server_ocsp_response.clone());

    let cert_resolver = match cred.use_signing_scheme {
        Some(scheme) => Arc::new(FixedSignatureSchemeServerCertResolver {
            credentials,
            scheme: lookup_scheme(scheme),
        }) as Arc<dyn server::ServerCredentialResolver>,
        None => Arc::new(SingleCredential::from(credentials)),
    };

    let mut cfg = ServerConfig::builder(Arc::new(provider))
        .with_client_cert_verifier(client_auth)
        .with_server_credential_resolver(cert_resolver)
        .unwrap();

    cfg.session_storage = ServerCacheWithResumptionDelay::new(opts.resumption_delay);
    cfg.max_fragment_size = opts.max_fragment;
    cfg.send_tls13_tickets = Tls13Tickets { default: 1, max: 1 };
    cfg.require_ems = opts.require_ems;
    cfg.cipher_suite_selector = match opts.server_preference {
        true => &PreferServerOrder,
        false => &PreferClientOrder,
    };

    if opts.export_traffic_secrets {
        cfg.key_log = key_log.clone();
    }

    if opts.tickets {
        cfg.ticketer = Some(
            cfg.provider()
                .ticketer_factory
                .ticketer()
                .unwrap(),
        );
    } else if opts.resumes == 0 {
        cfg.session_storage = Arc::new(server::NoServerSessionStorage {});
    }

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| ApplicationProtocol::from(proto.as_bytes()).to_owned())
            .collect::<Vec<_>>();
    }

    if opts.reject_alpn {
        cfg.alpn_protocols = vec![ApplicationProtocol::from(b"invalid")];
    }

    if opts.enable_early_data {
        // see kMaxEarlyDataAccepted in boringssl, which bogo validates
        cfg.max_early_data_size = 14336;
        cfg.send_half_rtt_data = true;
    }

    match opts.install_cert_compression_algs {
        CompressionAlgs::All => {
            cfg.cert_compressors = vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
            cfg.cert_decompressors =
                vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
        }
        CompressionAlgs::One(ShrinkingAlgorithm::ALGORITHM) => {
            cfg.cert_compressors = vec![&ShrinkingAlgorithm];
            cfg.cert_decompressors = vec![&ShrinkingAlgorithm];
        }
        CompressionAlgs::None => {}
        _ => unimplemented!(),
    }

    Arc::new(cfg)
}

struct ClientCacheWithSpecificKxHints {
    delay: u32,
    kx_hint: Option<NamedGroup>,
    storage: Arc<client::ClientSessionMemoryCache>,
}

impl ClientCacheWithSpecificKxHints {
    fn new(delay: u32, kx_hint: Option<NamedGroup>) -> Arc<Self> {
        Arc::new(Self {
            delay,
            kx_hint,
            storage: Arc::new(client::ClientSessionMemoryCache::new(32)),
        })
    }
}

impl client::ClientSessionStore for ClientCacheWithSpecificKxHints {
    fn set_kx_hint(&self, _: ClientSessionKey<'static>, _: NamedGroup) {}
    fn kx_hint(&self, _: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        self.kx_hint
    }

    fn set_tls12_session(&self, key: ClientSessionKey<'static>, mut value: client::Tls12Session) {
        value.rewind_epoch(self.delay);
        self.storage
            .set_tls12_session(key, value);
    }

    fn tls12_session(&self, key: &ClientSessionKey<'_>) -> Option<client::Tls12Session> {
        self.storage.tls12_session(key)
    }

    fn remove_tls12_session(&self, key: &ClientSessionKey<'static>) {
        self.storage.remove_tls12_session(key);
    }

    fn insert_tls13_ticket(&self, key: ClientSessionKey<'static>, mut value: Tls13Session) {
        value.rewind_epoch(self.delay);
        self.storage
            .insert_tls13_ticket(key, value)
    }

    fn take_tls13_ticket(&self, key: &ClientSessionKey<'static>) -> Option<Tls13Session> {
        self.storage.take_tls13_ticket(key)
    }
}

impl Debug for ClientCacheWithSpecificKxHints {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // Note: we omit self.storage here as it may contain sensitive data.
        f.debug_struct("ClientCacheWithoutKxHints")
            .field("delay", &self.delay)
            .finish_non_exhaustive()
    }
}

fn make_client_cfg(opts: &Options, key_log: &Arc<KeyLogMemo>) -> Arc<ClientConfig> {
    let provider = Arc::new(opts.provider());
    let cfg = ClientConfig::builder(provider.clone());

    let cfg = if opts.selected_provider.supports_ech() {
        let ech_cfg = ClientConfig::builder(
            CryptoProvider {
                tls12_cipher_suites: Default::default(),
                ..opts.provider()
            }
            .into(),
        );

        if let Some(ech_config_list) = &opts.ech_config_list {
            let ech_mode = match EchConfig::new(ech_config_list.clone(), ALL_HPKE_SUITES) {
                Ok(ech_config) => EchMode::from(ech_config),
                Err(Error::InvalidEncryptedClientHello(
                    EncryptedClientHelloError::NoCompatibleConfig,
                )) if opts.reject_unusable_ech_config => quit(":UNUSABLE_ECH_CONFIG_LIST:"),
                Err(_) => quit(":INVALID_ECH_CONFIG_LIST:"),
            };

            ech_cfg.with_ech(ech_mode)
        } else if opts.reject_unusable_ech_config {
            // no ech_config_list is a trivial rejection (boringssl has a more complex API that is tested here)
            quit(":UNUSABLE_ECH_CONFIG_LIST:");
        } else if opts.enable_ech_grease {
            let ech_mode = EchMode::Grease(EchGreaseConfig::new(
                GREASE_HPKE_SUITE,
                HpkePublicKey(GREASE_25519_PUBKEY.to_vec()),
            ));

            ech_cfg.with_ech(ech_mode)
        } else {
            cfg
        }
    } else {
        cfg
    };

    let cfg = cfg
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyServerAuth::new(
            &opts.trusted_cert_file,
            opts.ocsp,
            opts.expected_server_names(),
            &provider,
        )));

    let mut cfg = match opts.credentials.configured() {
        true => {
            let mut resolver = MultipleClientCredentialResolver {
                expect_selected: opts.credentials.expect_selected,
                ..Default::default()
            };

            if opts.credentials.default.configured() {
                let cred = &opts.credentials.default;
                resolver.set_default(cred.load_from_file(&provider), cred)
            }

            for cred in opts.credentials.additional.iter() {
                resolver.add(cred.load_from_file(&provider), cred);
            }

            cfg.with_client_credential_resolver(Arc::new(resolver))
                .unwrap()
        }
        false => match cfg.with_no_client_auth() {
            Ok(cfg) => cfg,
            Err(Error::ApiMisuse(ApiMisuse::NoCipherSuitesConfigured))
                if opts.reject_unusable_ech_config =>
            {
                quit(":UNUSABLE_ECH_CONFIG_LIST:")
            }
            Err(other) => panic!("unexpected error {other:?}"),
        },
    };

    cfg.resumption = Resumption::store(ClientCacheWithSpecificKxHints::new(
        opts.resumption_delay,
        opts.server_supported_group_hint,
    ))
    .tls12_resumption(match opts.tickets {
        true => Tls12Resumption::SessionIdOrTickets,
        false => Tls12Resumption::SessionIdOnly,
    });
    cfg.enable_sni = opts.use_sni;
    cfg.max_fragment_size = opts.max_fragment;
    cfg.require_ems = opts.require_ems;
    if opts.export_traffic_secrets {
        cfg.key_log = key_log.clone();
    }

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| ApplicationProtocol::from(proto.as_bytes()).to_owned())
            .collect();
    }

    if opts.enable_early_data {
        cfg.enable_early_data = true;
    }

    match opts.install_cert_compression_algs {
        CompressionAlgs::All => {
            cfg.cert_decompressors =
                vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
            cfg.cert_compressors = vec![&ExpandingAlgorithm, &ShrinkingAlgorithm, &RandomAlgorithm];
        }
        CompressionAlgs::One(ShrinkingAlgorithm::ALGORITHM) => {
            cfg.cert_decompressors = vec![&ShrinkingAlgorithm];
            cfg.cert_compressors = vec![&ShrinkingAlgorithm];
        }
        CompressionAlgs::None => {}
        _ => unimplemented!(),
    }

    Arc::new(cfg)
}

fn quit(why: &str) -> ! {
    eprintln!("{}", why);
    process::exit(0)
}

fn quit_err(why: &str) -> ! {
    eprintln!("{}", why);
    process::exit(1)
}

fn handle_err(opts: &Options, err: Error) -> ! {
    println!("TLS error: {err:?}");

    match err {
        Error::InappropriateHandshakeMessage { .. } | Error::InappropriateMessage { .. } => {
            quit(":UNEXPECTED_MESSAGE:")
        }
        Error::AlertReceived(AlertDescription::RecordOverflow) => {
            quit(":TLSV1_ALERT_RECORD_OVERFLOW:")
        }
        Error::AlertReceived(AlertDescription::HandshakeFailure) => quit(":HANDSHAKE_FAILURE:"),
        Error::AlertReceived(AlertDescription::ProtocolVersion) => quit(":WRONG_VERSION:"),
        Error::AlertReceived(AlertDescription::InternalError) => {
            quit(":PEER_ALERT_INTERNAL_ERROR:")
        }
        Error::InvalidMessage(
            InvalidMessage::MissingData("AlertDescription")
            | InvalidMessage::TrailingData("AlertMessagePayload"),
        ) => quit(":BAD_ALERT:"),
        Error::InvalidMessage(
            InvalidMessage::TrailingData("ChangeCipherSpecPayload") | InvalidMessage::InvalidCcs,
        ) => quit(":BAD_CHANGE_CIPHER_SPEC:"),
        Error::InvalidMessage(
            InvalidMessage::EmptyTicketValue | InvalidMessage::IllegalEmptyList(_),
        ) => quit(":DECODE_ERROR:"),
        Error::InvalidMessage(
            InvalidMessage::InvalidKeyUpdate
            | InvalidMessage::MissingData(_)
            | InvalidMessage::TrailingData(_)
            | InvalidMessage::UnexpectedMessage("HelloRetryRequest")
            | InvalidMessage::NoSignatureSchemes,
        ) => quit(":BAD_HANDSHAKE_MSG:"),
        Error::InvalidMessage(InvalidMessage::UnsupportedCompression) => {
            quit(":UNSUPPORTED_COMPRESSION:")
        }
        Error::InvalidMessage(InvalidMessage::InvalidCertRequest)
        | Error::InvalidMessage(InvalidMessage::InvalidDhParams)
        | Error::InvalidMessage(InvalidMessage::MissingKeyExchange) => quit(":BAD_HANDSHAKE_MSG:"),
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
        | Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        | Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        | Error::InvalidMessage(
            InvalidMessage::MessageTooLarge | InvalidMessage::CertificatePayloadTooLarge,
        ) => quit(":GARBAGE:"),
        Error::InvalidMessage(InvalidMessage::MessageTooShort)
            if opts.enable_ech_grease || opts.ech_config_list.is_some() =>
        {
            quit(":ERROR_PARSING_EXTENSION:")
        }
        Error::InvalidMessage(InvalidMessage::DuplicateExtension(_)) => {
            quit(":DUPLICATE_EXTENSION:")
        }
        Error::InvalidMessage(InvalidMessage::UnknownHelloRetryRequestExtension)
        | Error::InvalidMessage(InvalidMessage::UnknownCertificateExtension)
        | Error::InvalidMessage(InvalidMessage::MisplacedExtension(_)) => {
            quit(":UNEXPECTED_EXTENSION:")
        }
        Error::InvalidMessage(InvalidMessage::UnexpectedMessage(_)) => quit(":GARBAGE:"),
        Error::InvalidMessage(InvalidMessage::PreSharedKeyIsNotFinalExtension) => {
            quit(":PRE_SHARED_KEY_MUST_BE_LAST:")
        }
        Error::InvalidMessage(InvalidMessage::IllegalEmptyCertificateAuthoritiesExtension) => {
            quit(":ERROR_PARSING_EXTENSION:")
        }
        Error::DecryptError if opts.ech_config_list.is_some() => {
            quit(":INCONSISTENT_ECH_NEGOTIATION:")
        }
        Error::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        Error::NoApplicationProtocol => quit(":NO_APPLICATION_PROTOCOL:"),
        Error::PeerIncompatible(
            PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension,
        ) => quit(":UNEXPECTED_EXTENSION:"),
        Error::RejectedEch(rejected_err) => {
            if opts.expect_no_ech_retry_configs {
                assert_eq!(rejected_err.retry_configs(), None);
            }
            if let Some(expected_configs) = &opts.expect_ech_retry_configs {
                assert_eq!(
                    rejected_err.retry_configs().as_ref(),
                    Some(expected_configs)
                );
            }
            quit(":ECH_REJECTED:")
        }
        Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon) => {
            quit(":NO_SHARED_CIPHER:")
        }
        Error::PeerIncompatible(PeerIncompatible::KeyShareExtensionRequired) => {
            quit(":MISSING_KEY_SHARE:")
        }
        Error::PeerIncompatible(_) => quit(":INCOMPATIBLE:"),
        Error::PeerMisbehaved(PeerMisbehaved::MissingPskModesExtension) => {
            quit(":MISSING_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::TooMuchEarlyDataReceived) => {
            quit(":TOO_MUCH_READ_EARLY_DATA:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)
        | Error::PeerMisbehaved(PeerMisbehaved::SignedKxWithWrongAlgorithm) => {
            quit(":WRONG_SIGNATURE_TYPE:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCertCompression) => {
            quit(":UNKNOWN_CERT_COMPRESSION_ALG:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::InvalidCertCompression) => {
            quit(":CERT_DECOMPRESSION_FAILED:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::OfferedDuplicateCertificateCompressions) => {
            quit(":ERROR_PARSING_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCipherSuite) => {
            quit(":WRONG_CIPHER_RETURNED:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::TooManyWarningAlertsReceived) => {
            quit(":TOO_MANY_WARNING_ALERTS:")
        }
        Error::PeerMisbehaved(
            PeerMisbehaved::TooManyConsecutiveHandshakeMessagesAfterHandshake,
        ) => quit(":TOO_MANY_KEY_UPDATES:"),
        Error::PeerMisbehaved(PeerMisbehaved::MissingKeyShare) => quit(":MISSING_KEY_SHARE:"),
        Error::PeerMisbehaved(PeerMisbehaved::OfferedDuplicateKeyShares) => {
            quit(":DUPLICATE_KEY_SHARE:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec) => {
            quit(":ILLEGAL_MIDDLEBOX_CHANGE_CIPHER_SPEC:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::EarlyDataExtensionWithoutResumption) => {
            quit(":UNEXPECTED_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite) => {
            quit(":CIPHER_MISMATCH_ON_EARLY_DATA:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::ServerEchoedCompatibilitySessionId) => {
            quit(":SERVER_ECHOED_INVALID_SESSION_ID:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::TooManyEmptyFragments) => {
            quit(":TOO_MANY_EMPTY_FRAGMENTS:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch)
        | Error::PeerMisbehaved(PeerMisbehaved::UnsolicitedEchExtension) => {
            quit(":UNEXPECTED_EXTENSION:")
        }
        Error::PeerMisbehaved(
            PeerMisbehaved::UnsolicitedEncryptedExtension
            | PeerMisbehaved::UnsolicitedServerHelloExtension
            | PeerMisbehaved::UnexpectedCleartextExtension
            | PeerMisbehaved::UnsolicitedCertExtension,
        ) => quit(":UNEXPECTED_EXTENSION:"),
        Error::PeerMisbehaved(PeerMisbehaved::DisallowedEncryptedExtension) => {
            quit(":ERROR_PARSING_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup) => {
            quit(":ILLEGAL_HELLO_RETRY_REQUEST_WITH_OFFERED_GROUP:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup) => {
            quit(":ILLEGAL_HELLO_RETRY_REQUEST_WITH_UNOFFERED_GROUP:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges) => {
            quit(":EMPTY_HELLO_RETRY_REQUEST:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::DuplicateHelloRetryRequestExtensions) => {
            quit(":DUPLICATE_HELLO_RETRY_REQUEST_EXTENSIONS:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedTls12UsingTls13VersionExtension) => {
            quit(":SELECTED_TLS12_USING_TLS13_VERSION_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::OfferedIncorrectCompressions) => {
            quit(":INVALID_COMPRESSION_LIST:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedCompression) => {
            quit(":UNSUPPORTED_COMPRESSION_ALGORITHM:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::WrongGroupForKeyShare) => quit(":WRONG_CURVE:"),
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedKxGroup) => quit(":WRONG_CURVE:"),
        Error::PeerMisbehaved(PeerMisbehaved::RefusedToFollowHelloRetryRequest) => {
            quit(":WRONG_CURVE:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare) => quit(":BAD_ECPOINT:"),
        Error::PeerMisbehaved(PeerMisbehaved::MessageInterleavedWithHandshakeMessage) => {
            quit(":UNEXPECTED_MESSAGE:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::KeyEpochWithPendingFragment) => {
            quit(":EXCESS_HANDSHAKE_DATA:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::NoCertificatesPresented) => quit(":NO_CERTS:"),
        Error::PeerMisbehaved(PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion) => {
            quit(":WRONG_VERSION_ON_EARLY_DATA:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedUnofferedApplicationProtocol) => {
            quit(":INVALID_ALPN_PROTOCOL:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry) => {
            quit(":SELECTED_DIFFERENT_CIPHERSUITE_AFTER_RETRY:")
        }
        Error::PeerMisbehaved(
            PeerMisbehaved::ResumptionAttemptedWithVariedEms
            | PeerMisbehaved::ResumptionOfferedWithVariedEms,
        ) => quit(":RESUMED_SESSION_WITH_VARIED_EMS:"),
        Error::PeerMisbehaved(PeerMisbehaved::IllegalTlsInnerPlaintext) => {
            quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::SelectedInvalidPsk) => {
            quit(":PSK_IDENTITY_NOT_FOUND:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders) => {
            quit(":PSK_IDENTITY_BINDER_COUNT_MISMATCH:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite) => {
            quit(":OLD_SESSION_PRF_HASH_MISMATCH:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::PskExtensionMustBeLast) => {
            quit(":PRE_SHARED_KEY_MUST_BE_LAST:")
        }
        Error::PeerMisbehaved(
            PeerMisbehaved::IncorrectBinder | PeerMisbehaved::IncorrectFinished,
        ) => quit(":DIGEST_CHECK_FAILED:"),
        Error::PeerMisbehaved(PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints) => {
            quit(":SERVER_HELLO_MUST_OFFER_UNCOMPRESSED_EC_POINTS:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported) => {
            quit(":TLS13_DOWNGRADE:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage) => {
            quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:")
        }
        Error::PeerMisbehaved(
            PeerMisbehaved::IllegalAlertLevel(_, _) | PeerMisbehaved::IllegalWarningAlert(_),
        ) => quit(":BAD_ALERT:"),
        Error::PeerMisbehaved(PeerMisbehaved::IllegalTls13ContentType) => {
            quit(":INVALID_OUTER_RECORD_TYPE:")
        }
        Error::PeerMisbehaved(_) => panic!("!!! please add error mapping for {err:?}"),
        Error::AlertReceived(AlertDescription::UnexpectedMessage) => quit(":BAD_ALERT:"),
        Error::AlertReceived(AlertDescription::DecompressionFailure) => {
            quit_err(":SSLV3_ALERT_DECOMPRESSION_FAILURE:")
        }
        Error::InvalidCertificate(CertificateError::BadEncoding) => {
            quit(":CANNOT_PARSE_LEAF_CERT:")
        }
        Error::InvalidCertificate(CertificateError::BadSignature) => quit(":BAD_SIGNATURE:"),
        Error::InvalidCertificate(
            CertificateError::UnsupportedSignatureAlgorithm { .. }
            | CertificateError::UnsupportedSignatureAlgorithmForPublicKey { .. },
        ) => quit(":WRONG_SIGNATURE_TYPE:"),
        Error::InvalidCertificate(CertificateError::InvalidOcspResponse) => {
            // note: only use is in this file.
            quit(":OCSP_CB_ERROR:")
        }
        Error::InvalidCertificate(e) => quit(&format!(":BAD_CERT: ({e:?})")),
        Error::PeerSentOversizedRecord => quit(":DATA_LENGTH_TOO_LONG:"),
        _ => {
            eprintln!("unhandled error: {:?}", err);
            quit(":FIXME:")
        }
    }
}

#[derive(Debug, Default)]
struct KeyLogMemo(Mutex<KeyLogMemoInner>);

impl KeyLogMemo {
    fn clone_inner(&self) -> KeyLogMemoInner {
        self.0.lock().unwrap().clone()
    }
}

impl rustls::KeyLog for KeyLogMemo {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => {
                self.0
                    .lock()
                    .unwrap()
                    .client_traffic_secret = secret.to_vec()
            }
            "SERVER_TRAFFIC_SECRET_0" => {
                self.0
                    .lock()
                    .unwrap()
                    .server_traffic_secret = secret.to_vec()
            }
            _ => {}
        }
    }

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

#[derive(Clone, Debug, Default)]
struct KeyLogMemoInner {
    client_traffic_secret: Vec<u8>,
    server_traffic_secret: Vec<u8>,
}

#[derive(Debug, PartialEq)]
enum Side {
    Client,
    Server,
}

#[derive(Debug, PartialEq)]
enum CompressionAlgs {
    None,
    All,
    One(u16),
}

#[derive(Debug)]
struct ShrinkingAlgorithm;

impl ShrinkingAlgorithm {
    const ALGORITHM: u16 = 0xff01;
}

impl compress::CertDecompressor for ShrinkingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(Self::ALGORITHM)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() != input.len() + 2 {
            return Err(compress::DecompressionFailed);
        }
        output[..2].copy_from_slice(&[0, 0]);
        output[2..].copy_from_slice(input);
        Ok(())
    }
}

impl compress::CertCompressor for ShrinkingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(Self::ALGORITHM)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        assert_eq!(input[..2], [0, 0]);
        input.drain(0..2);
        Ok(input)
    }
}

#[derive(Debug)]
struct ExpandingAlgorithm;

impl compress::CertDecompressor for ExpandingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff02)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() + 4 != input.len() {
            return Err(compress::DecompressionFailed);
        }
        if input[..4] != [1, 2, 3, 4] {
            return Err(compress::DecompressionFailed);
        }
        output.copy_from_slice(&input[4..]);
        Ok(())
    }
}

impl compress::CertCompressor for ExpandingAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff02)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        input.insert(0, 1);
        input.insert(1, 2);
        input.insert(2, 3);
        input.insert(3, 4);
        Ok(input)
    }
}

#[derive(Debug)]
struct RandomAlgorithm;

impl compress::CertDecompressor for RandomAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff03)
    }

    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), compress::DecompressionFailed> {
        if output.len() + 1 != input.len() {
            return Err(compress::DecompressionFailed);
        }
        output.copy_from_slice(&input[1..]);
        Ok(())
    }
}

impl compress::CertCompressor for RandomAlgorithm {
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm(0xff03)
    }

    fn compress(
        &self,
        mut input: Vec<u8>,
        _: compress::CompressionLevel,
    ) -> Result<Vec<u8>, compress::CompressionFailed> {
        let random_byte = {
            let mut bytes = [0];
            // nb. provider is irrelevant for this use
            rustls_ring::DEFAULT_PROVIDER
                .secure_random
                .fill(&mut bytes)
                .unwrap();
            bytes[0]
        };
        input.insert(0, random_byte);
        Ok(input)
    }
}

static GREASE_HPKE_SUITE: &dyn Hpke = hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;

const GREASE_25519_PUBKEY: &[u8] = &[
    0x67, 0x35, 0xCA, 0x50, 0x21, 0xFC, 0x4F, 0xE6, 0x29, 0x3B, 0x31, 0x2C, 0xB5, 0xE0, 0x97, 0xD8,
    0xD0, 0x58, 0x97, 0xCF, 0x5C, 0x15, 0x12, 0x79, 0x4B, 0xEF, 0x1D, 0x98, 0x52, 0x74, 0xDC, 0x5E,
];

// nb. hpke::ALL_SUPPORTED_SUITES omits fips-incompatible options,
// this includes them. bogo fips tests are activated by -fips-202205
// (and no ech tests use that option)
static ALL_HPKE_SUITES: &[&dyn Hpke] = &[
    hpke::DH_KEM_P256_HKDF_SHA256_AES_128,
    hpke::DH_KEM_P256_HKDF_SHA256_AES_256,
    hpke::DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    hpke::DH_KEM_P384_HKDF_SHA384_AES_128,
    hpke::DH_KEM_P384_HKDF_SHA384_AES_256,
    hpke::DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY1305,
    hpke::DH_KEM_P521_HKDF_SHA512_AES_128,
    hpke::DH_KEM_P521_HKDF_SHA512_AES_256,
    hpke::DH_KEM_P521_HKDF_SHA512_CHACHA20_POLY1305,
    hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
    hpke::DH_KEM_X25519_HKDF_SHA256_AES_256,
    hpke::DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

static BOGO_NACK: i32 = 89;

const MAX_MESSAGE_SIZE: usize = 0xffff + 5;
