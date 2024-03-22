// This is a test shim for the BoringSSL-Go ('bogo') TLS
// test suite. See bogo/ for this in action.
//
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConfig, ClientConnection, Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::persist::ServerSessionValue;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ServerConfig, ServerConnection, WebPkiClientVerifier};
use rustls::{
    client, server, sign, version, AlertDescription, CertificateError, Connection,
    DigitallySignedStruct, DistinguishedName, Error, InvalidMessage, NamedGroup, PeerIncompatible,
    PeerMisbehaved, ProtocolVersion, RootCertStore, Side, SignatureAlgorithm, SignatureScheme,
    SupportedProtocolVersion,
};

#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
use rustls::crypto::aws_lc_rs as provider;
#[cfg(feature = "ring")]
use rustls::crypto::ring as provider;

use base64::prelude::{Engine, BASE64_STANDARD};
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use std::fmt::{Debug, Formatter};
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use std::time;
use std::{env, fs, net, process, thread};

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
  ($($arg:tt)*) => { {
    writeln!(&mut ::std::io::stderr(), $($arg)*).unwrap();
  } }
);

#[derive(Debug)]
struct Options {
    port: u16,
    side: Side,
    max_fragment: Option<usize>,
    resumes: usize,
    verify_peer: bool,
    require_any_client_cert: bool,
    root_hint_subjects: Vec<DistinguishedName>,
    offer_no_client_cas: bool,
    tickets: bool,
    resume_with_tickets_disabled: bool,
    queue_data: bool,
    queue_data_on_resume: bool,
    only_write_one_byte_after_handshake: bool,
    only_write_one_byte_after_handshake_on_resume: bool,
    shut_down_after_handshake: bool,
    check_close_notify: bool,
    host_name: String,
    use_sni: bool,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>,
    reject_alpn: bool,
    support_tls13: bool,
    support_tls12: bool,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
    server_ocsp_response: Vec<u8>,
    use_signing_scheme: u16,
    curves: Option<Vec<u16>>,
    export_keying_material: usize,
    export_keying_material_label: String,
    export_keying_material_context: String,
    export_keying_material_context_used: bool,
    read_size: usize,
    quic_transport_params: Vec<u8>,
    expect_quic_transport_params: Vec<u8>,
    enable_early_data: bool,
    expect_ticket_supports_early_data: bool,
    expect_accept_early_data: bool,
    expect_reject_early_data: bool,
    expect_version: u16,
    resumption_delay: u32,
    queue_early_data_after_received_messages: Vec<usize>,
}

impl Options {
    fn new() -> Self {
        Options {
            port: 0,
            side: Side::Client,
            max_fragment: None,
            resumes: 0,
            verify_peer: false,
            tickets: true,
            resume_with_tickets_disabled: false,
            host_name: "example.com".to_string(),
            use_sni: false,
            queue_data: false,
            queue_data_on_resume: false,
            only_write_one_byte_after_handshake: false,
            only_write_one_byte_after_handshake_on_resume: false,
            shut_down_after_handshake: false,
            check_close_notify: false,
            require_any_client_cert: false,
            root_hint_subjects: vec![],
            offer_no_client_cas: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            protocols: vec![],
            reject_alpn: false,
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            server_ocsp_response: vec![],
            use_signing_scheme: 0,
            curves: None,
            export_keying_material: 0,
            export_keying_material_label: "".to_string(),
            export_keying_material_context: "".to_string(),
            export_keying_material_context_used: false,
            read_size: 512,
            quic_transport_params: vec![],
            expect_quic_transport_params: vec![],
            enable_early_data: false,
            expect_ticket_supports_early_data: false,
            expect_accept_early_data: false,
            expect_reject_early_data: false,
            expect_version: 0,
            resumption_delay: 0,
            queue_early_data_after_received_messages: vec![],
        }
    }

    fn version_allowed(&self, vers: ProtocolVersion) -> bool {
        (self.min_version.is_none() || vers.get_u16() >= self.min_version.unwrap().get_u16())
            && (self.max_version.is_none() || vers.get_u16() <= self.max_version.unwrap().get_u16())
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && self.version_allowed(ProtocolVersion::TLSv1_3)
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(ProtocolVersion::TLSv1_2)
    }

    fn supported_versions(&self) -> Vec<&'static SupportedProtocolVersion> {
        let mut versions = vec![];

        if self.tls12_supported() {
            versions.push(&version::TLS12);
        }

        if self.tls13_supported() {
            versions.push(&version::TLS13);
        }
        versions
    }
}

fn load_cert(filename: &str) -> Vec<CertificateDer<'static>> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

fn load_key(filename: &str) -> PrivateKeyDer<'static> {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map(|result| result.unwrap())
        .collect::<Vec<_>>();
    assert!(keys.len() == 1);
    keys.pop().unwrap().into()
}

fn load_root_certs() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();

    // this is not actually used by the tests, but must be non-empty
    roots.add_parsable_certificates(load_cert("cert.pem"));

    Arc::new(roots)
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

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .inspect(|x| println!("item {:?}", x))
        .collect()
}

#[derive(Debug)]
struct DummyClientAuth {
    mandatory: bool,
    root_hint_subjects: Vec<DistinguishedName>,
    parent: Arc<dyn ClientCertVerifier>,
}

impl DummyClientAuth {
    fn new(mandatory: bool, root_hint_subjects: Vec<DistinguishedName>) -> Self {
        Self {
            mandatory,
            root_hint_subjects,
            parent: WebPkiClientVerifier::builder_with_provider(
                load_root_certs(),
                provider::default_provider().into(),
            )
            .build()
            .unwrap(),
        }
    }
}

impl ClientCertVerifier for DummyClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct DummyServerAuth {
    parent: Arc<dyn ServerCertVerifier>,
}

impl DummyServerAuth {
    fn new() -> Self {
        DummyServerAuth {
            parent: WebPkiServerVerifier::builder_with_provider(
                load_root_certs(),
                provider::default_provider().into(),
            )
            .build()
            .unwrap(),
        }
    }
}

impl ServerCertVerifier for DummyServerAuth {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _certs: &[CertificateDer<'_>],
        _hostname: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.parent
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeSigningKey {
    key: Arc<dyn sign::SigningKey>,
    scheme: SignatureScheme,
}

impl sign::SigningKey for FixedSignatureSchemeSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn sign::Signer>> {
        if offered.contains(&self.scheme) {
            self.key.choose_scheme(&[self.scheme])
        } else {
            self.key.choose_scheme(&[])
        }
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.key.algorithm()
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeServerCertResolver {
    resolver: Arc<dyn server::ResolvesServerCert>,
    scheme: SignatureScheme,
}

impl server::ResolvesServerCert for FixedSignatureSchemeServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        let mut certkey = self.resolver.resolve(client_hello)?;
        Arc::make_mut(&mut certkey).key = Arc::new(FixedSignatureSchemeSigningKey {
            key: certkey.key.clone(),
            scheme: self.scheme,
        });
        Some(certkey)
    }
}

#[derive(Debug)]
struct FixedSignatureSchemeClientCertResolver {
    resolver: Arc<dyn client::ResolvesClientCert>,
    scheme: SignatureScheme,
}

impl client::ResolvesClientCert for FixedSignatureSchemeClientCertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        if !sigschemes.contains(&self.scheme) {
            quit(":NO_COMMON_SIGNATURE_ALGORITHMS:");
        }
        let mut certkey = self
            .resolver
            .resolve(root_hint_subjects, sigschemes)?;
        Arc::make_mut(&mut certkey).key = Arc::new(FixedSignatureSchemeSigningKey {
            key: certkey.key.clone(),
            scheme: self.scheme,
        });
        Some(certkey)
    }

    fn has_certs(&self) -> bool {
        self.resolver.has_certs()
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
        // TODO: add support for Ed448
        // 0x0808 => SignatureScheme::ED448,
        _ => {
            println_err!("Unsupported signature scheme {:04x}", scheme);
            process::exit(BOGO_NACK);
        }
    }
}

fn lookup_kx_group(group: u16) -> &'static dyn SupportedKxGroup {
    match group {
        0x001d => provider::kx_group::X25519,
        0x0017 => provider::kx_group::SECP256R1,
        0x0018 => provider::kx_group::SECP384R1,
        _ => {
            println_err!("Unsupported kx group {:04x}", group);
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
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let mut ssv = ServerSessionValue::read_bytes(&value).unwrap();
        ssv.creation_time_sec -= self.delay as u64;

        self.storage
            .put(key, ssv.get_encoding())
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        self.storage.can_cache()
    }
}

fn make_server_cfg(opts: &Options) -> Arc<ServerConfig> {
    let client_auth =
        if opts.verify_peer || opts.offer_no_client_cas || opts.require_any_client_cert {
            Arc::new(DummyClientAuth::new(
                opts.require_any_client_cert,
                opts.root_hint_subjects.clone(),
            ))
        } else {
            server::WebPkiClientVerifier::no_client_auth()
        };

    let cert = load_cert(&opts.cert_file);
    let key = load_key(&opts.key_file);

    let kx_groups = if let Some(curves) = &opts.curves {
        curves
            .iter()
            .map(|curveid| lookup_kx_group(*curveid))
            .collect()
    } else {
        provider::ALL_KX_GROUPS.to_vec()
    };

    let mut cfg = ServerConfig::builder_with_provider(
        CryptoProvider {
            kx_groups,
            ..provider::default_provider()
        }
        .into(),
    )
    .with_protocol_versions(&opts.supported_versions())
    .unwrap()
    .with_client_cert_verifier(client_auth)
    .with_single_cert_with_ocsp(cert.clone(), key, opts.server_ocsp_response.clone())
    .unwrap();

    cfg.session_storage = ServerCacheWithResumptionDelay::new(opts.resumption_delay);
    cfg.max_fragment_size = opts.max_fragment;
    cfg.send_tls13_tickets = 1;

    if opts.use_signing_scheme > 0 {
        let scheme = lookup_scheme(opts.use_signing_scheme);
        cfg.cert_resolver = Arc::new(FixedSignatureSchemeServerCertResolver {
            resolver: cfg.cert_resolver.clone(),
            scheme,
        });
    }

    if opts.tickets {
        cfg.ticketer = provider::Ticketer::new().unwrap();
    } else if opts.resumes == 0 {
        cfg.session_storage = Arc::new(server::NoServerSessionStorage {});
    }

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>();
    }

    if opts.reject_alpn {
        cfg.alpn_protocols = vec![b"invalid".to_vec()];
    }

    if opts.enable_early_data {
        // see kMaxEarlyDataAccepted in boringssl, which bogo validates
        cfg.max_early_data_size = 14336;
        cfg.send_half_rtt_data = true;
    }

    Arc::new(cfg)
}

struct ClientCacheWithoutKxHints {
    delay: u32,
    storage: Arc<client::ClientSessionMemoryCache>,
}

impl ClientCacheWithoutKxHints {
    fn new(delay: u32) -> Arc<ClientCacheWithoutKxHints> {
        Arc::new(ClientCacheWithoutKxHints {
            delay,
            storage: Arc::new(client::ClientSessionMemoryCache::new(32)),
        })
    }
}

impl client::ClientSessionStore for ClientCacheWithoutKxHints {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}
    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        mut value: client::Tls12ClientSessionValue,
    ) {
        value.rewind_epoch(self.delay);
        self.storage
            .set_tls12_session(server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<client::Tls12ClientSessionValue> {
        self.storage.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.storage
            .remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        mut value: client::Tls13ClientSessionValue,
    ) {
        value.rewind_epoch(self.delay);
        self.storage
            .insert_tls13_ticket(server_name, value)
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<client::Tls13ClientSessionValue> {
        self.storage
            .take_tls13_ticket(server_name)
    }
}

impl Debug for ClientCacheWithoutKxHints {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Note: we omit self.storage here as it may contain sensitive data.
        f.debug_struct("ClientCacheWithoutKxHints")
            .field("delay", &self.delay)
            .finish()
    }
}

fn make_client_cfg(opts: &Options) -> Arc<ClientConfig> {
    let kx_groups = if let Some(curves) = &opts.curves {
        curves
            .iter()
            .map(|curveid| lookup_kx_group(*curveid))
            .collect()
    } else {
        provider::ALL_KX_GROUPS.to_vec()
    };

    let cfg = ClientConfig::builder_with_provider(
        CryptoProvider {
            kx_groups,
            ..provider::default_provider()
        }
        .into(),
    )
    .with_protocol_versions(&opts.supported_versions())
    .expect("inconsistent settings")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(DummyServerAuth::new()));

    let mut cfg = if !opts.cert_file.is_empty() && !opts.key_file.is_empty() {
        let cert = load_cert(&opts.cert_file);
        let key = load_key(&opts.key_file);
        cfg.with_client_auth_cert(cert, key)
            .unwrap()
    } else {
        cfg.with_no_client_auth()
    };

    if !opts.cert_file.is_empty() && opts.use_signing_scheme > 0 {
        let scheme = lookup_scheme(opts.use_signing_scheme);
        cfg.client_auth_cert_resolver = Arc::new(FixedSignatureSchemeClientCertResolver {
            resolver: cfg.client_auth_cert_resolver.clone(),
            scheme,
        });
    }

    cfg.resumption = Resumption::store(ClientCacheWithoutKxHints::new(opts.resumption_delay));
    cfg.enable_sni = opts.use_sni;
    cfg.max_fragment_size = opts.max_fragment;

    if !opts.protocols.is_empty() {
        cfg.alpn_protocols = opts
            .protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();
    }

    if opts.enable_early_data {
        cfg.enable_early_data = true;
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

fn handle_err(err: Error) -> ! {
    println!("TLS error: {:?}", err);
    thread::sleep(time::Duration::from_millis(100));

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
            InvalidMessage::InvalidKeyUpdate
            | InvalidMessage::MissingData(_)
            | InvalidMessage::TrailingData(_)
            | InvalidMessage::UnexpectedMessage("HelloRetryRequest")
            | InvalidMessage::NoSignatureSchemes
            | InvalidMessage::UnsupportedCompression,
        ) => quit(":BAD_HANDSHAKE_MSG:"),
        Error::InvalidMessage(InvalidMessage::InvalidCertRequest)
        | Error::InvalidMessage(InvalidMessage::InvalidDhParams)
        | Error::InvalidMessage(InvalidMessage::MissingKeyExchange) => quit(":BAD_HANDSHAKE_MSG:"),
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
        | Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        | Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        | Error::InvalidMessage(InvalidMessage::MessageTooLarge) => quit(":GARBAGE:"),
        Error::InvalidMessage(InvalidMessage::UnexpectedMessage(_)) => quit(":GARBAGE:"),
        Error::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        Error::NoApplicationProtocol => quit(":NO_APPLICATION_PROTOCOL:"),
        Error::PeerIncompatible(
            PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension,
        ) => quit(":UNEXPECTED_EXTENSION:"),
        Error::PeerIncompatible(_) => quit(":INCOMPATIBLE:"),
        Error::PeerMisbehaved(PeerMisbehaved::MissingPskModesExtension) => {
            quit(":MISSING_EXTENSION:")
        }
        Error::PeerMisbehaved(PeerMisbehaved::TooMuchEarlyDataReceived) => {
            quit(":TOO_MUCH_READ_EARLY_DATA:")
        }
        Error::PeerMisbehaved(_) => quit(":PEER_MISBEHAVIOUR:"),
        Error::NoCertificatesPresented => quit(":NO_CERTS:"),
        Error::AlertReceived(AlertDescription::UnexpectedMessage) => quit(":BAD_ALERT:"),
        Error::AlertReceived(AlertDescription::DecompressionFailure) => {
            quit_err(":SSLV3_ALERT_DECOMPRESSION_FAILURE:")
        }
        Error::InvalidCertificate(CertificateError::BadEncoding) => {
            quit(":CANNOT_PARSE_LEAF_CERT:")
        }
        Error::InvalidCertificate(CertificateError::BadSignature) => quit(":BAD_SIGNATURE:"),
        Error::InvalidCertificate(e) => quit(&format!(":BAD_CERT: ({:?})", e)),
        Error::PeerSentOversizedRecord => quit(":DATA_LENGTH_TOO_LONG:"),
        _ => {
            println_err!("unhandled error: {:?}", err);
            quit(":FIXME:")
        }
    }
}

fn flush(sess: &mut Connection, conn: &mut net::TcpStream) {
    while sess.wants_write() {
        if let Err(err) = sess.write_tls(conn) {
            println!("IO error: {:?}", err);
            process::exit(0);
        }
    }
    conn.flush().unwrap();
}

fn client(conn: &mut Connection) -> &mut ClientConnection {
    conn.try_into().unwrap()
}

fn server(conn: &mut Connection) -> &mut ServerConnection {
    match conn {
        Connection::Server(s) => s,
        _ => panic!("Connection is not a ServerConnection"),
    }
}

const MAX_MESSAGE_SIZE: usize = 0xffff + 5;

fn after_read(sess: &mut Connection, conn: &mut net::TcpStream) {
    if let Err(err) = sess.process_new_packets() {
        flush(sess, conn); /* send any alerts before exiting */
        handle_err(err);
    }
}

fn read_n_bytes(sess: &mut Connection, conn: &mut net::TcpStream, n: usize) {
    let mut bytes = [0u8; MAX_MESSAGE_SIZE];
    match conn.read(&mut bytes[..n]) {
        Ok(count) => {
            println!("read {:?} bytes", count);
            sess.read_tls(&mut io::Cursor::new(&mut bytes[..count]))
                .expect("read_tls not expected to fail reading from buffer");
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("invalid read: {}", err),
    };

    after_read(sess, conn);
}

fn read_all_bytes(sess: &mut Connection, conn: &mut net::TcpStream) {
    match sess.read_tls(conn) {
        Ok(_) => {}
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("invalid read: {}", err),
    };

    after_read(sess, conn);
}

fn exec(opts: &Options, mut sess: Connection, count: usize) {
    let mut sent_message = false;

    let addrs = [
        net::SocketAddr::from((net::Ipv6Addr::LOCALHOST, opts.port)),
        net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, opts.port)),
    ];
    let mut conn = net::TcpStream::connect(&addrs[..]).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut sent_exporter = false;
    let mut quench_writes = false;

    loop {
        if !sent_message && (opts.queue_data || (opts.queue_data_on_resume && count > 0)) {
            if !opts
                .queue_early_data_after_received_messages
                .is_empty()
            {
                flush(&mut sess, &mut conn);
                for message_size_estimate in &opts.queue_early_data_after_received_messages {
                    read_n_bytes(&mut sess, &mut conn, *message_size_estimate);
                }
                println!("now ready for early data");
            }

            if count > 0 && opts.enable_early_data {
                let len = client(&mut sess)
                    .early_data()
                    .expect("0rtt not available")
                    .write(b"hello")
                    .expect("0rtt write failed");
                sess.writer()
                    .write_all(&b"hello"[len..])
                    .unwrap();
                sent_message = true;
            } else if !opts.only_write_one_byte_after_handshake {
                let _ = sess.writer().write_all(b"hello");
                sent_message = true;
            }
        }

        if !quench_writes {
            flush(&mut sess, &mut conn);
        }

        if sess.wants_read() {
            read_all_bytes(&mut sess, &mut conn);
        }

        if opts.side == Side::Server && opts.enable_early_data {
            if let Some(ref mut ed) = server(&mut sess).early_data() {
                let mut data = Vec::new();
                let data_len = ed
                    .read_to_end(&mut data)
                    .expect("cannot read early_data");

                for b in data.iter_mut() {
                    *b ^= 0xff;
                }

                sess.writer()
                    .write_all(&data[..data_len])
                    .expect("cannot echo early_data in 1rtt data");
            }
        }

        if !sess.is_handshaking() && opts.export_keying_material > 0 && !sent_exporter {
            let mut export = vec![0; opts.export_keying_material];
            sess.export_keying_material(
                &mut export,
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
            )
            .unwrap();
            sess.writer()
                .write_all(&export)
                .unwrap();
            sent_exporter = true;
        }

        if !sess.is_handshaking() && opts.only_write_one_byte_after_handshake && !sent_message {
            println!("writing message and then only one byte of its tls frame");
            flush(&mut sess, &mut conn);

            sess.writer()
                .write_all(b"hello")
                .unwrap();
            sent_message = true;

            let mut one_byte = [0u8];
            let mut cursor = io::Cursor::new(&mut one_byte[..]);
            sess.write_tls(&mut cursor).unwrap();
            conn.write_all(&one_byte)
                .expect("IO error");

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
                    Some(ProtocolVersion::TLSv1_3) | Some(ProtocolVersion::Unknown(0x7f17)) => {}
                    _ => quit_err("wrong protocol version"),
                }
            }
        }

        let mut buf = [0u8; 1024];
        let len = match sess
            .reader()
            .read(&mut buf[..opts.read_size])
        {
            Ok(0) => {
                if opts.check_close_notify {
                    println!("close notify ok");
                }
                println!("EOF (tls)");
                return;
            }
            Ok(len) => len,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => 0,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                if opts.check_close_notify {
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                }
                println!("EOF (tcp)");
                return;
            }
            Err(err) => panic!("unhandled read error {:?}", err),
        };

        if opts.shut_down_after_handshake && !sent_shutdown && !sess.is_handshaking() {
            sess.send_close_notify();
            sent_shutdown = true;
        }

        if quench_writes && len > 0 {
            println!("unquenching writes after {:?}", len);
            quench_writes = false;
        }

        for b in buf.iter_mut() {
            *b ^= 0xff;
        }

        sess.writer()
            .write_all(&buf[..len])
            .unwrap();
    }
}

pub fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init();

    args.remove(0);

    if !args.is_empty() && args[0] == "-is-handshaker-supported" {
        println!("No");
        process::exit(0);
    }
    println!("options: {:?}", args);

    let mut opts = Options::new();

    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.side = Side::Server;
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
            "-max-send-fragment" => {
                let max_fragment = args.remove(0).parse::<usize>().unwrap();
                opts.max_fragment = Some(max_fragment + 5); // ours includes header
            }
            "-read-size" => {
                let rdsz = args.remove(0).parse::<usize>().unwrap();
                opts.read_size = rdsz;
            }
            "-tls13-variant" => {
                let variant = args.remove(0).parse::<u16>().unwrap();
                if variant != 1 {
                    println!("NYI TLS1.3 variant selection: {:?} {:?}", arg, variant);
                    process::exit(BOGO_NACK);
                }
            }
            "-no-ticket" => {
                opts.tickets = false;
            }
            "-on-resume-no-ticket" => {
                opts.resume_with_tickets_disabled = true;
            }
            "-signing-prefs" => {
                let alg = args.remove(0).parse::<u16>().unwrap();
                opts.use_signing_scheme = alg;
            }
            "-use-client-ca-list" => {
                match args.remove(0).as_ref() {
                    "<EMPTY>" | "<NULL>" => {
                        opts.root_hint_subjects = vec![];
                    }
                    list => {
                        opts.root_hint_subjects = list.split(',')
                            .map(|entry| DistinguishedName::from(decode_hex(entry)))
                            .collect();
                    }
                }
            }
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-resume-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-peer-verify-pref" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-on-initial-expect-alpn" |
            "-on-resume-expect-alpn" |
            "-on-retry-expect-alpn" |
            "-expect-server-name" |
            "-expect-ocsp-response" |
            "-expect-signed-cert-timestamps" |
            "-expect-certificate-types" |
            "-expect-client-ca-list" |
            "-on-retry-expect-early-data-reason" |
            "-on-resume-expect-early-data-reason" |
            "-on-initial-expect-early-data-reason" |
            "-on-initial-expect-cipher" |
            "-on-resume-expect-cipher" |
            "-on-retry-expect-cipher" |
            "-expect-ticket-age-skew" |
            "-handshaker-path" |
            "-application-settings" |
            "-expect-msg-callback" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }

            "-expect-secure-renegotiation" |
            "-expect-no-session-id" |
            "-enable-ed25519" |
            "-expect-hrr" |
            "-expect-no-hrr" |
            "-on-resume-expect-no-offer-early-data" |
            "-key-update" | //< we could implement an API for this
            "-expect-tls13-downgrade" |
            "-enable-signed-cert-timestamps" |
            "-expect-session-id" => {
                println!("not checking {}; NYI", arg);
            }

            "-export-keying-material" => {
                opts.export_keying_material = args.remove(0).parse::<usize>().unwrap();
            }
            "-export-label" => {
                opts.export_keying_material_label = args.remove(0);
            }
            "-export-context" => {
                opts.export_keying_material_context = args.remove(0);
            }
            "-use-export-context" => {
                opts.export_keying_material_context_used = true;
            }
            "-quic-transport-params" => {
                opts.quic_transport_params = BASE64_STANDARD.decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
            }
            "-expect-quic-transport-params" => {
                opts.expect_quic_transport_params = BASE64_STANDARD.decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
            }

            "-ocsp-response" => {
                opts.server_ocsp_response = BASE64_STANDARD.decode(args.remove(0).as_bytes())
                    .expect("invalid base64");
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
            "-read-with-unfinished-write" => {
                opts.queue_data = true;
                opts.only_write_one_byte_after_handshake = true;
            }
            "-shim-shuts-down" => {
                opts.shut_down_after_handshake = true;
            }
            "-check-close-notify" => {
                opts.check_close_notify = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
                opts.use_sni = true;
            }
            "-advertise-alpn" => {
                opts.protocols = split_protocols(&args.remove(0));
            }
            "-reject-alpn" => {
                opts.reject_alpn = true;
            }
            "-use-null-client-ca-list" => {
                opts.offer_no_client_cas = true;
            }
            "-enable-early-data" => {
                opts.tickets = false;
                opts.enable_early_data = true;
            }
            "-on-resume-shim-writes-first" => {
                opts.queue_data_on_resume = true;
            }
            "-on-resume-read-with-unfinished-write" => {
                opts.queue_data_on_resume = true;
                opts.only_write_one_byte_after_handshake_on_resume = true;
            }
            "-on-resume-early-write-after-message" => {
                opts.queue_early_data_after_received_messages= match args.remove(0).parse::<u8>().unwrap() {
                    // estimate where these messages appear in the server's first flight.
                    2 => vec![5 + 128 + 5 + 32],
                    8 => vec![5 + 128 + 5 + 32, 5 + 64],
                    _ => {
                        panic!("unhandled -on-resume-early-write-after-message");
                    }
                };
                opts.queue_data_on_resume = true;
            }
            "-expect-ticket-supports-early-data" => {
                opts.expect_ticket_supports_early_data = true;
            }
            "-expect-accept-early-data" |
            "-on-resume-expect-accept-early-data" => {
                opts.expect_accept_early_data = true;
            }
            "-expect-early-data-reason" |
            "-on-resume-expect-reject-early-data-reason" => {
                let reason = args.remove(0);
                match reason.as_str() {
                    "disabled" | "protocol_version" => {
                        opts.expect_reject_early_data = true;
                    }
                    _ => {
                        println!("NYI early data reason: {}", reason);
                        process::exit(1);
                    }
                }
            }
            "-expect-reject-early-data" |
            "-on-resume-expect-reject-early-data" => {
                opts.expect_reject_early_data = true;
            }
            "-expect-version" => {
                opts.expect_version = args.remove(0).parse::<u16>().unwrap();
            }
            "-curves" => {
                let curve = args.remove(0).parse::<u16>().unwrap();
                if let Some(mut curves) = opts.curves.take() {
                    curves.push(curve);
                } else {
                    opts.curves = Some(vec![ curve ]);
                }
            }
            "-resumption-delay" => {
                opts.resumption_delay = args.remove(0).parse::<u32>().unwrap();
                align_time();
            }

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-handoff" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            "-enable-ocsp-stapling" |
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
            "-expect-verify-result" |
            "-send-alert" |
            "-digest-prefs" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-expect-early-data-info" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-expect-draft-downgrade" |
            "-allow-unknown-alpn-protos" |
            "-on-initial-tls13-variant" |
            "-on-initial-expect-curve-id" |
            "-on-resume-export-early-keying-material" |
            "-on-resume-enable-early-data" |
            "-export-early-keying-material" |
            "-handshake-twice" |
            "-on-resume-verify-fail" |
            "-reverify-on-resume" |
            "-verify-prefs" |
            "-no-op-extra-handshake" |
            "-expect-peer-cert-file" |
            "-no-rsa-pss-rsae-certs" |
            "-ignore-tls13-downgrade" |
            "-allow-hint-mismatch" |
            "-fips-202205" |
            "-wpa-202304" |
            "-srtp-profiles" |
            "-permute-extensions" |
            "-signed-cert-timestamps" |
            "-on-initial-expect-peer-cert-file" => {
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

    let (client_cfg, mut server_cfg) = match opts.side {
        Side::Client => (Some(make_client_cfg(&opts)), None),
        Side::Server => (None, Some(make_server_cfg(&opts))),
    };

    fn make_session(
        opts: &Options,
        scfg: &Option<Arc<ServerConfig>>,
        ccfg: &Option<Arc<ClientConfig>>,
    ) -> Connection {
        assert!(opts.quic_transport_params.is_empty());
        assert!(opts
            .expect_quic_transport_params
            .is_empty());

        if opts.side == Side::Server {
            let scfg = Arc::clone(scfg.as_ref().unwrap());
            ServerConnection::new(scfg)
                .unwrap()
                .into()
        } else {
            let server_name = ServerName::try_from(opts.host_name.as_str())
                .unwrap()
                .to_owned();
            let ccfg = Arc::clone(ccfg.as_ref().unwrap());

            ClientConnection::new(ccfg, server_name)
                .unwrap()
                .into()
        }
    }

    for i in 0..opts.resumes + 1 {
        let sess = make_session(&opts, &server_cfg, &client_cfg);
        exec(&opts, sess, i);
        if opts.resume_with_tickets_disabled {
            opts.tickets = false;
            server_cfg = Some(make_server_cfg(&opts));
        }
    }
}
