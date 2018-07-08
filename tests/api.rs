// Assorted public API tests.
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic;
use std::fs;
use std::mem;
use std::io::{self, Write, Read};

extern crate rustls;

use rustls::{ClientConfig, ClientSession, ResolvesClientCert};
use rustls::{ServerConfig, ServerSession, ResolvesServerCert};
use rustls::Session;
use rustls::{Stream, StreamOwned};
use rustls::{ProtocolVersion, SignatureScheme, CipherSuite};
use rustls::TLSError;
use rustls::sign;
use rustls::{ALL_CIPHERSUITES, SupportedCipherSuite};
use rustls::{Certificate, PrivateKey};
use rustls::internal::pemfile;
use rustls::{RootCertStore, NoClientAuth, AllowAnyAuthenticatedClient};
use rustls::KeyLog;

extern crate webpki;

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

#[derive(Clone, Copy)]
enum KeyType {
    RSA,
    ECDSA
}

static ALL_KEY_TYPES: [KeyType; 2] = [ KeyType::RSA, KeyType::ECDSA ];

impl KeyType {
    fn path_for(&self, part: &str) -> String {
        match self {
            KeyType::RSA => format!("test-ca/rsa/{}", part),
            KeyType::ECDSA => format!("test-ca/ecdsa/{}", part),
        }
    }

    fn get_chain(&self) -> Vec<Certificate> {
        pemfile::certs(&mut io::BufReader::new(fs::File::open(self.path_for("end.fullchain"))
                                               .unwrap()))
            .unwrap()
    }

    fn get_key(&self) -> PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(fs::File::open(self.path_for("end.key"))
                                                            .unwrap()))
                .unwrap()[0]
            .clone()
    }

    fn get_client_chain(&self) -> Vec<Certificate> {
        pemfile::certs(&mut io::BufReader::new(fs::File::open(self.path_for("client.fullchain"))
                                               .unwrap()))
            .unwrap()
    }

    fn get_client_key(&self) -> PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(fs::File::open(self.path_for("client.key"))
                                                            .unwrap()))
                .unwrap()[0]
            .clone()
    }
}

fn make_server_config(kt: KeyType) -> ServerConfig {
    let mut cfg = ServerConfig::new(NoClientAuth::new());
    cfg.set_single_cert(kt.get_chain(), kt.get_key()).unwrap();

    cfg
}

fn make_server_config_with_mandatory_client_auth(kt: KeyType) -> ServerConfig {
    let roots = kt.get_chain();
    let mut client_auth_roots = RootCertStore::empty();
    for root in roots {
        client_auth_roots.add(&root).unwrap();
    }

    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);
    let mut cfg = ServerConfig::new(client_auth);
    cfg.set_single_cert(kt.get_chain(), kt.get_key()).unwrap();

    cfg
}

fn make_client_config(kt: KeyType) -> ClientConfig {
    let mut cfg = ClientConfig::new();
    let mut rootbuf = io::BufReader::new(fs::File::open(kt.path_for("ca.cert")).unwrap());
    cfg.root_store.add_pem_file(&mut rootbuf).unwrap();

    cfg
}

fn make_client_config_with_auth(kt: KeyType) -> ClientConfig {
    let mut cfg = make_client_config(kt);
    cfg.set_single_client_cert(kt.get_client_chain(), kt.get_client_key());
    cfg
}

fn make_pair(kt: KeyType) -> (ClientSession, ServerSession) {
    make_pair_for_configs(make_client_config(kt),
                          make_server_config(kt))
}

fn make_pair_for_configs(client_config: ClientConfig,
                         server_config: ServerConfig) -> (ClientSession, ServerSession) {
    make_pair_for_arc_configs(&Arc::new(client_config),
                              &Arc::new(server_config))
}

fn make_pair_for_arc_configs(client_config: &Arc<ClientConfig>,
                             server_config: &Arc<ServerConfig>) -> (ClientSession, ServerSession) {
    (
        ClientSession::new(client_config, dns_name("localhost")),
        ServerSession::new(server_config)
    )
}

fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets().unwrap();
        transfer(server, client);
        client.process_new_packets().unwrap();
    }
}

struct AllClientVersions {
    client_config: ClientConfig,
    index: usize,
}

impl AllClientVersions {
    fn new(client_config: ClientConfig) -> AllClientVersions {
        AllClientVersions { client_config, index: 0 }
    }
}

impl Iterator for AllClientVersions {
    type Item = ClientConfig;

    fn next(&mut self) -> Option<ClientConfig> {
        let mut config = self.client_config.clone();
        self.index += 1;

        match self.index {
            1 => {
                config.versions = vec![ProtocolVersion::TLSv1_2];
                Some(config)
            },
            2 => {
                config.versions = vec![ProtocolVersion::TLSv1_3];
                Some(config)
            },
            _ => None
        }
    }
}

#[derive(PartialEq, Debug)]
enum TLSErrorFromPeer { Client(TLSError), Server(TLSError) }

fn do_handshake_until_error(client: &mut ClientSession,
                            server: &mut ServerSession)
                            -> Result<(), TLSErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets()
            .map_err(|err| TLSErrorFromPeer::Server(err))?;
        transfer(server, client);
        client.process_new_packets()
            .map_err(|err| TLSErrorFromPeer::Client(err))?;
    }

    Ok(())
}

fn dns_name(name: &'static str) -> webpki::DNSNameRef {
    webpki::DNSNameRef::try_from_ascii_str(name).unwrap()
}

fn alpn_test(server_protos: Vec<String>, client_protos: Vec<String>, agreed: Option<&str>) {
    let mut client_config = make_client_config(KeyType::RSA);
    let mut server_config = make_server_config(KeyType::RSA);

    client_config.alpn_protocols = client_protos;
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for client_config in AllClientVersions::new(client_config) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);

        assert_eq!(client.get_alpn_protocol(), None);
        assert_eq!(server.get_alpn_protocol(), None);
        do_handshake(&mut client, &mut server);
        assert_eq!(client.get_alpn_protocol(), agreed);
        assert_eq!(server.get_alpn_protocol(), agreed);
    }
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec!["server-proto".to_string()], vec![], None);

    // client support
    alpn_test(vec![], vec!["client-proto".to_string()], None);

    // no overlap
    alpn_test(vec!["server-proto".to_string()],
              vec!["client-proto".to_string()],
              None);

    // server chooses preference
    alpn_test(vec!["server-proto".to_string(), "client-proto".to_string()],
              vec!["client-proto".to_string(), "server-proto".to_string()],
              Some("server-proto"));

    // case sensitive
    alpn_test(vec!["PROTO".to_string()], vec!["proto".to_string()], None);
}

fn version_test(client_versions: Vec<ProtocolVersion>,
                server_versions: Vec<ProtocolVersion>,
                result: Option<ProtocolVersion>) {
    let mut client_config = make_client_config(KeyType::RSA);
    let mut server_config = make_server_config(KeyType::RSA);

    println!("version {:?} {:?} -> {:?}",
             client_versions,
             server_versions,
             result);

    if !client_versions.is_empty() {
        client_config.versions = client_versions;
    }

    if !server_versions.is_empty() {
        server_config.versions = server_versions;
    }

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.get_protocol_version(), None);
    assert_eq!(server.get_protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    } else {
        do_handshake(&mut client, &mut server);
        assert_eq!(client.get_protocol_version(), result);
        assert_eq!(server.get_protocol_version(), result);
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(vec![], vec![], Some(ProtocolVersion::TLSv1_3));

    // client default, server 1.2 -> 1.2
    version_test(vec![],
                 vec![ProtocolVersion::TLSv1_2],
                 Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server default -> 1.2
    version_test(vec![ProtocolVersion::TLSv1_2],
                 vec![],
                 Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server 1.3 -> fail
    version_test(vec![ProtocolVersion::TLSv1_2],
                 vec![ProtocolVersion::TLSv1_3],
                 None);

    // client 1.3, server 1.2 -> fail
    version_test(vec![ProtocolVersion::TLSv1_3],
                 vec![ProtocolVersion::TLSv1_2],
                 None);

    // client 1.3, server 1.2+1.3 -> 1.3
    version_test(vec![ProtocolVersion::TLSv1_3],
                 vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                 Some(ProtocolVersion::TLSv1_3));

    // client 1.2+1.3, server 1.2 -> 1.2
    version_test(vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
                 vec![ProtocolVersion::TLSv1_2],
                 Some(ProtocolVersion::TLSv1_2));
}

fn check_read(reader: &mut io::Read, bytes: &[u8]) {
    let mut buf = Vec::new();
    assert_eq!(bytes.len(), reader.read_to_end(&mut buf).unwrap());
    assert_eq!(bytes.to_vec(), buf);
}

#[test]
fn buffered_client_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for client_config in AllClientVersions::new(make_client_config(KeyType::RSA)) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);

        assert_eq!(5, client.write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut server, b"hello");
    }
}

#[test]
fn buffered_server_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for client_config in AllClientVersions::new(make_client_config(KeyType::RSA)) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);

        assert_eq!(5, server.write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();

        check_read(&mut client, b"hello");
    }
}

#[test]
fn buffered_both_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::RSA));

    for client_config in AllClientVersions::new(make_client_config(KeyType::RSA)) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);

        assert_eq!(12, server.write(b"from-server!").unwrap());
        assert_eq!(12, client.write(b"from-client!").unwrap());

        do_handshake(&mut client, &mut server);

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut client, b"from-server!");
        check_read(&mut server, b"from-client!");
    }
}

#[test]
fn client_can_get_server_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        for client_config in AllClientVersions::new(make_client_config(*kt)) {
            let (mut client, mut server) = make_pair_for_configs(client_config,
                                                                 make_server_config(*kt));
            do_handshake(&mut client, &mut server);

            let certs = client.get_peer_certificates();
            assert_eq!(certs, Some(kt.get_chain()));
        }
    }
}

#[test]
fn server_can_get_client_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.set_single_client_cert(kt.get_chain(), kt.get_key());

        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for client_config in AllClientVersions::new(client_config) {
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                     &server_config);
            do_handshake(&mut client, &mut server);

            let certs = server.get_peer_certificates();
            assert_eq!(certs, Some(kt.get_chain()));
        }
    }
}

fn check_read_and_close(reader: &mut io::Read, expect: &[u8]) {
    let mut buf = Vec::new();
    buf.resize(expect.len(), 0u8);
    assert_eq!(expect.len(), reader.read(&mut buf).unwrap());
    assert_eq!(expect.to_vec(), buf);

    let err = reader.read(&mut buf);
    assert!(err.is_err());
    assert_eq!(err.err().unwrap().kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn server_close_notify() {
    let kt = KeyType::RSA;
    let mut client_config = make_client_config(kt);
    client_config.set_single_client_cert(kt.get_chain(), kt.get_key());

    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for client_config in AllClientVersions::new(client_config) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(12, server.write(b"from-server!").unwrap());
        assert_eq!(12, client.write(b"from-client!").unwrap());
        server.send_close_notify();

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read_and_close(&mut client, b"from-server!");

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server, b"from-client!");
    }
}

#[test]
fn client_close_notify() {
    let kt = KeyType::RSA;
    let mut client_config = make_client_config(kt);
    client_config.set_single_client_cert(kt.get_chain(), kt.get_key());

    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for client_config in AllClientVersions::new(client_config) {
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                 &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(12, server.write(b"from-server!").unwrap());
        assert_eq!(12, client.write(b"from-client!").unwrap());
        client.send_close_notify();

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read_and_close(&mut server, b"from-client!");

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client, b"from-server!");
    }
}

struct ServerCheckCertResolve {
    expected: String
}

impl ServerCheckCertResolve {
    fn new(expect: &str) -> ServerCheckCertResolve {
        ServerCheckCertResolve {
            expected: expect.to_string()
        }
    }
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self,
               server_name: Option<webpki::DNSNameRef>,
               sigschemes: &[SignatureScheme])
        -> Option<sign::CertifiedKey> {
        if let Some(got_dns_name) = server_name {
            let got: &str = got_dns_name.into();
            if got != self.expected {
                panic!("unexpected dns name (wanted '{}' got '{:?}')", &self.expected, got_dns_name);
            }
        } else {
            panic!("dns name not provided (wanted '{}')", &self.expected);
        }

        if sigschemes.len() == 0 {
            panic!("no signature schemes shared by client");
        }

        None
    }
}

#[test]
fn server_cert_resolve_with_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve::new("the-value-from-sni"));

        let mut client = ClientSession::new(&Arc::new(client_config), dns_name("the-value-from-sni"));
        let mut server = ServerSession::new(&Arc::new(server_config));

        let err = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(err.is_err(), true);
    }
}

struct ServerCheckNoSNI {}

impl ResolvesServerCert for ServerCheckNoSNI {
    fn resolve(&self,
               server_name: Option<webpki::DNSNameRef>,
               _sigschemes: &[SignatureScheme])
        -> Option<sign::CertifiedKey> {
        assert!(server_name.is_none());

        None
    }
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.enable_sni = false;

        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckNoSNI {});
        let server_config = Arc::new(server_config);

        for client_config in AllClientVersions::new(client_config) {
            let mut client = ClientSession::new(&Arc::new(client_config), dns_name("value-not-sent"));
            let mut server = ServerSession::new(&server_config);

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(err.is_err(), true);
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let server_config = Arc::new(make_server_config(*kt));

        for client_config in AllClientVersions::new(client_config) {
            let mut client = ClientSession::new(&Arc::new(client_config),
                                                dns_name("not-the-right-hostname.com"));
            let mut server = ServerSession::new(&server_config);

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(err,
                       Err(TLSErrorFromPeer::Client(
                               TLSError::WebPKIError(webpki::Error::CertNotValidForName))
                           )
                       );
        }
    }
}

struct ClientCheckCertResolve {
    query_count: atomic::AtomicUsize,
    expect_queries: usize
}

impl ClientCheckCertResolve {
    fn new(expect_queries: usize) -> ClientCheckCertResolve {
        ClientCheckCertResolve {
            query_count: atomic::AtomicUsize::new(0),
            expect_queries: expect_queries
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        let count = self.query_count.load(atomic::Ordering::SeqCst);
        assert_eq!(count, self.expect_queries);
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(&self,
               acceptable_issuers: &[&[u8]],
               sigschemes: &[SignatureScheme])
        -> Option<sign::CertifiedKey> {
        self.query_count.fetch_add(1, atomic::Ordering::SeqCst);

        if acceptable_issuers.len() == 0 {
            panic!("no issuers offered by server");
        }

        if sigschemes.len() == 0 {
            panic!("no signature schemes shared by server");
        }

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn client_cert_resolve() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(2));

        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for client_config in AllClientVersions::new(client_config) {
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                     &server_config);

            assert_eq!(
                do_handshake_until_error(&mut client, &mut server),
                Err(TLSErrorFromPeer::Server(TLSError::NoCertificatesPresented)));
        }
    }
}

#[test]
fn client_auth_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_auth(*kt);
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for client_config in AllClientVersions::new(client_config) {
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config),
                                                                     &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[test]
fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::RSA);
    client.read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref()).unwrap();
    let mut err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = client.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_error_is_sticky() {
    let (_, mut server) = make_pair(KeyType::RSA);
    server.read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref()).unwrap();
    let mut err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
    err = server.process_new_packets();
    assert_eq!(err.is_err(), true);
}

#[test]
fn server_is_send_and_sync() {
    let (_, server) = make_pair(KeyType::RSA);
    &server as &Send;
    &server as &Sync;
}

#[test]
fn client_is_send_and_sync() {
    let (client, _) = make_pair(KeyType::RSA);
    &client as &Send;
    &client as &Sync;
}

#[test]
fn server_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    server.set_buffer_limit(32);

    assert_eq!(server.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(server.write(b"01234567890123456789").unwrap(), 12);

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client, b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    // this test will vary in behaviour depending on the default suites
    do_handshake(&mut client, &mut server);
    server.set_buffer_limit(48);

    assert_eq!(server.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(server.write(b"01234567890123456789").unwrap(), 6);

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client, b"01234567890123456789012345");
}

#[test]
fn client_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.set_buffer_limit(32);

    assert_eq!(client.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(client.write(b"01234567890123456789").unwrap(), 12);

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server, b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    do_handshake(&mut client, &mut server);
    client.set_buffer_limit(48);

    assert_eq!(client.write(b"01234567890123456789").unwrap(), 20);
    assert_eq!(client.write(b"01234567890123456789").unwrap(), 6);

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server, b"01234567890123456789012345");
}

struct OtherSession<'a> {
    sess: &'a mut Session,
    pub reads: usize,
    pub writes: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::TLSError>,
}

impl<'a> OtherSession<'a> {
    fn new(sess: &'a mut Session) -> OtherSession<'a> {
        OtherSession {
            sess,
            reads: 0,
            writes: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
        }
    }

    fn new_fails(sess: &'a mut Session) -> OtherSession<'a> {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }
}

impl<'a> io::Read for OtherSession<'a> {
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<'a> io::Write for OtherSession<'a> {
    fn write(&mut self, mut b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let l = self.sess.read_tls(b.by_ref())?;
        let rc = self.sess.process_new_packets();

        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        Ok(l)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> rustls::WriteV for OtherSession<'a> {
    fn writev(&mut self, b: &[&[u8]]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 { bytes.len() / 2 } else { bytes.len() }
            } else {
                bytes.len()
            };

            let l = self.sess.read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = self.sess.process_new_packets();
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

#[test]
fn client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    assert_eq!(true, client.is_handshaking());
    let (rdlen, wrlen) = client.complete_io(&mut OtherSession::new(&mut server)).unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert_eq!(false, client.is_handshaking());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let (mut client, _) = make_pair(KeyType::RSA);
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, client.is_handshaking());
    let err = client.complete_io(&mut input).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client.write(b"01234567890123456789").unwrap();
        client.write(b"01234567890123456789").unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.writes, 2);
        }
        check_read(&mut server, b"0123456789012345678901234567890123456789");
    }
}

#[test]
fn client_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server.write(b"01234567890123456789").unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut client, b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        assert_eq!(true, server.is_handshaking());
        let (rdlen, wrlen) = server.complete_io(&mut OtherSession::new(&mut client)).unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert_eq!(false, server.is_handshaking());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let (_, mut server) = make_pair(KeyType::RSA);
    let mut input = io::Cursor::new(Vec::new());

    assert_eq!(true, server.is_handshaking());
    let err = server.complete_io(&mut input).unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server.write(b"01234567890123456789").unwrap();
        server.write(b"01234567890123456789").unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.writes, 2);
        }
        check_read(&mut client, b"0123456789012345678901234567890123456789");
    }
}

#[test]
fn server_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client.write(b"01234567890123456789").unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut server, b"01234567890123456789");
    }
}

#[test]
fn client_stream_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream = Stream::new(&mut client, &mut pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut server, b"hello");
    }
}

#[test]
fn client_streamowned_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        {
            let pipe = OtherSession::new(&mut server);
            let mut stream = StreamOwned::new(client, pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut server, b"hello");
    }
}

#[test]
fn client_stream_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        server.write(b"world").unwrap();

        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream = Stream::new(&mut client, &mut pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn client_streamowned_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (client, mut server) = make_pair(*kt);

        server.write(b"world").unwrap();

        {
            let pipe = OtherSession::new(&mut server);
            let mut stream = StreamOwned::new(client, pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn server_stream_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream = Stream::new(&mut server, &mut pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client, b"hello");
    }
}

#[test]
fn server_streamowned_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt);

        {
            let pipe = OtherSession::new(&mut client);
            let mut stream = StreamOwned::new(server, pipe);
            assert_eq!(stream.write(b"hello").unwrap(), 5);
        }
        check_read(&mut client, b"hello");
    }
}

#[test]
fn server_stream_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        client.write(b"world").unwrap();

        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream = Stream::new(&mut server, &mut pipe);
            check_read(&mut stream, b"world");
        }
    }
}

#[test]
fn server_streamowned_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, server) = make_pair(*kt);

        client.write(b"world").unwrap();

        {
            let pipe = OtherSession::new(&mut client);
            let mut stream = StreamOwned::new(server, pipe);
            check_read(&mut stream, b"world");
        }
    }
}

fn make_disjoint_suite_configs() -> (ClientConfig, ServerConfig) {
    let kt = KeyType::RSA;
    let mut server_config = make_server_config(kt);
    server_config.ciphersuites = vec![];

    (make_client_config(kt), server_config)
}

#[test]
fn client_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    {
        let mut pipe = OtherSession::new_fails(&mut server);
        let mut client_stream = Stream::new(&mut client, &mut pipe);
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(format!("{:?}", rc),
                   "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })");
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(format!("{:?}", rc),
                   "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })");

    }
}

#[test]
fn client_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (client, mut server) = make_pair_for_configs(client_config, server_config);

    let pipe = OtherSession::new_fails(&mut server);
    let mut client_stream = StreamOwned::new(client, pipe);
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(format!("{:?}", rc),
               "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })");
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(format!("{:?}", rc),
               "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })");
}

#[test]
fn server_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    client.write(b"world").unwrap();

    {
        let mut pipe = OtherSession::new_fails(&mut client);
        let mut server_stream = Stream::new(&mut server, &mut pipe);
        let mut bytes = [0u8; 5];
        let rc = server_stream.read(&mut bytes);
        assert!(rc.is_err());
        assert_eq!(format!("{:?}", rc),
                   "Err(Custom { kind: InvalidData, error: PeerIncompatibleError(\"no ciphersuites in common\") })");
    }
}

#[test]
fn server_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, server) = make_pair_for_configs(client_config, server_config);

    client.write(b"world").unwrap();

    let pipe = OtherSession::new_fails(&mut client);
    let mut server_stream = StreamOwned::new(server, pipe);
    let mut bytes = [0u8; 5];
    let rc = server_stream.read(&mut bytes);
    assert!(rc.is_err());
    assert_eq!(format!("{:?}", rc),
               "Err(Custom { kind: InvalidData, error: PeerIncompatibleError(\"no ciphersuites in common\") })");
}

#[test]
fn server_config_is_clone() {
    let _ = make_server_config(KeyType::RSA).clone();
}

#[test]
fn client_config_is_clone() {
    let _ = make_client_config(KeyType::RSA).clone();
}

#[test]
fn client_session_is_debug() {
    let (client, _) = make_pair(KeyType::RSA);
    println!("{:?}", client);
}

#[test]
fn server_session_is_debug() {
    let (_, server) = make_pair(KeyType::RSA);
    println!("{:?}", server);
}

#[test]
fn server_complete_io_for_handshake_ending_with_alert() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(true, server.is_handshaking());

    let mut pipe = OtherSession::new_fails(&mut client);
    let rc = server.complete_io(&mut pipe);
    assert!(rc.is_err(),
            "server io failed due to handshake failure");
    assert!(!server.wants_write(),
            "but server did send its alert");
    assert_eq!(format!("{:?}", pipe.last_error),
               "Some(AlertReceived(HandshakeFailure))",
               "which was received by client");
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::RSA;
    let mut client = ClientSession::new(&Arc::new(make_client_config(kt)),
                                        dns_name("second.testserver.com"));
    let mut server = ServerSession::new(&Arc::new(make_server_config(kt)));

    assert_eq!(None, server.get_sni_hostname());
    do_handshake(&mut client, &mut server);
    assert_eq!(Some("second.testserver.com"), server.get_sni_hostname());
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::ResolvesServerCertUsingSNI::new();
    let signing_key = sign::RSASigningKey::new(&kt.get_key())
        .unwrap();
    let signing_key: Arc<Box<sign::SigningKey>> = Arc::new(Box::new(signing_key));
    resolver.add("localhost",
                 sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
        .unwrap();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerSession::new(&server_config);
    let mut client1 = ClientSession::new(&Arc::new(make_client_config(kt)), dns_name("localhost"));
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerSession::new(&server_config);
    let mut client2 = ClientSession::new(&Arc::new(make_client_config(kt)), dns_name("notlocalhost"));
    let err = do_handshake_until_error(&mut client2, &mut server2);
    assert_eq!(err,
               Err(TLSErrorFromPeer::Server(
                       TLSError::General("no server certificate chain resolved".into()))));
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::ResolvesServerCertUsingSNI::new();
    let signing_key = sign::RSASigningKey::new(&kt.get_key())
        .unwrap();
    let signing_key: Arc<Box<sign::SigningKey>> = Arc::new(Box::new(signing_key));

    assert_eq!(Ok(()),
               resolver.add("localhost",
                            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())));
    assert_eq!(Err(TLSError::General("The server certificate is not valid for the given name".into())),
               resolver.add("not-localhost",
                            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())));
    assert_eq!(Err(TLSError::General("Bad DNS name".into())),
               resolver.add("not ascii 🦀",
                            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::RSA;
    let mut resolver = rustls::ResolvesServerCertUsingSNI::new();
    let signing_key = sign::RSASigningKey::new(&kt.get_key())
        .unwrap();
    let signing_key: Arc<Box<sign::SigningKey>> = Arc::new(Box::new(signing_key));

    assert_eq!(Err(TLSError::General("No end-entity certificate in certificate chain".into())),
               resolver.add("localhost",
                            sign::CertifiedKey::new(vec![], signing_key.clone())));

    let bad_chain = vec![ rustls::Certificate(vec![ 0xa0 ]) ];
    assert_eq!(Err(TLSError::General("End-entity certificate in certificate chain is syntactically invalid".into())),
               resolver.add("localhost",
                            sign::CertifiedKey::new(bad_chain, signing_key.clone())));
}

fn do_exporter_test(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(Err(TLSError::HandshakeNotComplete),
               client.export_keying_material(&mut client_secret, b"label", Some(b"context")));
    assert_eq!(Err(TLSError::HandshakeNotComplete),
               server.export_keying_material(&mut server_secret, b"label", Some(b"context")));
    do_handshake(&mut client, &mut server);

    assert_eq!(Ok(()),
               client.export_keying_material(&mut client_secret, b"label", Some(b"context")));
    assert_eq!(Ok(()),
               server.export_keying_material(&mut server_secret, b"label", Some(b"context")));
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    assert_eq!(Ok(()),
               client.export_keying_material(&mut client_secret, b"label", None));
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert_eq!(Ok(()),
               server.export_keying_material(&mut server_secret, b"label", None));
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());
}

#[test]
fn test_tls12_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        let server_config = make_server_config(*kt);
        client_config.versions = vec![ ProtocolVersion::TLSv1_2 ];

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        let server_config = make_server_config(*kt);
        client_config.versions = vec![ ProtocolVersion::TLSv1_3 ];

        do_exporter_test(client_config, server_config);
    }
}

fn do_suite_test(client_config: ClientConfig,
                 server_config: ServerConfig,
                 expect_suite: &'static SupportedCipherSuite,
                 expect_version: ProtocolVersion) {
    println!("do_suite_test {:?} {:?}", expect_version, expect_suite.suite);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(None, client.get_negotiated_ciphersuite());
    assert_eq!(None, server.get_negotiated_ciphersuite());
    assert_eq!(None, client.get_protocol_version());
    assert_eq!(None, server.get_protocol_version());
    assert_eq!(true, client.is_handshaking());
    assert_eq!(true, server.is_handshaking());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert_eq!(true, client.is_handshaking());
    assert_eq!(true, server.is_handshaking());
    assert_eq!(None, client.get_protocol_version());
    assert_eq!(Some(expect_version), server.get_protocol_version());
    assert_eq!(None, client.get_negotiated_ciphersuite());
    assert_eq!(Some(expect_suite), server.get_negotiated_ciphersuite());

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(Some(expect_suite), client.get_negotiated_ciphersuite());
    assert_eq!(Some(expect_suite), server.get_negotiated_ciphersuite());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(false, client.is_handshaking());
    assert_eq!(false, server.is_handshaking());
    assert_eq!(Some(expect_version), client.get_protocol_version());
    assert_eq!(Some(expect_version), server.get_protocol_version());
    assert_eq!(Some(expect_suite), client.get_negotiated_ciphersuite());
    assert_eq!(Some(expect_suite), server.get_negotiated_ciphersuite());
}

fn find_suite(suite: CipherSuite) -> &'static SupportedCipherSuite {
    for scs in ALL_CIPHERSUITES.iter() {
        if scs.suite == suite {
            return scs;
        }
    }

    panic!("find_suite given unsuppported suite");
}

static TEST_CIPHERSUITES: [(ProtocolVersion, KeyType, CipherSuite); 9] = [
    (ProtocolVersion::TLSv1_3, KeyType::RSA, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
    (ProtocolVersion::TLSv1_3, KeyType::RSA, CipherSuite::TLS13_AES_256_GCM_SHA384),
    (ProtocolVersion::TLSv1_3, KeyType::RSA, CipherSuite::TLS13_AES_128_GCM_SHA256),
    (ProtocolVersion::TLSv1_2, KeyType::ECDSA, CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    (ProtocolVersion::TLSv1_2, KeyType::RSA,   CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    (ProtocolVersion::TLSv1_2, KeyType::ECDSA, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    (ProtocolVersion::TLSv1_2, KeyType::ECDSA, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    (ProtocolVersion::TLSv1_2, KeyType::RSA,   CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    (ProtocolVersion::TLSv1_2, KeyType::RSA,   CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
];

#[test]
fn negotiated_ciphersuite_default() {
    for kt in ALL_KEY_TYPES.iter() {
        do_suite_test(make_client_config(*kt),
                      make_server_config(*kt),
                      find_suite(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
                      ProtocolVersion::TLSv1_3);
    }
}

#[test]
fn all_suites_covered() {
    assert_eq!(ALL_CIPHERSUITES.len(), TEST_CIPHERSUITES.len());
}

#[test]
fn negotiated_ciphersuite_client() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let mut client_config = make_client_config(kt);
        client_config.ciphersuites = vec![scs];
        client_config.versions = vec![version];

        do_suite_test(client_config,
                      make_server_config(kt),
                      scs,
                      version);
    }
}

#[test]
fn negotiated_ciphersuite_server() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let mut server_config = make_server_config(kt);
        server_config.ciphersuites = vec![scs];
        server_config.versions = vec![version];

        do_suite_test(make_client_config(kt),
                      server_config,
                      scs,
                      version);
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}

struct KeyLogToVec(Mutex<Vec<KeyLogItem>>);

impl KeyLogToVec {
    fn new() -> Self {
        KeyLogToVec(Mutex::new(vec![]))
    }

    fn take(&self) -> Vec<KeyLogItem> {
        mem::replace(&mut self.0.lock()
                         .unwrap(),
                     vec![])
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into()
        };

        self.0.lock()
            .unwrap()
            .push(value);
    }
}

#[test]
fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new());
    let server_key_log = Arc::new(KeyLogToVec::new());

    let kt = KeyType::RSA;
    let mut client_config = make_client_config(kt);
    client_config.versions = vec![ ProtocolVersion::TLSv1_2 ];
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();
    assert_eq!(client_full_log, server_full_log);
    assert_eq!(1, client_full_log.len());
    assert_eq!("CLIENT_RANDOM", client_full_log[0].label);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();
    assert_eq!(client_resume_log, server_resume_log);
    assert_eq!(1, client_resume_log.len());
    assert_eq!("CLIENT_RANDOM", client_resume_log[0].label);
    assert_eq!(client_full_log[0].secret, client_resume_log[0].secret);
}

#[test]
fn key_log_for_tls13() {
    let client_key_log = Arc::new(KeyLogToVec::new());
    let server_key_log = Arc::new(KeyLogToVec::new());

    let kt = KeyType::RSA;
    let mut client_config = make_client_config(kt);
    client_config.versions = vec![ ProtocolVersion::TLSv1_3 ];
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[3].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[1]);
    assert_eq!(client_full_log[1], server_full_log[0]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_resume_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_resume_log[1].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[3].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[4].label);

    assert_eq!(client_resume_log[0], server_resume_log[1]);
    assert_eq!(client_resume_log[1], server_resume_log[0]);
    assert_eq!(client_resume_log[2], server_resume_log[2]);
    assert_eq!(client_resume_log[3], server_resume_log[3]);
    assert_eq!(client_resume_log[4], server_resume_log[4]);
}

#[test]
fn vectored_write_for_server_appdata() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    server.write(b"01234567890123456789").unwrap();
    server.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.writev_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(&mut client, b"0123456789012345678901234567890123456789");
}

#[test]
fn vectored_write_for_client_appdata() {
    let (mut client, mut server) = make_pair(KeyType::RSA);
    do_handshake(&mut client, &mut server);

    client.write(b"01234567890123456789").unwrap();
    client.write(b"01234567890123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.writev_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(&mut server, b"0123456789012345678901234567890123456789");
}

#[test]
fn vectored_write_for_server_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    server.write(b"01234567890123456789").unwrap();
    server.write(b"0123456789").unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.writev_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 5000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() > 3); // at least a server hello/cert/serverkx
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.writev_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 74);
        assert_eq!(pipe.writevs, vec![vec![42, 32]]);
    }

    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), false);
    check_read(&mut client, b"012345678901234567890123456789");
}

#[test]
fn vectored_write_for_client_handshake() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.write(b"01234567890123456789").unwrap();
    client.write(b"0123456789").unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.writev_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 200); // just the client hello
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 1); // only a client hello
    }

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.writev_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 138);
        // CCS, finished, then two application datas
        assert_eq!(pipe.writevs, vec![vec![6, 58, 42, 32]]);
    }

    assert_eq!(server.is_handshaking(), false);
    assert_eq!(client.is_handshaking(), false);
    check_read(&mut server, b"012345678901234567890123456789");
}

#[test]
fn vectored_write_with_slow_client() {
    let (mut client, mut server) = make_pair(KeyType::RSA);

    client.set_buffer_limit(32);

    do_handshake(&mut client, &mut server);
    server.write(b"01234567890123456789").unwrap();

    {
        let mut pipe = OtherSession::new(&mut client);
        pipe.short_writes = true;
        let wrlen = server.writev_tls(&mut pipe).unwrap() +
            server.writev_tls(&mut pipe).unwrap() +
            server.writev_tls(&mut pipe).unwrap() +
            server.writev_tls(&mut pipe).unwrap() +
            server.writev_tls(&mut pipe).unwrap() +
            server.writev_tls(&mut pipe).unwrap();
        assert_eq!(42, wrlen);
        assert_eq!(pipe.writevs, vec![vec![21], vec![10], vec![5], vec![3], vec![3]]);
    }
    check_read(&mut client, b"01234567890123456789");
}
