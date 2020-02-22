// This program does assorted benchmarking of rustls.
//
// Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
// etc. because it's unstable at the time of writing.

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::fs;
use std::io::{self, Write, Read};
use std::env;

use rustls;
use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::ServerSessionMemoryCache;
use rustls::ClientSessionMemoryCache;
use rustls::NoServerSessionStorage;
use rustls::NoClientSessionStorage;
use rustls::{NoClientAuth, RootCertStore, AllowAnyAuthenticatedClient};
use rustls::Session;
use rustls::Ticketer;
use rustls::internal::pemfile;
use rustls::internal::msgs::enums::SignatureAlgorithm;

use webpki;

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + f64::from(d.subsec_nanos()) / 1e9
}

fn _bench<Fsetup, Ftest, S>(count: usize, name: &'static str, f_setup: Fsetup, f_test: Ftest)
    where Fsetup: Fn() -> S,
          Ftest: Fn(S)
{
    let mut times = Vec::new();

    for _ in 0..count {
        let state = f_setup();
        let start = Instant::now();
        f_test(state);
        times.push(duration_nanos(Instant::now().duration_since(start)));
    }

    println!("{}", name);
    println!("{:?}", times);
}

fn time<F>(mut f: F) -> f64
    where F: FnMut()
{
    let start = Instant::now();
    f();
    let end = Instant::now();
    let dur = duration_nanos(end.duration_since(start));
    f64::from(dur)
}

fn transfer(left: &mut dyn Session, right: &mut dyn Session) -> f64 {
    let mut buf = [0u8; 262144];
    let mut read_time = 0f64;

    while left.wants_write() {
        let sz = left.write_tls(&mut buf.as_mut()).unwrap();

        if sz == 0 {
            return read_time;
        }

        let mut offs = 0;
        loop {
            let start = Instant::now();
            offs += right.read_tls(&mut buf[offs..sz].as_ref()).unwrap();
            let end = Instant::now();
            read_time += f64::from(duration_nanos(end.duration_since(start)));
            if sz == offs {
                break;
            }
        }
    }

    read_time
}

fn drain(d: &mut dyn Session, expect_len: usize) {
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

#[derive(PartialEq, Clone, Copy)]
enum ClientAuth {
    No,
    Yes,
}

#[derive(PartialEq, Clone, Copy)]
enum Resumption {
    No,
    SessionID,
    Tickets,
}

impl Resumption {
    fn label(&self) -> &'static str {
        match *self {
            Resumption::No => "no-resume",
            Resumption::SessionID => "sessionid",
            Resumption::Tickets => "tickets",
        }
    }
}

// copied from tests/api.rs
#[derive(PartialEq, Clone, Copy)]
enum KeyType {
    RSA,
    ECDSA
}

impl KeyType {
    fn for_suite(suite: &'static rustls::SupportedCipherSuite) -> KeyType {
        if suite.sign == SignatureAlgorithm::ECDSA {
            KeyType::ECDSA
        } else {
            KeyType::RSA
        }
    }

    fn path_for(&self, part: &str) -> String {
        match self {
            KeyType::RSA => format!("test-ca/rsa/{}", part),
            KeyType::ECDSA => format!("test-ca/ecdsa/{}", part),
        }
    }

    fn get_chain(&self) -> Vec<rustls::Certificate> {
        pemfile::certs(&mut io::BufReader::new(fs::File::open(self.path_for("end.fullchain"))
                                               .unwrap()))
            .unwrap()
    }

    fn get_key(&self) -> rustls::PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(fs::File::open(self.path_for("end.key"))
                                                            .unwrap()))
                .unwrap()[0]
            .clone()
    }

    fn get_client_chain(&self) -> Vec<rustls::Certificate> {
        pemfile::certs(&mut io::BufReader::new(fs::File::open(self.path_for("client.fullchain"))
                                               .unwrap()))
            .unwrap()
    }

    fn get_client_key(&self) -> rustls::PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(fs::File::open(self.path_for("client.key"))
                                                            .unwrap()))
                .unwrap()[0]
            .clone()
    }
}

fn make_server_config(version: rustls::ProtocolVersion,
                      suite: &'static rustls::SupportedCipherSuite,
                      client_auth: ClientAuth,
                      resume: Resumption)
                      -> ServerConfig {
    let kt = KeyType::for_suite(suite);
    let client_auth = match client_auth {
        ClientAuth::Yes => {
            let roots = kt.get_chain();
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        },
        ClientAuth::No => {
            NoClientAuth::new()
        }
    };

    let mut cfg = ServerConfig::new(client_auth);
    cfg.set_single_cert(kt.get_chain(), kt.get_key())
        .expect("bad certs/private key?");

    if resume == Resumption::SessionID {
        cfg.set_persistence(ServerSessionMemoryCache::new(128));
    } else if resume == Resumption::Tickets {
        cfg.ticketer = Ticketer::new();
    } else {
        cfg.set_persistence(Arc::new(NoServerSessionStorage {}));
    }

    cfg.versions.clear();
    cfg.versions.push(version);

    cfg
}

fn make_client_config(version: rustls::ProtocolVersion,
                      suite: &'static rustls::SupportedCipherSuite,
                      clientauth: ClientAuth,
                      resume: Resumption)
                      -> ClientConfig {
    let kt = KeyType::for_suite(suite);
    let mut cfg = ClientConfig::new();
    let mut rootbuf = io::BufReader::new(fs::File::open(kt.path_for("ca.cert")).unwrap());
    cfg.root_store.add_pem_file(&mut rootbuf).unwrap();
    cfg.ciphersuites.clear();
    cfg.ciphersuites.push(suite);
    cfg.versions.clear();
    cfg.versions.push(version);

    if clientauth == ClientAuth::Yes {
        cfg.set_single_client_cert(kt.get_client_chain(), kt.get_client_key())
            .unwrap();
    }

    if resume != Resumption::No {
        cfg.set_persistence(ClientSessionMemoryCache::new(128));
    } else {
        cfg.set_persistence(Arc::new(NoClientSessionStorage {}));
    }

    cfg
}

fn apply_work_multiplier(work: u64) -> u64 {
    let mul = match env::var("BENCH_MULTIPLIER") {
        Ok(val) => val.parse::<f64>().expect("invalid BENCH_MULTIPLIER value"),
        Err(_) => 1.
    };

    ((work as f64) * mul).round() as u64
}

fn bench_handshake(version: rustls::ProtocolVersion,
                   suite: &'static rustls::SupportedCipherSuite,
                   clientauth: ClientAuth,
                   resume: Resumption) {
    let client_config = Arc::new(make_client_config(version, suite, clientauth, resume));
    let server_config = Arc::new(make_server_config(version, suite, clientauth, resume));

    if !suite.usable_for_version(version) {
        return;
    }

    let rounds = apply_work_multiplier(if resume == Resumption::No { 512 } else { 4096 });
    let mut client_time = 0f64;
    let mut server_time = 0f64;

    for _ in 0..rounds {
        let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
        let mut client = ClientSession::new(&client_config, dns_name);
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

    println!("handshakes\t{:?}\t{:?}\tclient\t{}\t{}\t{:.2}\thandshake/s",
             version,
             suite.suite,
             if clientauth == ClientAuth::Yes {
                 "mutual"
             } else {
                 "server-auth"
             },
             resume.label(),
             (rounds as f64) / client_time);
    println!("handshakes\t{:?}\t{:?}\tserver\t{}\t{}\t{:.2}\thandshake/s",
             version,
             suite.suite,
             if clientauth == ClientAuth::Yes {
                 "mutual"
             } else {
                 "server-auth"
             },
             resume.label(),
             (rounds as f64) / server_time);
}

fn do_handshake_step(client: &mut ClientSession, server: &mut ServerSession) -> bool {
    if server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets().unwrap();
        transfer(server, client);
        client.process_new_packets().unwrap();
        true
    } else {
        false
    }
}

fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) {
    while do_handshake_step(client, server) {}
}

fn bench_bulk(version: rustls::ProtocolVersion, suite: &'static rustls::SupportedCipherSuite,
              plaintext_size: u64) {
    let client_config =
        Arc::new(make_client_config(version, suite, ClientAuth::No, Resumption::No));
    let server_config = Arc::new(make_server_config(version, suite, ClientAuth::No, Resumption::No));

    if !suite.usable_for_version(version) {
        return;
    }

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut client = ClientSession::new(&client_config, dns_name);
    let mut server = ServerSession::new(&server_config);

    do_handshake(&mut client, &mut server);

    let mut buf = Vec::new();
    buf.resize(plaintext_size as usize, 0u8);

    let total_data = apply_work_multiplier(
        if plaintext_size < 8192 {
            64 * 1024 * 1024
        } else {
            1024 * 1024 * 1024
        }
    );
    let rounds = total_data / plaintext_size;
    let mut time_send = 0f64;
    let mut time_recv = 0f64;

    for _ in 0..rounds {
        time_send += time(|| {
            server.write_all(&buf).unwrap();
            ()
        });

        time_recv += transfer(&mut server, &mut client);

        time_recv += time(|| {
            client.process_new_packets().unwrap()
        });
        drain(&mut client, buf.len());
    }

    let total_mbs = ((plaintext_size * rounds) as f64) / (1024. * 1024.);
    println!("bulk\t{:?}\t{:?}\tsend\t{:.2}\tMB/s",
             version,
             suite.suite,
             total_mbs / time_send);
    println!("bulk\t{:?}\t{:?}\trecv\t{:.2}\tMB/s",
             version,
             suite.suite,
             total_mbs / time_recv);
}

fn bench_memory(version: rustls::ProtocolVersion,
                suite: &'static rustls::SupportedCipherSuite,
                session_count: u64) {
    let client_config =
        Arc::new(make_client_config(version, suite, ClientAuth::No, Resumption::No));
    let server_config = Arc::new(make_server_config(version, suite, ClientAuth::No, Resumption::No));

    if !suite.usable_for_version(version) {
        return;
    }

    // The target here is to end up with session_count post-handshake
    // server and client sessions.
    let session_count = (session_count / 2) as usize;
    let mut servers = Vec::with_capacity(session_count);
    let mut clients = Vec::with_capacity(session_count);

    for _i in 0..session_count {
        servers.push(ServerSession::new(&server_config));
        let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
        clients.push(ClientSession::new(&client_config, dns_name));
    }

    for _step in 0..5 {
        for (mut client, mut server) in clients.iter_mut().zip(servers.iter_mut()) {
            do_handshake_step(&mut client, &mut server);
        }
    }

    for client in clients.iter_mut() {
        client.write_all(&[0u8; 1024]).unwrap();
    }

    for (client, server) in clients.iter_mut().zip(servers.iter_mut()) {
        transfer(client, server);
        let mut buf = [0u8; 1024];
        server.read(&mut buf).unwrap();
    }
}

fn lookup_suite(name: &str) -> &'static rustls::SupportedCipherSuite {
    for suite in &rustls::ALL_CIPHERSUITES {
        if format!("{:?}", suite.suite).to_lowercase() == name.to_lowercase() {
            return suite;
        }
    }

    panic!("unknown suite {:?}", name);
}

fn selected_tests(mut args: env::Args) {
    let mode = args.next()
        .expect("first argument must be mode");

    match mode.as_ref() {
        "bulk" => {
            match args.next() {
                Some(suite) => {
                    let len = args.next()
                        .map(|arg| arg.parse::<u64>()
                             .expect("3rd arg must be plaintext size integer"))
                        .unwrap_or(1048576);
                    let suite = lookup_suite(&suite);
                    bench_bulk(rustls::ProtocolVersion::TLSv1_3, suite, len);
                    bench_bulk(rustls::ProtocolVersion::TLSv1_2, suite, len);
                }
                None => {
                    panic!("bulk needs ciphersuite argument");
                }
            }
        }

        "handshake" | "handshake-resume" | "handshake-ticket" => {
            match args.next() {
                Some(suite) => {
                    let suite = lookup_suite(&suite);
                    let resume = if mode == "handshake" {
                        Resumption::No
                    } else if mode == "handshake-resume" {
                        Resumption::SessionID
                    } else {
                        Resumption::Tickets
                    };

                    bench_handshake(rustls::ProtocolVersion::TLSv1_3, suite, ClientAuth::No, resume);
                    bench_handshake(rustls::ProtocolVersion::TLSv1_2, suite, ClientAuth::No, resume);
                }
                None => {
                    panic!("handshake* needs ciphersuite argument");
                }
            }
        }

        "memory" => {
            match args.next() {
                Some(suite) => {
                    let count = args.next()
                        .map(|arg| arg.parse::<u64>()
                             .expect("3rd arg must be session count integer"))
                        .unwrap_or(1000000);
                    let suite = lookup_suite(&suite);
                    bench_memory(rustls::ProtocolVersion::TLSv1_3, suite, count);
                    bench_memory(rustls::ProtocolVersion::TLSv1_2, suite, count);
                }
                None => {
                    panic!("memory needs ciphersuite argument");
                }
            }
        }

        _ => {
            panic!("unsupported mode {:?}", mode);
        }
    }
}

fn all_tests() {
    for version in &[rustls::ProtocolVersion::TLSv1_3, rustls::ProtocolVersion::TLSv1_2] {
        for suite in &rustls::ALL_CIPHERSUITES {
            bench_bulk(*version, suite, 1024 * 1024);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::No);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::No);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::SessionID);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::SessionID);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::Tickets);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::Tickets);
        }
    }
}

fn main() {
    let mut args = env::args();
    if args.len() > 1 {
        args.next();
        selected_tests(args);
    } else {
        all_tests();
    }
}
