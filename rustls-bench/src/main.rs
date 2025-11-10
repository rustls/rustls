// This program does assorted benchmarking of rustls.
//
// Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
// etc. because it's unstable at the time of writing.
#![warn(
    clippy::alloc_instead_of_core,
    clippy::manual_let_else,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    elided_lifetimes_in_paths,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use core::mem;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use rustls::client::{Resumption, UnbufferedClientConnection};
use rustls::crypto::{CryptoProvider, Identity};
use rustls::enums::{CipherSuite, ProtocolVersion};
use rustls::server::{
    NoServerSessionStorage, ServerSessionMemoryCache, UnbufferedServerConnection,
    WebPkiClientVerifier,
};
use rustls::unbuffered::{ConnectionState, EncryptError, InsufficientSizeError, UnbufferedStatus};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, HandshakeKind, RootCertStore, ServerConfig,
    ServerConnection, SideData,
};
use rustls_test::KeyType;

pub fn main() {
    let args = Args::parse();

    match args.command() {
        Command::Bulk {
            cipher_suite,
            plaintext_size,
            max_fragment_size,
        } => {
            let provider = args
                .provider
                .unwrap_or_else(Provider::choose_default);
            for bench in lookup_matching_benches(cipher_suite, args.key_type, &provider).iter() {
                bench_bulk(
                    &Parameters::new(bench, &args)
                        .with_plaintext_size(*plaintext_size)
                        .with_max_fragment(*max_fragment_size),
                );
            }
        }

        Command::Handshake { cipher_suite }
        | Command::HandshakeResume { cipher_suite }
        | Command::HandshakeTicket { cipher_suite } => {
            let resume = ResumptionParam::from_subcommand(args.command());
            let provider = args
                .provider
                .unwrap_or_else(Provider::choose_default);
            for bench in lookup_matching_benches(cipher_suite, args.key_type, &provider).iter() {
                bench_handshake(
                    &Parameters::new(bench, &args)
                        .with_client_auth(ClientAuth::No)
                        .with_resume(resume),
                );
            }
        }
        Command::Memory {
            cipher_suite,
            count,
        } => {
            let provider = args
                .provider
                .unwrap_or_else(Provider::choose_default);
            for bench in lookup_matching_benches(cipher_suite, args.key_type, &provider).iter() {
                let params = Parameters::new(bench, &args);
                let client_config = params.client_config();
                let server_config = params.server_config();

                bench_memory(client_config, server_config, *count);
            }
        }
        Command::ListSuites => {
            let provider = args
                .provider
                .unwrap_or_else(Provider::choose_default);
            for bench in ALL_BENCHMARKS
                .iter()
                .filter(|t| provider.supports_benchmark(t))
            {
                println!(
                    "{:?} (key={:?} version={:?})",
                    bench.ciphersuite, bench.key_type, bench.version
                );
            }
        }
        Command::AllTests => {
            all_tests(&args);
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about = "Runs rustls benchmarks")]
struct Args {
    #[arg(
        long,
        default_value_t = 1.0,
        env = "BENCH_MULTIPLIER",
        help = "Multiplies the length of every test by the given float value"
    )]
    multiplier: f64,

    #[arg(
        long,
        env = "BENCH_LATENCY",
        help = "Writes individual handshake latency into files starting with this string.  The files are named by appending a role (client/server), a thread id, and 'latency.tsv' to the given string."
    )]
    latency_prefix: Option<String>,

    #[arg(
        long,
        help = "Which key type to use for server and client authentication.  The default is to run tests once for each key type."
    )]
    key_type: Option<RequestedKeyType>,

    #[arg(long, help = "Which provider to test")]
    provider: Option<Provider>,

    #[arg(long, default_value = "1", help = "Number of threads to use")]
    threads: NonZeroUsize,

    #[arg(long, value_enum, default_value_t = Api::Both, help = "Choose buffered or unbuffered API")]
    api: Api,

    #[command(subcommand)]
    command: Option<Command>,
}

impl Args {
    fn command(&self) -> &Command {
        self.command
            .as_ref()
            .unwrap_or(&Command::AllTests)
    }
}

#[derive(Parser, Debug)]
enum Command {
    #[command(about = "Runs bulk data benchmarks")]
    Bulk {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,

        #[arg(default_value_t = 1048576, help = "The size of each data write")]
        plaintext_size: u64,

        #[arg(help = "Maximum TLS fragment size")]
        max_fragment_size: Option<usize>,
    },

    #[command(about = "Runs full handshake speed benchmarks")]
    Handshake {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,
    },

    #[command(about = "Runs stateful resumed handshake speed benchmarks")]
    HandshakeResume {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,
    },

    #[command(about = "Runs stateless resumed handshake speed benchmarks")]
    HandshakeTicket {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,
    },

    #[command(
        about = "Runs memory benchmarks",
        long_about = "This creates `count` connections in parallel (count / 2 clients connected\n\
                      to count / 2 servers), and then moves them in lock-step though the handshake.\n\
                      Once the handshake completes the client writes 1KB of data to the server."
    )]
    Memory {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,

        #[arg(
            default_value_t = 1000000,
            help = "How many connections to create in parallel"
        )]
        count: u64,
    },

    #[command(about = "Lists the supported values for cipher-suite options")]
    ListSuites,

    #[command(about = "Run all tests (the default subcommand)")]
    AllTests,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Api {
    Both,
    Buffered,
    Unbuffered,
}

impl Api {
    fn use_buffered(&self) -> bool {
        matches!(*self, Self::Both | Self::Buffered)
    }

    fn use_unbuffered(&self) -> bool {
        matches!(*self, Self::Both | Self::Unbuffered)
    }
}

fn all_tests(args: &Args) {
    let provider = args
        .provider
        .unwrap_or_else(Provider::choose_default);

    for bench in ALL_BENCHMARKS
        .iter()
        .filter(|t| provider.supports_benchmark(t))
    {
        let params = Parameters::new(bench, args).with_plaintext_size(1024 * 1024);
        bench_bulk(&params);
        bench_bulk(&params.with_max_fragment(Some(10000)));
        bench_handshake(&params);
        bench_handshake(&params.with_client_auth(ClientAuth::Yes));
        bench_handshake(&params.with_resume(ResumptionParam::SessionId));
        bench_handshake(
            &params
                .with_client_auth(ClientAuth::Yes)
                .with_resume(ResumptionParam::SessionId),
        );
        bench_handshake(&params.with_resume(ResumptionParam::Tickets));
        bench_handshake(
            &params
                .with_client_auth(ClientAuth::Yes)
                .with_resume(ResumptionParam::Tickets),
        );
    }
}

fn bench_handshake(params: &Parameters) {
    let client_config = params.client_config();
    let server_config = params.server_config();

    let rounds = params.apply_work_multiplier(if params.resume == ResumptionParam::No {
        512
    } else {
        4096
    });

    // warm up, and prime session cache for resumptions
    bench_handshake_buffered(
        1,
        ResumptionParam::No,
        client_config.clone(),
        server_config.clone(),
        &params.without_latency_measurement(),
    );

    if params.api.use_buffered() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_handshake_buffered(
                    rounds,
                    params.resume,
                    client_config,
                    server_config,
                    params,
                )
            },
        );

        report_handshake_result("handshakes", params, rounds, results);
    }

    if params.api.use_unbuffered() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_handshake_unbuffered(rounds, params.resume, client_config, server_config)
            },
        );

        report_handshake_result("handshakes-unbuffered", params, rounds, results);
    }
}

fn bench_handshake_buffered(
    mut rounds: u64,
    resume: ResumptionParam,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    params: &Parameters,
) -> Timings {
    let mut timings = Timings::default();
    let mut buffers = TempBuffers::new();
    let mut client_latency = params.open_latency_file("client");
    let mut server_latency = params.open_latency_file("server");

    while rounds > 0 {
        let mut client_time = 0f64;
        let mut server_time = 0f64;

        let mut client = time(&mut client_time, || {
            let server_name = "localhost".try_into().unwrap();
            ClientConnection::new(client_config.clone(), server_name).unwrap()
        });
        let mut server = time(&mut server_time, || {
            ServerConnection::new(server_config.clone()).unwrap()
        });

        time(&mut server_time, || {
            transfer(&mut buffers, &mut client, &mut server, None);
        });
        time(&mut client_time, || {
            transfer(&mut buffers, &mut server, &mut client, None);
        });
        time(&mut server_time, || {
            transfer(&mut buffers, &mut client, &mut server, None);
        });
        time(&mut client_time, || {
            transfer(&mut buffers, &mut server, &mut client, None);
        });

        // check we reached idle
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());

        // if we achieved the desired handshake shape, count this handshake.
        if client.handshake_kind() == Some(resume.as_handshake_kind())
            && server.handshake_kind() == Some(resume.as_handshake_kind())
        {
            client_latency.sample(client_time);
            server_latency.sample(server_time);
            timings.client += client_time;
            timings.server += server_time;
            rounds -= 1;
        } else {
            // otherwise, this handshake is ignored against the quota for this thread,
            // and serves just to refresh the session cache.  that is mainly
            // necessary for TLS1.3, where tickets are single-use and limited to
            // 8 per server.
        }
    }

    timings
}

fn bench_handshake_unbuffered(
    mut rounds: u64,
    resume: ResumptionParam,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> Timings {
    let mut timings = Timings::default();

    while rounds > 0 {
        let mut client_time = 0f64;
        let mut server_time = 0f64;

        let client = time(&mut client_time, || {
            let server_name = "localhost".try_into().unwrap();
            UnbufferedClientConnection::new(client_config.clone(), server_name).unwrap()
        });
        let server = time(&mut server_time, || {
            UnbufferedServerConnection::new(server_config.clone()).unwrap()
        });

        // nb. buffer allocation is outside the library, so is outside the benchmark scope
        let mut client = Unbuffered::new_client(client);
        let mut server = Unbuffered::new_server(server);

        let client_wrote = time(&mut client_time, || client.communicate());
        if client_wrote {
            client.swap_buffers(&mut server);
        }

        let server_wrote = time(&mut server_time, || server.communicate());
        if server_wrote {
            server.swap_buffers(&mut client);
        }

        let client_wrote = time(&mut client_time, || client.communicate());
        if client_wrote {
            client.swap_buffers(&mut server);
        }

        let server_wrote = time(&mut server_time, || server.communicate());
        if server_wrote {
            server.swap_buffers(&mut client);
        }

        // check we reached idle
        assert!(!server.communicate());
        assert!(!client.communicate());

        // if we achieved the desired handshake shape, count this handshake.
        if client.conn.handshake_kind() == Some(resume.as_handshake_kind())
            && server.conn.handshake_kind() == Some(resume.as_handshake_kind())
        {
            timings.client += client_time;
            timings.server += server_time;
            rounds -= 1;
        } else {
            // otherwise, this handshake is ignored against the quota for this thread,
            // and serves just to refresh the session cache.  that is mainly
            // necessary for TLS1.3, where tickets are single-use and limited to
            // 8 per server.
        }
    }

    timings
}

/// Run `f` on `count` threads, and then return the timings produced
/// by each thread.
///
/// `client_config` and `server_config` are cloned into each thread fn.
fn multithreaded(
    count: NonZeroUsize,
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
    f: impl Fn(Arc<ClientConfig>, Arc<ServerConfig>) -> Timings + Send + Sync,
) -> Vec<Timings> {
    if count.get() == 1 {
        // Use the current thread if possible; for mysterious reasons this is much
        // faster for bulk tests on Intel, but makes little difference on AMD and
        // elsewhere.
        return vec![f(client_config.clone(), server_config.clone())];
    }

    thread::scope(|s| {
        let threads = (0..count.into())
            .map(|_| {
                let client_config = client_config.clone();
                let server_config = server_config.clone();
                s.spawn(|| f(client_config, server_config))
            })
            .collect::<Vec<_>>();

        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<Timings>>()
    })
}

fn report_handshake_result(variant: &str, params: &Parameters, rounds: u64, timings: Vec<Timings>) {
    print!(
        "{}\t{:?}\t{:?}\t{:?}\tclient\t{}\t{}\t",
        variant,
        params.proto.version,
        params.proto.key_type,
        params.proto.ciphersuite,
        params.client_auth.label(),
        params.resume.label(),
    );
    report_timings("handshakes/s", &timings, rounds as f64, |t| t.client);

    print!(
        "{}\t{:?}\t{:?}\t{:?}\tserver\t{}\t{}\t",
        variant,
        params.proto.version,
        params.proto.key_type,
        params.proto.ciphersuite,
        params.client_auth.label(),
        params.resume.label(),
    );
    report_timings("handshakes/s", &timings, rounds as f64, |t| t.server);
}

fn report_timings(
    units: &str,
    thread_timings: &[Timings],
    work_per_thread: f64,
    which: impl Fn(&Timings) -> f64,
) {
    // maintain old output for --threads=1
    if let &[timing] = thread_timings {
        println!("{:.2}\t{}", work_per_thread / which(&timing), units);
        return;
    }

    let mut total_rate = 0.;
    print!("threads\t{}\t", thread_timings.len());

    for t in thread_timings.iter() {
        let rate = work_per_thread / which(t);
        total_rate += rate;
        print!("{rate:.2}\t");
    }

    println!(
        "total\t{:.2}\tper-thread\t{:.2}\t{}",
        total_rate,
        total_rate / (thread_timings.len() as f64),
        units,
    );
}

#[derive(Clone, Copy, Debug, Default)]
struct Timings {
    client: f64,
    server: f64,
}

fn bench_bulk(params: &Parameters) {
    let client_config = params.client_config();
    let server_config = params.server_config();

    // for small plaintext_sizes and their associated slowness, send
    // less total data
    let total_data = params.apply_work_multiplier(
        1024 * 1024
            * match params.plaintext_size {
                ..=8192 => 64,
                _ => 1024,
            },
    );
    let rounds = total_data / params.plaintext_size;

    if params.api.use_buffered() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_bulk_buffered(client_config, server_config, params.plaintext_size, rounds)
            },
        );

        report_bulk_result("bulk", params, results, rounds);
    }

    if params.api.use_unbuffered() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_bulk_unbuffered(client_config, server_config, params.plaintext_size, rounds)
            },
        );

        report_bulk_result("bulk-unbuffered", params, results, rounds);
    }
}

fn bench_bulk_buffered(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    plaintext_size: u64,
    rounds: u64,
) -> Timings {
    let server_name = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(client_config, server_name).unwrap();
    client.set_buffer_limit(None);
    let mut server = ServerConnection::new(server_config).unwrap();
    server.set_buffer_limit(None);

    let mut timings = Timings::default();
    let mut buffers = TempBuffers::new();
    do_handshake(&mut buffers, &mut client, &mut server);

    let buf = vec![0; plaintext_size as usize];
    for _ in 0..rounds {
        time(&mut timings.server, || {
            server.writer().write_all(&buf).unwrap();
        });

        timings.client += transfer(&mut buffers, &mut server, &mut client, Some(buf.len()));
    }

    timings
}

fn bench_bulk_unbuffered(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    plaintext_size: u64,
    rounds: u64,
) -> Timings {
    let server_name = "localhost".try_into().unwrap();
    let mut client = Unbuffered::new_client(
        UnbufferedClientConnection::new(client_config, server_name).unwrap(),
    );
    let mut server =
        Unbuffered::new_server(UnbufferedServerConnection::new(server_config).unwrap());

    client.handshake(&mut server);

    let mut timings = Timings::default();

    let buf = vec![0; plaintext_size as usize];
    for _ in 0..rounds {
        time(&mut timings.server, || {
            server.write(&buf);
        });

        server.swap_buffers(&mut client);

        time(&mut timings.client, || {
            client.read_and_discard(buf.len());
        });
    }

    timings
}

fn report_bulk_result(variant: &str, params: &Parameters, timings: Vec<Timings>, rounds: u64) {
    let mfs_str = format!(
        "max_fragment_size:{}",
        params
            .max_fragment_size
            .map(|v| v.to_string())
            .unwrap_or_else(|| "default".to_string())
    );
    let total_mbs = ((params.plaintext_size * rounds) as f64) / (1024. * 1024.);
    print!(
        "{}\t{:?}\t{:?}\t{}\tsend\t",
        variant, params.proto.version, params.proto.ciphersuite, mfs_str,
    );
    report_timings("MB/s", &timings, total_mbs, |t| t.server);

    print!(
        "{}\t{:?}\t{:?}\t{}\trecv\t",
        variant, params.proto.version, params.proto.ciphersuite, mfs_str,
    );
    report_timings("MB/s", &timings, total_mbs, |t| t.client);
}

fn bench_memory(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    conn_count: u64,
) {
    // The target here is to end up with conn_count post-handshake
    // server and client sessions.
    let conn_count = (conn_count / 2) as usize;
    let mut servers = Vec::with_capacity(conn_count);
    let mut clients = Vec::with_capacity(conn_count);
    let mut buffers = TempBuffers::new();

    for _i in 0..conn_count {
        servers.push(ServerConnection::new(server_config.clone()).unwrap());
        let server_name = "localhost".try_into().unwrap();
        clients.push(ClientConnection::new(client_config.clone(), server_name).unwrap());
    }

    for _step in 0..5 {
        for (client, server) in clients
            .iter_mut()
            .zip(servers.iter_mut())
        {
            do_handshake_step(&mut buffers, client, server);
        }
    }

    for client in clients.iter_mut() {
        client
            .writer()
            .write_all(&[0u8; 1024])
            .unwrap();
    }

    for (client, server) in clients
        .iter_mut()
        .zip(servers.iter_mut())
    {
        transfer(&mut buffers, client, server, Some(1024));
    }
}

fn lookup_matching_benches(
    ciphersuite_name: &str,
    key_type: Option<RequestedKeyType>,
    provider: &Provider,
) -> Vec<BenchmarkParam> {
    let r: Vec<BenchmarkParam> = ALL_BENCHMARKS
        .iter()
        .filter(|params| {
            format!("{:?}", params.ciphersuite).to_lowercase() == ciphersuite_name.to_lowercase()
                && (key_type.is_none() || Some(params.key_type) == key_type.map(KeyType::from))
                && provider.supports_benchmark(params)
        })
        .cloned()
        .collect();

    if r.is_empty() {
        panic!("unknown suite {ciphersuite_name:?}");
    }

    r
}

/// General parameters common to several kinds of benchmark.
#[derive(Clone)]
struct Parameters {
    /// Set by the user.
    work_multiplier: f64,
    latency_prefix: Option<String>,
    provider: Provider,
    api: Api,
    threads: NonZeroUsize,

    /// A compatible key/cipher suite/version combination.
    proto: BenchmarkParam,

    /// Whether the client authenticates.
    client_auth: ClientAuth,

    /// Whether the sessions are resumed.
    resume: ResumptionParam,

    /// The maximum fragment size (if any).
    max_fragment_size: Option<usize>,

    /// For bulk benchmarks, how much data to send
    plaintext_size: u64,
}

impl Parameters {
    fn new(bench: &BenchmarkParam, args: &Args) -> Self {
        Self {
            work_multiplier: args.multiplier,
            latency_prefix: args.latency_prefix.clone(),
            provider: args
                .provider
                .unwrap_or_else(Provider::choose_default),
            api: args.api,
            threads: args.threads,
            proto: bench.clone(),
            client_auth: ClientAuth::No,
            resume: ResumptionParam::No,
            max_fragment_size: None,
            plaintext_size: 1024,
        }
    }

    fn with_plaintext_size(&self, plaintext_size: u64) -> Self {
        let mut s = self.clone();
        s.plaintext_size = plaintext_size;
        s
    }

    fn with_max_fragment(&self, max_fragment_size: Option<usize>) -> Self {
        let mut s = self.clone();
        s.max_fragment_size = max_fragment_size;
        s
    }

    fn with_client_auth(&self, client_auth: ClientAuth) -> Self {
        let mut s = self.clone();
        s.client_auth = client_auth;
        s
    }

    fn with_resume(&self, resume: ResumptionParam) -> Self {
        let mut s = self.clone();
        s.resume = resume;
        s
    }

    fn without_latency_measurement(&self) -> Self {
        let mut s = self.clone();
        s.latency_prefix = None;
        s
    }

    fn server_config(&self) -> Arc<ServerConfig> {
        let provider = Arc::new(self.provider.build());
        let client_auth = match self.client_auth {
            ClientAuth::Yes => {
                let Identity::X509(id) = &*self.proto.key_type.identity() else {
                    panic!("client auth requested but no X.509 identity available");
                };

                let mut client_auth_roots = RootCertStore::empty();
                for root in &id.intermediates {
                    client_auth_roots
                        .add(root.clone())
                        .unwrap();
                }

                WebPkiClientVerifier::builder(client_auth_roots.into(), &provider)
                    .build()
                    .unwrap()
            }
            ClientAuth::No => WebPkiClientVerifier::no_client_auth(),
        };

        let mut cfg = ServerConfig::builder(provider)
            .with_client_cert_verifier(client_auth)
            .with_single_cert(self.proto.key_type.identity(), self.proto.key_type.key())
            .expect("bad certs/private key?");

        match self.resume {
            ResumptionParam::SessionId => {
                cfg.session_storage = ServerSessionMemoryCache::new(128);
            }
            ResumptionParam::Tickets => {
                cfg.ticketer = Some(
                    cfg.crypto_provider()
                        .ticketer_factory
                        .ticketer()
                        .unwrap(),
                );
            }
            ResumptionParam::No => {
                cfg.session_storage = Arc::new(NoServerSessionStorage {});
            }
        }

        cfg.max_fragment_size = self.max_fragment_size;
        Arc::new(cfg)
    }

    fn client_config(&self) -> Arc<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(self.proto.key_type.ca_cert())
            .unwrap();

        let cfg = ClientConfig::builder(
            self.provider
                .build_with_cipher_suite(self.proto.ciphersuite)
                .into(),
        )
        .with_root_certificates(root_store);

        let mut cfg = match self.client_auth {
            ClientAuth::Yes => cfg
                .with_client_auth_cert(
                    self.proto.key_type.client_identity(),
                    self.proto.key_type.client_key(),
                )
                .unwrap(),
            ClientAuth::No => cfg.with_no_client_auth().unwrap(),
        };

        cfg.resumption = match self.resume {
            ResumptionParam::No => Resumption::disabled(),
            _ => Resumption::in_memory_sessions(128),
        };

        Arc::new(cfg)
    }

    fn apply_work_multiplier(&self, work: u64) -> u64 {
        ((work as f64) * self.work_multiplier).round() as u64
    }

    fn open_latency_file(&self, role: &str) -> LatencyOutput {
        LatencyOutput::new(&self.latency_prefix, role)
    }
}

struct LatencyOutput {
    output: Option<File>,
}

impl LatencyOutput {
    fn new(prefix: &Option<String>, role: &str) -> Self {
        let thread_id = thread::current().id();
        let output = prefix.as_ref().map(|prefix| {
            let file_name = format!("{prefix}-{role}-{thread_id:?}-latency.tsv");
            File::create(&file_name).expect("cannot open latency output file")
        });

        Self { output }
    }

    fn sample(&mut self, secs: f64) {
        if let Some(file) = &mut self.output {
            writeln!(file, "{:.8}\t{:.8}", wall_time(), secs * 1e6).unwrap();
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum ClientAuth {
    No,
    Yes,
}

impl ClientAuth {
    fn label(&self) -> &'static str {
        match *self {
            Self::No => "server-auth",
            Self::Yes => "mutual",
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum ResumptionParam {
    No,
    SessionId,
    Tickets,
}

impl ResumptionParam {
    fn from_subcommand(cmd: &Command) -> Self {
        match cmd {
            Command::Handshake { .. } => Self::No,
            Command::HandshakeResume { .. } => Self::SessionId,
            Command::HandshakeTicket { .. } => Self::Tickets,
            _ => todo!("unhandled subcommand {cmd:?}"),
        }
    }

    fn as_handshake_kind(&self) -> HandshakeKind {
        match *self {
            Self::No => HandshakeKind::Full,
            Self::SessionId | Self::Tickets => HandshakeKind::Resumed,
        }
    }

    fn label(&self) -> &'static str {
        match *self {
            Self::No => "no-resume",
            Self::SessionId => "sessionid",
            Self::Tickets => "tickets",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum Provider {
    #[cfg(feature = "aws-lc-rs")]
    AwsLcRs,
    #[cfg(all(feature = "aws-lc-rs", feature = "fips"))]
    AwsLcRsFips,
    #[cfg(feature = "graviola")]
    Graviola,
    #[cfg(feature = "ring")]
    Ring,
    #[value(skip)]
    _None, // prevents this enum being uninhabited when built with no features
}

impl Provider {
    fn build(self) -> CryptoProvider {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::AwsLcRs => rustls::crypto::aws_lc_rs::DEFAULT_PROVIDER,
            #[cfg(all(feature = "aws-lc-rs", feature = "fips"))]
            Self::AwsLcRsFips => rustls::crypto::default_fips_provider(),
            #[cfg(feature = "graviola")]
            Self::Graviola => rustls_graviola::default_provider(),
            #[cfg(feature = "ring")]
            Self::Ring => rustls_ring::DEFAULT_PROVIDER,
            Self::_None => unreachable!(),
        }
    }

    fn build_with_cipher_suite(&self, name: CipherSuite) -> CryptoProvider {
        let mut provider = self.build();
        provider
            .tls12_cipher_suites
            .to_mut()
            .retain(|cs| cs.common.suite == name);
        provider
            .tls13_cipher_suites
            .to_mut()
            .retain(|cs| cs.common.suite == name);
        provider
    }

    fn supports_benchmark(&self, param: &BenchmarkParam) -> bool {
        let prov = self.build_with_cipher_suite(param.ciphersuite);
        (prov.tls12_cipher_suites.len() + prov.tls13_cipher_suites.len()) > 0
            && self.supports_key_type(param.key_type)
    }

    fn supports_key_type(&self, _key_type: KeyType) -> bool {
        match self {
            #[cfg(feature = "graviola")]
            Self::Graviola => !matches!(_key_type, KeyType::Ed25519),
            // all other providers support all key types
            _ => true,
        }
    }

    fn choose_default() -> Self {
        #[allow(unused_mut)]
        let mut available = vec![];

        #[cfg(feature = "aws-lc-rs")]
        available.push(Self::AwsLcRs);

        #[cfg(all(feature = "aws-lc-rs", feature = "fips"))]
        available.push(Self::AwsLcRsFips);

        #[cfg(feature = "graviola")]
        available.push(Self::Graviola);

        #[cfg(feature = "ring")]
        available.push(Self::Ring);

        match available[..] {
            [] => panic!("no providers available in this build"),
            [one] => one,
            _ => panic!("you must choose provider: available are {available:?}"),
        }
    }
}

/// Known combinations of valid test cases.
///
/// See `ALL_BENCHMARKS`.
#[derive(Clone)]
struct BenchmarkParam {
    key_type: KeyType,
    ciphersuite: CipherSuite,
    version: ProtocolVersion,
}

impl BenchmarkParam {
    const fn new(key_type: KeyType, ciphersuite: CipherSuite, version: ProtocolVersion) -> Self {
        Self {
            key_type,
            ciphersuite,
            version,
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug, ValueEnum)]
enum RequestedKeyType {
    Rsa2048,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

impl From<RequestedKeyType> for KeyType {
    fn from(val: RequestedKeyType) -> Self {
        match val {
            RequestedKeyType::Rsa2048 => Self::Rsa2048,
            RequestedKeyType::EcdsaP256 => Self::EcdsaP256,
            RequestedKeyType::EcdsaP384 => Self::EcdsaP384,
            RequestedKeyType::Ed25519 => Self::Ed25519,
        }
    }
}

struct Unbuffered {
    conn: UnbufferedConnection,
    input: Vec<u8>,
    input_used: usize,
    output: Vec<u8>,
    output_used: usize,
}

impl Unbuffered {
    fn new_client(client: UnbufferedClientConnection) -> Self {
        Self {
            conn: UnbufferedConnection::Client(client),
            input: vec![0u8; Self::BUFFER_LEN],
            input_used: 0,
            output: vec![0u8; Self::BUFFER_LEN],
            output_used: 0,
        }
    }

    fn new_server(server: UnbufferedServerConnection) -> Self {
        Self {
            conn: UnbufferedConnection::Server(server),
            input: vec![0u8; Self::BUFFER_LEN],
            input_used: 0,
            output: vec![0u8; Self::BUFFER_LEN],
            output_used: 0,
        }
    }

    fn handshake(&mut self, peer: &mut Self) {
        loop {
            let mut progress = false;

            if self.communicate() {
                self.swap_buffers(peer);
                progress = true;
            }

            if peer.communicate() {
                peer.swap_buffers(self);
                progress = true;
            }

            if !progress {
                return;
            }
        }
    }

    fn swap_buffers(&mut self, peer: &mut Self) {
        // our output becomes peer's input, and peer's input
        // becomes our output.
        mem::swap(&mut self.input, &mut peer.output);
        mem::swap(&mut self.input_used, &mut peer.output_used);
        mem::swap(&mut self.output, &mut peer.input);
        mem::swap(&mut self.output_used, &mut peer.input_used);
    }

    fn communicate(&mut self) -> bool {
        let (input_used, output_added) = self.conn.communicate(
            &mut self.input[..self.input_used],
            &mut self.output[self.output_used..],
        );
        assert_eq!(input_used, self.input_used);
        self.input_used = 0;
        self.output_used += output_added;
        self.output_used > 0
    }

    fn write(&mut self, data: &[u8]) {
        assert_eq!(self.input_used, 0);
        let output_added = match self
            .conn
            .write(data, &mut self.output[self.output_used..])
        {
            Ok(output_added) => output_added,
            Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size, ..
            })) => {
                self.output
                    .resize(self.output_used + required_size, 0);
                self.conn
                    .write(data, &mut self.output[self.output_used..])
                    .unwrap()
            }
            Err(other) => panic!("unexpected write error {other:?}"),
        };
        self.output_used += output_added;
    }

    fn read_and_discard(&mut self, len: usize) {
        assert!(self.input_used > 0);
        let input_used = self
            .conn
            .read_and_discard(len, &mut self.input[..self.input_used]);
        assert_eq!(input_used, self.input_used);
        self.input_used = 0;
    }

    const BUFFER_LEN: usize = 16_384;
}

enum UnbufferedConnection {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

impl UnbufferedConnection {
    fn communicate(&mut self, input: &mut [u8], output: &mut [u8]) -> (usize, usize) {
        let mut input_used = 0;
        let mut output_added = 0;

        loop {
            match self {
                Self::Client(client) => {
                    match client.process_tls_records(&mut input[input_used..]) {
                        UnbufferedStatus {
                            state: Ok(ConnectionState::EncodeTlsData(mut etd)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            output_added += etd
                                .encode(&mut output[output_added..])
                                .unwrap();
                        }
                        UnbufferedStatus {
                            state: Ok(ConnectionState::TransmitTlsData(ttd)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            ttd.done();
                            return (input_used, output_added);
                        }
                        UnbufferedStatus {
                            state: Ok(ConnectionState::WriteTraffic(_)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            return (input_used, output_added);
                        }
                        st => {
                            println!("unexpected client {st:?}");
                            return (input_used, output_added);
                        }
                    }
                }
                Self::Server(server) => {
                    match server.process_tls_records(&mut input[input_used..]) {
                        UnbufferedStatus {
                            state: Ok(ConnectionState::EncodeTlsData(mut etd)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            output_added += etd
                                .encode(&mut output[output_added..])
                                .unwrap();
                        }
                        UnbufferedStatus {
                            state: Ok(ConnectionState::TransmitTlsData(ttd)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            ttd.done();
                            return (input_used, output_added);
                        }
                        UnbufferedStatus {
                            state: Ok(ConnectionState::WriteTraffic(_)),
                            discard,
                            ..
                        } => {
                            input_used += discard;
                            return (input_used, output_added);
                        }
                        st => {
                            println!("unexpected server {st:?}");
                            return (input_used, output_added);
                        }
                    }
                }
            }
        }
    }

    fn write(&mut self, data: &[u8], output: &mut [u8]) -> Result<usize, EncryptError> {
        match self {
            Self::Client(client) => match client.process_tls_records(&mut []) {
                UnbufferedStatus {
                    state: Ok(ConnectionState::WriteTraffic(mut wt)),
                    ..
                } => wt.encrypt(data, output),
                st => panic!("unexpected write state: {st:?}"),
            },
            Self::Server(server) => match server.process_tls_records(&mut []) {
                UnbufferedStatus {
                    state: Ok(ConnectionState::WriteTraffic(mut wt)),
                    ..
                } => wt.encrypt(data, output),
                st => panic!("unexpected write state: {st:?}"),
            },
        }
    }

    fn read_and_discard(&mut self, mut expected: usize, input: &mut [u8]) -> usize {
        let mut input_used = 0;

        let client = match self {
            Self::Client(client) => client,
            Self::Server(_) => todo!("server read"),
        };

        while expected > 0 {
            match client.process_tls_records(&mut input[input_used..]) {
                UnbufferedStatus {
                    state: Ok(ConnectionState::ReadTraffic(mut rt)),
                    discard,
                    ..
                } => {
                    input_used += discard;
                    let record = rt.next_record().unwrap().unwrap();
                    input_used += record.discard;
                    expected -= record.payload.len();
                }
                st => panic!("unexpected read state: {st:?}"),
            }
        }

        input_used
    }

    fn handshake_kind(&self) -> Option<HandshakeKind> {
        match self {
            Self::Client(client) => client.handshake_kind(),
            Self::Server(server) => server.handshake_kind(),
        }
    }
}

fn do_handshake_step(
    buffers: &mut TempBuffers,
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> bool {
    if server.is_handshaking() || client.is_handshaking() {
        transfer(buffers, client, server, None);
        transfer(buffers, server, client, None);
        true
    } else {
        false
    }
}

fn do_handshake(
    buffers: &mut TempBuffers,
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) {
    while do_handshake_step(buffers, client, server) {}
}

fn time<F, T>(time_out: &mut f64, mut f: F) -> T
where
    F: FnMut() -> T,
{
    let start = Instant::now();
    let r = f();
    let end = Instant::now();
    *time_out += duration_nanos(end.duration_since(start));
    r
}

fn transfer<L, R, LS, RS>(
    buffers: &mut TempBuffers,
    left: &mut L,
    right: &mut R,
    expect_data: Option<usize>,
) -> f64
where
    L: DerefMut + Deref<Target = ConnectionCommon<LS>>,
    R: DerefMut + Deref<Target = ConnectionCommon<RS>>,
    LS: SideData,
    RS: SideData,
{
    let mut read_time = 0f64;
    let mut data_left = expect_data;

    loop {
        let mut sz = 0;

        while left.wants_write() {
            let written = left
                .write_tls(&mut buffers.tls[sz..].as_mut())
                .unwrap();
            if written == 0 {
                break;
            }

            sz += written;
        }

        if sz == 0 {
            return read_time;
        }

        let mut offs = 0;
        loop {
            let start = Instant::now();
            match right.read_tls(&mut buffers.tls[offs..sz].as_ref()) {
                Ok(read) => {
                    right.process_new_packets().unwrap();
                    offs += read;
                }
                Err(err) => {
                    panic!("error on transfer {offs}..{sz}: {err}");
                }
            }

            if let Some(left) = &mut data_left {
                loop {
                    let sz = match right.reader().read(&mut [0u8; 16_384]) {
                        Ok(sz) => sz,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => panic!("failed to read data: {err}"),
                    };

                    *left -= sz;
                    if *left == 0 {
                        break;
                    }
                }
            }

            let end = Instant::now();
            read_time += duration_nanos(end.duration_since(start));
            if sz == offs {
                break;
            }
        }
    }
}

/// Temporary buffers shared between calls.
struct TempBuffers {
    tls: Vec<u8>,
}

impl TempBuffers {
    fn new() -> Self {
        Self {
            tls: vec![0u8; 262_144],
        }
    }
}

fn wall_time() -> f64 {
    duration_nanos(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap(),
    )
}

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + f64::from(d.subsec_nanos()) / 1e9
}

static ALL_BENCHMARKS: &[BenchmarkParam] = &[
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::EcdsaP256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::EcdsaP256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::EcdsaP384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::Ed25519,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_2,
    ),
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::EcdsaP256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::Ed25519,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::Rsa2048,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::EcdsaP256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        ProtocolVersion::TLSv1_3,
    ),
    BenchmarkParam::new(
        KeyType::Ed25519,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        ProtocolVersion::TLSv1_3,
    ),
];

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
