// This program does assorted benchmarking of rustls.
//
// Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
// etc. because it's unstable at the time of writing.

use core::num::NonZeroUsize;
use core::time::Duration;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use rustls::client::{ClientHandshake, Resumption};
use rustls::crypto::{CipherSuite, CryptoProvider, Identity};
use rustls::enums::ProtocolVersion;
use rustls::server::{
    NoServerSessionStorage, ServerHandshake, ServerSessionMemoryCache, WebPkiClientVerifier,
};
use rustls::split::{ReceiveTraffic, ReceiveTrafficState, SendTraffic};
use rustls::{
    ClientConfig, ClientSide, Connection, HandshakeKind, RootCertStore, ServerConfig, ServerSide,
    SideData, SliceInput, Tcp,
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

        Command::BulkSplit {
            cipher_suite,
            plaintext_size,
        } => {
            let provider = args
                .provider
                .unwrap_or_else(Provider::choose_default);
            for bench in lookup_matching_benches(cipher_suite, args.key_type, &provider).iter() {
                bench_bulk_split(
                    &Parameters::new(bench, &args).with_plaintext_size(*plaintext_size),
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

    #[arg(long, value_enum, default_value_t = Api::Both, help = "Choose `Connection` or `States` API")]
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

    #[command(
        about = "Runs bulk data benchmarks in both directions at once, using split connections",
        long_about = "This splits a client and server connection into their send and receive halves.\n\
                      One thread sends client-to-server, while another sends server-to-client, so\n\
                      each connection is sending and receiving at the same time."
    )]
    BulkSplit {
        #[arg(help = "Which cipher suite to use; see `list-suites` for possible values.")]
        cipher_suite: String,

        #[arg(default_value_t = 1048576, help = "The size of each data write")]
        plaintext_size: u64,
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
    Connection,
    States,
}

impl Api {
    fn use_connection(&self) -> bool {
        matches!(*self, Self::Both | Self::Connection)
    }
    fn use_states(&self) -> bool {
        matches!(*self, Self::Both | Self::States)
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
    bench_handshake_connection(
        1,
        ResumptionParam::No,
        client_config.clone(),
        server_config.clone(),
        &params.without_latency_measurement(),
    );

    if params.api.use_connection() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_handshake_connection(
                    rounds,
                    params.resume,
                    client_config,
                    server_config,
                    params,
                )
            },
        );

        report_handshake_result("handshakes(Connection)", params, rounds, results);
    }

    if params.api.use_states() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_handshake_states(rounds, params.resume, client_config, server_config, params)
            },
        );

        report_handshake_result("handshakes(States)", params, rounds, results);
    }
}

fn bench_handshake_connection(
    mut rounds: u64,
    resume: ResumptionParam,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    params: &Parameters,
) -> Timings {
    let mut timings = Timings::default();
    let mut client_buffer = Vec::with_capacity(64 * 1024);
    let mut server_buffer = Vec::with_capacity(64 * 1024);
    let mut client_latency = params.open_latency_file("client");
    let mut server_latency = params.open_latency_file("server");

    while rounds > 0 {
        let mut client_time = 0f64;
        let mut server_time = 0f64;

        client_buffer.clear();
        server_buffer.clear();

        let mut client = time(&mut client_time, || {
            let server_name = "localhost".try_into().unwrap();
            client_config
                .connect(server_name)
                .build(&mut client_buffer)
                .unwrap()
        });
        let mut server = time(&mut server_time, || {
            Connection::new(server_config.clone()).unwrap()
        });

        time(&mut server_time, || {
            transfer(&mut client_buffer, &mut server_buffer, &mut server, None);
        });
        time(&mut client_time, || {
            transfer(&mut server_buffer, &mut client_buffer, &mut client, None);
        });
        time(&mut server_time, || {
            transfer(&mut client_buffer, &mut server_buffer, &mut server, None);
        });
        time(&mut client_time, || {
            transfer(&mut server_buffer, &mut client_buffer, &mut client, None);
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

fn bench_handshake_states(
    mut rounds: u64,
    resume: ResumptionParam,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    params: &Parameters,
) -> Timings {
    let mut timings = Timings::default();
    let mut client_buffer = Vec::with_capacity(64 * 1024);
    let mut server_buffer = Vec::with_capacity(64 * 1024);
    let mut client_latency = params.open_latency_file("client");
    let mut server_latency = params.open_latency_file("server");

    while rounds > 0 {
        let mut client_time = 0f64;
        let mut server_time = 0f64;

        client_buffer.clear();
        server_buffer.clear();

        let mut client = time(&mut client_time, || {
            let server_name = "localhost".try_into().unwrap();

            ClientHandshake::NeedsInput(
                client_config
                    .connect(server_name)
                    .start_handshake(&mut client_buffer)
                    .unwrap(),
            )
        });
        let mut server = time(&mut server_time, || {
            ServerHandshake::NeedsInput(ServerHandshake::start())
        });

        let (client, server) = loop {
            if !client_buffer.is_empty() {
                server = time(&mut server_time, || {
                    let mut client_input = SliceInput::new(client_buffer.as_mut_slice());

                    let ServerHandshake::NeedsInput(needs_input) = server else {
                        return server;
                    };

                    let next = match needs_input
                        .process(&mut client_input, &mut server_buffer)
                        .unwrap()
                    {
                        ServerHandshake::NeedsInput(needs_input) => {
                            ServerHandshake::NeedsInput(needs_input)
                        }
                        ServerHandshake::Accepted(accepted) => accepted
                            .choose_config(server_config.clone(), &mut server_buffer)
                            .unwrap(),
                        ServerHandshake::VerifyClientIdentity(verify_peer_identity) => {
                            verify_peer_identity
                                .with_config(&mut server_buffer)
                                .unwrap()
                        }
                        ServerHandshake::EarlyData(received_early_data) => {
                            ServerHandshake::NeedsInput(received_early_data.into_next().1)
                        }
                        ServerHandshake::Complete(connection) => {
                            ServerHandshake::Complete(connection)
                        }
                        _ => todo!(),
                    };
                    let used = client_input.into_used();
                    client_buffer.drain(..used);
                    next
                });
            }

            if !server_buffer.is_empty() {
                client = time(&mut client_time, || {
                    let mut server_input = SliceInput::new(server_buffer.as_mut_slice());

                    let ClientHandshake::NeedsInput(needs_input) = client else {
                        return client;
                    };

                    let next = match needs_input
                        .process(&mut server_input, &mut client_buffer)
                        .unwrap()
                    {
                        ClientHandshake::NeedsInput(needs_input) => {
                            ClientHandshake::NeedsInput(needs_input)
                        }
                        ClientHandshake::VerifyServerIdentity(verify_peer_identity) => {
                            verify_peer_identity
                                .with_config(&mut client_buffer)
                                .unwrap()
                        }
                        ClientHandshake::Complete(connection) => {
                            ClientHandshake::Complete(connection)
                        }
                        _ => todo!(),
                    };
                    let used = server_input.into_used();
                    server_buffer.drain(..used);
                    next
                });
            }

            if let (ClientHandshake::Complete(_), ServerHandshake::Complete(_)) = (&client, &server)
            {
                let ClientHandshake::Complete(client) = client else {
                    unreachable!()
                };
                let ServerHandshake::Complete(server) = server else {
                    unreachable!()
                };
                break (client, server);
            }
        };

        // feed in any remaining post-handshake data
        let (mut client, mut server) = (client, server);
        time(&mut client_time, || {
            transfer(&mut server_buffer, &mut client_buffer, &mut client, None);
        });
        time(&mut server_time, || {
            transfer(&mut client_buffer, &mut server_buffer, &mut server, None);
        });
        assert!(client_buffer.is_empty() && server_buffer.is_empty());

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

/// Run `f` on `count` threads, and then return the timings produced
/// by each thread.
///
/// `client_config` and `server_config` are cloned into each thread fn.
fn multithreaded<R: Send>(
    count: NonZeroUsize,
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
    f: impl Fn(Arc<ClientConfig>, Arc<ServerConfig>) -> R + Send + Sync,
) -> Vec<R> {
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
            .collect::<Vec<R>>()
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

fn report_timings<T>(
    units: &str,
    thread_timings: &[T],
    work_per_thread: f64,
    which: impl Fn(&T) -> f64,
) {
    // maintain old output for --threads=1
    if let [timing] = thread_timings {
        println!("{:.2}\t{}", work_per_thread / which(timing), units);
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
    let rounds = params.bulk_rounds();

    if params.api.use_connection() {
        let results = multithreaded(
            params.threads,
            &client_config,
            &server_config,
            move |client_config, server_config| {
                bench_bulk_one(client_config, server_config, params.plaintext_size, rounds)
            },
        );

        report_bulk_result("bulk", params, results, rounds);
    }
}

fn bench_bulk_one(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    plaintext_size: u64,
    rounds: u64,
) -> BulkTimings {
    let server_name = "localhost".try_into().unwrap();
    let mut client_buffer = Vec::with_capacity(1024 * 1024);
    let mut client = client_config
        .connect(server_name)
        .build(&mut client_buffer)
        .unwrap();
    let mut server = Connection::new(server_config).unwrap();
    let mut server_buffer = Vec::with_capacity(1024 * 1024);

    let mut timings = BulkTimings::default();
    do_handshake(
        &mut client_buffer,
        &mut client,
        &mut server_buffer,
        &mut server,
    );

    let buf = vec![0; plaintext_size as usize];
    for _ in 0..rounds {
        time(&mut timings.send, || {
            server
                .write((&buf).into(), &mut server_buffer)
                .unwrap();
        });

        timings.recv += transfer(
            &mut server_buffer,
            &mut client_buffer,
            &mut client,
            Some(buf.len()),
        );
    }

    timings
}

fn bench_bulk_split(params: &Parameters) {
    let client_config = params.client_config();
    let server_config = params.server_config();
    let rounds = params.bulk_rounds();

    let results = multithreaded(
        params.threads,
        &client_config,
        &server_config,
        move |client_config, server_config| {
            bench_bulk_split_one(client_config, server_config, params.plaintext_size, rounds)
        },
    );

    let (client_to_server, server_to_client): (Vec<_>, Vec<_>) = results.into_iter().unzip();
    report_bulk_result("bulk-split(c2s)", params, client_to_server, rounds);
    report_bulk_result("bulk-split(s2c)", params, server_to_client, rounds);
}

/// Returns the timings for the client-to-server and server-to-client directions.
fn bench_bulk_split_one(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    plaintext_size: u64,
    rounds: u64,
) -> (BulkTimings, BulkTimings) {
    let server_name = "localhost".try_into().unwrap();
    let mut client_buffer = Vec::with_capacity(64 * 1024);
    let mut client = client_config
        .connect(server_name)
        .build(&mut client_buffer)
        .unwrap();
    let mut server = Connection::new(server_config).unwrap();
    let mut server_buffer = Vec::with_capacity(64 * 1024);

    do_handshake(
        &mut client_buffer,
        &mut client,
        &mut server_buffer,
        &mut server,
    );
    assert!(client_buffer.is_empty() && server_buffer.is_empty());

    let client = client.split().unwrap();
    let server = server.split().unwrap();
    let start = Barrier::new(2);

    thread::scope(|s| {
        let client_to_server = s.spawn(|| {
            bulk_split_direction(client.send, server.receive, plaintext_size, rounds, &start)
        });
        let server_to_client = s.spawn(|| {
            bulk_split_direction(server.send, client.receive, plaintext_size, rounds, &start)
        });

        (
            client_to_server.join().unwrap(),
            server_to_client.join().unwrap(),
        )
    })
}

fn bulk_split_direction<Side: SideData>(
    mut send: SendTraffic,
    mut receive: ReceiveTraffic<Side>,
    plaintext_size: u64,
    rounds: u64,
    start: &Barrier,
) -> BulkTimings {
    let mut timings = BulkTimings::default();
    let buf = vec![0; plaintext_size as usize];
    let mut wire = Vec::with_capacity(buf.len() + buf.len() / 64 + 0xffff);

    start.wait();
    for _ in 0..rounds {
        time(&mut timings.send, || {
            send.write((&buf).into(), &mut wire)
                .unwrap();
        });

        receive = time(&mut timings.recv, || {
            receive_split(receive, &mut wire, buf.len())
        });
    }

    timings
}

fn receive_split<Side: SideData>(
    mut receive: ReceiveTraffic<Side>,
    wire: &mut Vec<u8>,
    expect_data: usize,
) -> ReceiveTraffic<Side> {
    let mut input = SliceInput::new(wire);
    let mut received = 0;

    loop {
        match receive.read(&mut input).unwrap() {
            ReceiveTrafficState::Available(mut data) => {
                received += data.data().len();
                receive = expect_read_more(data.into_next());
            }
            state => {
                receive = expect_read_more(state);
                break;
            }
        }
    }

    let used = input.into_used();
    assert_eq!(used, wire.len());
    assert_eq!(received, expect_data);
    wire.clear();
    receive
}

fn expect_read_more<Side: SideData>(state: ReceiveTrafficState<'_, Side>) -> ReceiveTraffic<Side> {
    match state {
        ReceiveTrafficState::ReadMore(receive) => receive,
        ReceiveTrafficState::FlushSender(flush) => expect_read_more(flush.into_next()),
        ReceiveTrafficState::Available(_) => panic!("unexpected application data"),
        ReceiveTrafficState::CloseNotify => panic!("unexpected close_notify"),
    }
}

fn report_bulk_result(variant: &str, params: &Parameters, timings: Vec<BulkTimings>, rounds: u64) {
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
    report_timings("MB/s", &timings, total_mbs, |t| t.send);

    print!(
        "{}\t{:?}\t{:?}\t{}\trecv\t",
        variant, params.proto.version, params.proto.ciphersuite, mfs_str,
    );
    report_timings("MB/s", &timings, total_mbs, |t| t.recv);
}

#[derive(Clone, Copy, Debug, Default)]
struct BulkTimings {
    send: f64,
    recv: f64,
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

    for _i in 0..conn_count {
        servers.push((Vec::new(), Connection::new(server_config.clone()).unwrap()));
        let server_name = "localhost".try_into().unwrap();
        let mut client_buffer = Vec::new();
        let client = client_config
            .connect(server_name)
            .build(&mut client_buffer)
            .unwrap();
        clients.push((client_buffer, client));
    }

    for _step in 0..5 {
        for (client, server) in clients
            .iter_mut()
            .zip(servers.iter_mut())
        {
            do_handshake_step(&mut client.0, &mut client.1, &mut server.0, &mut server.1);
        }
    }

    for client in clients.iter_mut() {
        client
            .1
            .write((&[0u8; 1024]).into(), &mut client.0)
            .unwrap();
    }

    for (client, server) in clients
        .iter_mut()
        .zip(servers.iter_mut())
    {
        transfer(&mut client.0, &mut server.0, &mut server.1, Some(1024));
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

                Arc::new(
                    WebPkiClientVerifier::builder(client_auth_roots.into(), &provider)
                        .build()
                        .unwrap(),
                )
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
                    cfg.provider()
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

    fn bulk_rounds(&self) -> u64 {
        // for small plaintext_sizes and their associated slowness, send
        // less total data
        let total_data = self.apply_work_multiplier(
            1024 * 1024
                * match self.plaintext_size {
                    ..=8192 => 64,
                    _ => 1024,
                },
        );
        total_data / self.plaintext_size
    }

    fn apply_work_multiplier(&self, work: u64) -> u64 {
        ((work as f64) * self.work_multiplier).round() as u64
    }

    fn open_latency_file(&self, role: &str) -> LatencyOutput {
        LatencyOutput::new(self.latency_prefix.as_deref(), role)
    }
}

struct LatencyOutput {
    output: Option<File>,
}

impl LatencyOutput {
    fn new(prefix: Option<&str>, role: &str) -> Self {
        let thread_id = thread::current().id();
        let output = prefix.map(|prefix| {
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
            Self::AwsLcRs => rustls_aws_lc_rs::DEFAULT_PROVIDER,
            #[cfg(all(feature = "aws-lc-rs", feature = "fips"))]
            Self::AwsLcRsFips => rustls_aws_lc_rs::DEFAULT_FIPS_PROVIDER,
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

fn do_handshake_step(
    client_buffer: &mut Vec<u8>,
    client: &mut Connection<ClientSide, Tcp>,
    server_buffer: &mut Vec<u8>,
    server: &mut Connection<ServerSide, Tcp>,
) -> bool {
    if server.is_handshaking() || client.is_handshaking() {
        transfer(client_buffer, server_buffer, server, None);
        transfer(server_buffer, client_buffer, client, None);
        true
    } else {
        false
    }
}

fn do_handshake(
    client_buffer: &mut Vec<u8>,
    client: &mut Connection<ClientSide, Tcp>,
    server_buffer: &mut Vec<u8>,
    server: &mut Connection<ServerSide, Tcp>,
) {
    while do_handshake_step(client_buffer, client, server_buffer, server) {}
}

fn time<F, T>(time_out: &mut f64, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let r = f();
    let end = Instant::now();
    *time_out += duration_nanos(end.duration_since(start));
    r
}

fn transfer(
    left_buffer: &mut Vec<u8>,
    right_buffer: &mut Vec<u8>,
    right: &mut Connection<impl SideData, Tcp>,
    expect_data: Option<usize>,
) -> f64 {
    if left_buffer.is_empty() {
        return 0.;
    }

    let start = Instant::now();
    let mut input = SliceInput::new(left_buffer);
    let mut received = 0;
    let mut handler = right.read_tls(&mut input, right_buffer);
    while let Some(result) = handler.next_payload() {
        received += result.unwrap().bytes().len();
    }
    drop(handler);
    let used = input.into_used();
    let read_time = duration_nanos(start.elapsed());

    assert_eq!(used, left_buffer.len());
    if let Some(expected) = expect_data {
        assert_eq!(received, expected);
    }
    left_buffer.clear();
    read_time
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
