use core::hint::black_box;
use core::mem;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use itertools::Itertools;
use rayon::iter::Either;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use rustls::client::Resumption;
use rustls::crypto::{CipherSuite, CryptoProvider, GetRandomFailed, SecureRandom, TicketProducer};
use rustls::enums::ProtocolVersion;
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, RootCertStore, ServerConfig,
    ServerConnection,
};
use rustls_test::KeyType;

use crate::benchmark::{
    AuthKeySource, Benchmark, BenchmarkKind, BenchmarkParams, ResumptionKind,
    get_reported_instr_count, validate_benchmarks,
};
use crate::util::async_io::{self, AsyncRead, AsyncWrite};
use crate::util::transport::{
    read_handshake_message, read_plaintext_to_end_bounded, send_handshake_message,
    write_all_plaintext_bounded,
};
use crate::valgrind::{CallgrindRunner, CountInstructions, DhatRunner, MemoryDetails};

mod benchmark;
mod util;
mod valgrind;

/// The size in bytes of the plaintext sent in the transfer benchmark
const TRANSFER_PLAINTEXT_SIZE: usize = 1024 * 1024 * 10; // 10 MB

/// The amount of times a resumed handshake should be executed during benchmarking.
///
/// Handshakes with session resumption execute a very small amount of instructions (less than 200_000
/// for some parameters), so a small difference in instructions accounts for a high difference in
/// percentage (making the benchmark more sensitive to noise, because differences as low as 500
/// instructions already raise a flag). Running the handshake multiple times gives additional weight
/// to the instructions involved in the handshake, and less weight to noisy one-time setup code.
///
/// More specifically, great part of the noise in resumed handshakes comes from the usage of
/// [`rustls::client::ClientSessionMemoryCache`] and [`rustls::server::ServerSessionMemoryCache`],
/// which rely on a randomized `HashMap` under the hood (you can check for yourself by that
/// `HashMap` by a `FxHashMap`, which brings the noise down to acceptable levels in a single run).
const RESUMED_HANDSHAKE_RUNS: usize = 30;

/// The name of the file where the instruction counts are stored after a `run-all` run
const ICOUNTS_FILENAME: &str = "icounts.csv";

/// The name of the file where the memory data are stored after a `run-all` run
const MEMORY_FILENAME: &str = "memory.csv";

/// Default size in bytes for internal buffers (256 KB)
const DEFAULT_BUFFER_SIZE: usize = 262144;

#[derive(Parser)]
#[command(about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run all benchmarks and print the measured CPU instruction counts in CSV format
    RunAll {
        #[arg(short, long, default_value = "target/ci-bench")]
        output_dir: PathBuf,
    },
    /// Run a single benchmark at the provided index (used by the bench runner to start each benchmark in its own process)
    RunPipe {
        index: u32,
        side: Side,
        measurement_mode: Mode,
    },
    /// Run all benchmarks in walltime mode and print the measured timings in CSV format
    Walltime {
        #[arg(short, long)]
        iterations_per_scenario: usize,
    },
    /// Compare the icount results from two previous benchmark runs and print a user-friendly markdown overview
    Compare {
        /// Path to the directory with the results of a previous `run-all` execution
        baseline_dir: PathBuf,
        /// Path to the directory with the results of a previous `run-all` execution
        candidate_dir: PathBuf,
    },
    /// Compare the memory results from two previous benchmark runs and print a user-friendly markdown overview
    CompareMemory {
        comparator: CompareMemoryOperand,
        /// Path to the directory with the results of a previous `run-all` execution
        baseline_dir: PathBuf,
        /// Path to the directory with the results of a previous `run-all` execution
        candidate_dir: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub enum CompareMemoryOperand {
    #[default]
    TotalBytes,
    TotalBlocks,
    PeakBytes,
    PeakBlocks,
}

impl CompareMemoryOperand {
    fn choose(&self, memory: MemoryDetails) -> u64 {
        match self {
            Self::TotalBytes => memory.heap_total_bytes,
            Self::TotalBlocks => memory.heap_total_blocks,
            Self::PeakBytes => memory.heap_peak_bytes,
            Self::PeakBlocks => memory.heap_peak_blocks,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
pub enum Side {
    Server,
    Client,
}

#[derive(Copy, Clone, ValueEnum)]
pub enum Mode {
    Instruction,
    Memory,
}

impl Side {
    /// Returns the string representation of the side
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

fn main() -> anyhow::Result<()> {
    let benchmarks = all_benchmarks()?;

    let cli = Cli::parse();
    match cli.command {
        Command::RunAll { output_dir } => {
            let executable = std::env::args().next().unwrap();
            let results = run_all(executable, output_dir.clone(), &benchmarks)?;

            // Output results in CSV (note: not using a library here to avoid extra dependencies)
            let mut csv_file = File::create(output_dir.join(ICOUNTS_FILENAME))
                .context("cannot create output csv file")?;
            for (name, combined) in &results {
                writeln!(csv_file, "{name},{}", combined.instructions)?;
            }

            let mut csv_file = File::create(output_dir.join(MEMORY_FILENAME))
                .context("cannot create output csv file")?;
            for (name, combined) in results {
                writeln!(
                    csv_file,
                    "{name},{},{},{},{}",
                    combined.memory.heap_total_bytes,
                    combined.memory.heap_total_blocks,
                    combined.memory.heap_peak_bytes,
                    combined.memory.heap_peak_blocks,
                )?;
            }
        }
        Command::RunPipe {
            index,
            side,
            measurement_mode,
        } => {
            let bench = benchmarks
                .get(index as usize)
                .ok_or_else(|| anyhow::anyhow!("Benchmark not found: {index}"))?;

            if let Some(warm_up) = bench.params.warm_up {
                warm_up();
            }

            let stdin_lock = io::stdin().lock();
            let stdout_lock = io::stdout().lock();

            // `StdinLock` and `StdoutLock` are buffered, which makes the instruction counts less
            // deterministic (the growth of the internal buffers varies across runs, causing
            // differences of hundreds of instructions). To counter this, we do the actual io
            // operations through `File`, which is unbuffered. The `stdin_lock` and `stdout_lock`
            // variables are kept around to ensure exclusive access.

            // safety: the file descriptor is valid and we have exclusive access to it for the
            // duration of the lock
            let mut stdin = unsafe { File::from_raw_fd(stdin_lock.as_raw_fd()) };
            let mut stdout = unsafe { File::from_raw_fd(stdout_lock.as_raw_fd()) };

            // When measuring instructions, we do multiple resumed handshakes, for
            // reasons explained in the comments to `RESUMED_HANDSHAKE_RUNS`.
            let resumed_reps = match measurement_mode {
                Mode::Instruction => RESUMED_HANDSHAKE_RUNS,
                _ => 1,
            };

            let handshake_buf = &mut [0u8; DEFAULT_BUFFER_SIZE];
            let resumption_kind = bench.kind.resumption_kind();
            let io = StepperIo {
                reader: &mut stdin,
                writer: &mut stdout,
                handshake_buf,
            };
            async_io::block_on_single_poll(async {
                match side {
                    Side::Server => {
                        run_bench(
                            ServerSideStepper {
                                io,
                                config: ServerSideStepper::make_config(
                                    &bench.params,
                                    resumption_kind,
                                ),
                            },
                            bench.kind,
                            resumed_reps,
                        )
                        .await
                    }
                    Side::Client => {
                        run_bench(
                            ClientSideStepper {
                                io,
                                resumption_kind,
                                config: ClientSideStepper::make_config(
                                    &bench.params,
                                    resumption_kind,
                                ),
                            },
                            bench.kind,
                            resumed_reps,
                        )
                        .await
                    }
                }
            })
            .with_context(|| format!("{} crashed for {} side", bench.name(), side.as_str()))?;

            // Prevent stdin / stdout from being closed
            mem::forget(stdin);
            mem::forget(stdout);
        }
        Command::Walltime {
            iterations_per_scenario,
        } => {
            let mut timings = vec![Vec::with_capacity(iterations_per_scenario); benchmarks.len()];
            for _ in 0..iterations_per_scenario {
                for (i, bench) in benchmarks.iter().enumerate() {
                    let start = Instant::now();

                    // The variables below are used to initialize the client and server configs. We
                    // let them go through `black_box` to ensure the optimizer doesn't take
                    // advantage of knowing both the client and the server side of the
                    // configuration.
                    let resumption_kind = black_box(bench.kind.resumption_kind());
                    let params = black_box(&bench.params);

                    let (mut client_writer, mut server_reader) =
                        async_io::async_pipe(DEFAULT_BUFFER_SIZE);
                    let (mut server_writer, mut client_reader) =
                        async_io::async_pipe(DEFAULT_BUFFER_SIZE);

                    let server_side = async move {
                        let handshake_buf = &mut [0u8; DEFAULT_BUFFER_SIZE];
                        run_bench(
                            ServerSideStepper {
                                io: StepperIo {
                                    reader: &mut server_reader,
                                    writer: &mut server_writer,
                                    handshake_buf,
                                },
                                config: ServerSideStepper::make_config(params, resumption_kind),
                            },
                            bench.kind,
                            RESUMED_HANDSHAKE_RUNS,
                        )
                        .await
                    };

                    let client_side = async move {
                        let handshake_buf = &mut [0u8; DEFAULT_BUFFER_SIZE];
                        run_bench(
                            ClientSideStepper {
                                io: StepperIo {
                                    reader: &mut client_reader,
                                    writer: &mut client_writer,
                                    handshake_buf,
                                },
                                resumption_kind,
                                config: ClientSideStepper::make_config(params, resumption_kind),
                            },
                            bench.kind,
                            RESUMED_HANDSHAKE_RUNS,
                        )
                        .await
                    };

                    let (client_result, server_result) =
                        async_io::block_on_concurrent(client_side, server_side);
                    client_result
                        .with_context(|| format!("client side of {} crashed", bench.name()))?;
                    server_result
                        .with_context(|| format!("server side of {} crashed", bench.name()))?;

                    timings[i].push(start.elapsed());
                }
            }

            // Output the results
            for (i, bench_timings) in timings.into_iter().enumerate() {
                print!("{}", benchmarks[i].name());
                for timing in bench_timings {
                    print!(",{}", timing.as_nanos())
                }
                println!();
            }
        }
        Command::Compare {
            baseline_dir,
            candidate_dir,
        } => {
            let baseline = read_icount_results(&baseline_dir.join(ICOUNTS_FILENAME))?;
            let candidate = read_icount_results(&candidate_dir.join(ICOUNTS_FILENAME))?;
            let result =
                compare_icount_results(&baseline_dir, &candidate_dir, &baseline, &candidate)?;
            print_icount_report(&result);
        }
        Command::CompareMemory {
            comparator,
            baseline_dir,
            candidate_dir,
        } => {
            let baseline = read_memory_results(&baseline_dir.join(MEMORY_FILENAME))?;
            let candidate = read_memory_results(&candidate_dir.join(MEMORY_FILENAME))?;

            print_memory_report(&compare_memory_results(&baseline, &candidate, comparator)?);
        }
    }

    Ok(())
}

/// Returns all benchmarks
fn all_benchmarks() -> anyhow::Result<Vec<Benchmark>> {
    let mut benchmarks = Vec::new();
    for param in all_benchmarks_params() {
        add_benchmark_group(&mut benchmarks, param);
    }

    validate_benchmarks(&benchmarks)?;
    Ok(benchmarks)
}

/// The benchmark params to use for each group of benchmarks
fn all_benchmarks_params() -> Vec<BenchmarkParams> {
    let mut all = Vec::new();

    for (provider, ticketer, provider_name, warm_up) in [
        (
            derandomize(rustls_ring::DEFAULT_PROVIDER),
            &(ring_ticketer as fn() -> Arc<dyn TicketProducer>),
            "ring",
            None,
        ),
        (
            derandomize(rustls_aws_lc_rs::DEFAULT_PROVIDER),
            &(aws_lc_rs_ticketer as fn() -> Arc<dyn TicketProducer>),
            "aws_lc_rs",
            Some(warm_up_aws_lc_rs as fn()),
        ),
    ] {
        for (key_type, suite_name, name) in [
            (
                KeyType::Rsa2048,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                "1.2_rsa_aes",
            ),
            (
                KeyType::Rsa2048,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                "1.3_rsa_aes",
            ),
            (
                KeyType::EcdsaP256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                "1.3_ecdsap256_aes",
            ),
            (
                KeyType::EcdsaP384,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                "1.3_ecdsap384_aes",
            ),
            (
                KeyType::Rsa2048,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                "1.3_rsa_chacha",
            ),
            (
                KeyType::EcdsaP256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                "1.3_ecdsap256_chacha",
            ),
            (
                KeyType::EcdsaP384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                "1.3_ecdsap384_chacha",
            ),
        ] {
            all.push(BenchmarkParams::new(
                select_suite(provider.clone(), suite_name),
                ticketer,
                AuthKeySource::KeyType(key_type),
                format!("{provider_name}_{name}"),
                warm_up,
            ));
        }
    }

    let make_ticketer =
        &((|| Arc::new(rustls_fuzzing_provider::Ticketer)) as fn() -> Arc<dyn TicketProducer>);

    all.push(BenchmarkParams::new(
        rustls_fuzzing_provider::PROVIDER_TLS13.into(),
        make_ticketer,
        AuthKeySource::FuzzingProvider,
        "1.3_no_crypto".to_string(),
        None,
    ));

    all.push(BenchmarkParams::new(
        rustls_fuzzing_provider::PROVIDER_TLS12.into(),
        make_ticketer,
        AuthKeySource::FuzzingProvider,
        "1.2_no_crypto".to_string(),
        None,
    ));

    all
}

fn ring_ticketer() -> Arc<dyn TicketProducer> {
    rustls_ring::DEFAULT_PROVIDER
        .ticketer_factory
        .ticketer()
        .unwrap()
}

fn aws_lc_rs_ticketer() -> Arc<dyn TicketProducer> {
    rustls_aws_lc_rs::DEFAULT_PROVIDER
        .ticketer_factory
        .ticketer()
        .unwrap()
}

fn select_suite(mut provider: CryptoProvider, name: CipherSuite) -> Arc<CryptoProvider> {
    provider
        .tls12_cipher_suites
        .to_mut()
        .retain(|suite| suite.common.suite == name);
    provider
        .tls13_cipher_suites
        .to_mut()
        .retain(|suite| suite.common.suite == name);
    provider.into()
}

fn derandomize(base: CryptoProvider) -> CryptoProvider {
    CryptoProvider {
        secure_random: &NotRandom,
        ..base
    }
}

fn warm_up_aws_lc_rs() {
    // "Warm up" provider's actual entropy source.  aws-lc-rs particularly
    // has an expensive process here, which is one-time (per calling thread)
    // so not useful to include in benchmark measurements.
    rustls_aws_lc_rs::DEFAULT_PROVIDER
        .secure_random
        .fill(&mut [0u8])
        .unwrap();
}

#[derive(Debug)]
struct NotRandom;

impl SecureRandom for NotRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        buf.fill(0x5a);
        Ok(())
    }
}

/// Adds a group of benchmarks for the specified parameters
///
/// The benchmarks in the group are:
///
/// - Handshake without resumption
/// - Handshake with session id resumption
/// - Handshake with ticket resumption
/// - Transfer a 1MB data stream from the server to the client
fn add_benchmark_group(benchmarks: &mut Vec<Benchmark>, params: BenchmarkParams) {
    let params_label = params.label.clone();

    // Create handshake benchmarks for all resumption kinds
    for &resumption_param in ResumptionKind::ALL {
        let handshake_bench = Benchmark::new(
            format!("handshake_{}_{params_label}", resumption_param.label()),
            BenchmarkKind::Handshake(resumption_param),
            params.clone(),
        );

        benchmarks.push(handshake_bench);
    }

    // Benchmark data transfer
    benchmarks.push(Benchmark::new(
        format!("transfer_no_resume_{params_label}"),
        BenchmarkKind::Transfer,
        params,
    ));
}

/// Run all the provided benches under callgrind to retrieve their instruction count
fn run_all(
    executable: String,
    output_dir: PathBuf,
    benches: &[Benchmark],
) -> anyhow::Result<Vec<(String, CombinedMeasurement)>> {
    for bench in benches {
        if let Some(warm_up) = bench.params.warm_up {
            warm_up();
        }
    }

    // Run the benchmarks in parallel
    let cg_runner = CallgrindRunner::new(executable.clone(), output_dir.clone())?;
    let cg_results: Vec<_> = benches
        .par_iter()
        .enumerate()
        .map(|(i, bench)| (bench, cg_runner.run_bench(i as u32, bench)))
        .collect();

    let dh_runner = DhatRunner::new(executable, output_dir)?;
    let dh_results: Vec<_> = benches
        .par_iter()
        .enumerate()
        .map(|(i, bench)| (bench, dh_runner.run_bench(i as u32, bench)))
        .collect();

    // Report possible errors
    let (errors, cg_results): (Vec<_>, FxHashMap<_, _>) =
        cg_results
            .into_iter()
            .partition_map(|(bench, result)| match result {
                Err(_) => Either::Left(()),
                Ok(instr_counts) => Either::Right((bench.name(), instr_counts)),
            });
    if !errors.is_empty() {
        // Note: there is no need to explicitly report the names of each crashed benchmark, because
        // names and other details are automatically printed to stderr by the child process upon
        // crashing
        anyhow::bail!("One or more benchmarks crashed");
    }
    let (errors, dh_results): (Vec<_>, FxHashMap<_, _>) =
        dh_results
            .into_iter()
            .partition_map(|(bench, result)| match result {
                Err(_) => Either::Left(()),
                Ok(heap_profile) => Either::Right((bench.name(), heap_profile)),
            });
    if !errors.is_empty() {
        // Note: there is no need to explicitly report the names of each crashed benchmark, because
        // names and other details are automatically printed to stderr by the child process upon
        // crashing
        anyhow::bail!("One or more benchmarks crashed");
    }

    // Gather results keeping the original order of the benchmarks
    let mut measurements = Vec::new();
    for bench in benches {
        let instr_counts = get_reported_instr_count(bench, &cg_results);
        let memory = &dh_results[bench.name()];
        measurements.push((
            bench.name_with_side(Side::Server),
            CombinedMeasurement {
                instructions: instr_counts.server,
                memory: memory.server,
            },
        ));
        measurements.push((
            bench.name_with_side(Side::Client),
            CombinedMeasurement {
                instructions: instr_counts.client,
                memory: memory.client,
            },
        ));
    }

    Ok(measurements)
}

pub struct CombinedMeasurement {
    instructions: u64,
    memory: MemoryDetails,
}

/// Drives the different steps in a benchmark.
///
/// See [`run_bench`] for specific details on how it is used.
#[async_trait(?Send)]
trait BenchStepper {
    type Endpoint;

    async fn handshake(&mut self) -> anyhow::Result<Self::Endpoint>;
    async fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()>;
    async fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()>;
    fn handshake_kind(&self, endpoint: &Self::Endpoint) -> HandshakeKind;
}

/// Stepper fields necessary for IO
struct StepperIo<'a> {
    reader: &'a mut dyn AsyncRead,
    writer: &'a mut dyn AsyncWrite,
    handshake_buf: &'a mut [u8],
}

/// A benchmark stepper for the client-side of the connection
struct ClientSideStepper<'a> {
    io: StepperIo<'a>,
    resumption_kind: ResumptionKind,
    config: Arc<ClientConfig>,
}

impl ClientSideStepper<'_> {
    fn make_config(params: &BenchmarkParams, resume: ResumptionKind) -> Arc<ClientConfig> {
        let cfg = ClientConfig::builder(params.provider.clone());

        let mut cfg = match params.auth_key {
            AuthKeySource::KeyType(key_type) => {
                let mut root_store = RootCertStore::empty();
                root_store
                    .add(key_type.ca_cert())
                    .unwrap();

                cfg.with_root_certificates(root_store)
                    .with_no_client_auth()
                    .unwrap()
            }

            AuthKeySource::FuzzingProvider => cfg
                .dangerous()
                .with_custom_certificate_verifier(rustls_fuzzing_provider::server_verifier())
                .with_no_client_auth()
                .unwrap(),
        };

        if resume != ResumptionKind::No {
            cfg.resumption = Resumption::in_memory_sessions(128);
        } else {
            cfg.resumption = Resumption::disabled();
        }

        Arc::new(cfg)
    }
}

#[async_trait(?Send)]
impl BenchStepper for ClientSideStepper<'_> {
    type Endpoint = ClientConnection;

    async fn handshake(&mut self) -> anyhow::Result<Self::Endpoint> {
        let server_name = "localhost".try_into().unwrap();
        let mut client = self
            .config
            .connect(server_name)
            .build()
            .unwrap();
        client.set_buffer_limit(None);

        loop {
            send_handshake_message(&mut client, self.io.writer, self.io.handshake_buf).await?;
            if !client.is_handshaking() && !client.wants_write() {
                break;
            }
            read_handshake_message(&mut client, self.io.reader, self.io.handshake_buf).await?;
        }

        // Session ids and tickets are no longer part of the handshake in TLS 1.3, so we need to
        // explicitly receive them from the server
        if self.resumption_kind != ResumptionKind::No
            && client.protocol_version().unwrap() == ProtocolVersion::TLSv1_3
        {
            read_handshake_message(&mut client, self.io.reader, self.io.handshake_buf).await?;
        }

        Ok(client)
    }

    async fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()> {
        // The client syncs by receiving a single byte (we assert that it matches the `42` byte sent
        // by the server, just to be sure)
        let buf = &mut [0];
        self.io.reader.read_exact(buf).await?;
        assert_eq!(buf[0], 42);
        Ok(())
    }

    async fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()> {
        let total_plaintext_read = read_plaintext_to_end_bounded(endpoint, self.io.reader).await?;
        assert_eq!(total_plaintext_read, TRANSFER_PLAINTEXT_SIZE);
        Ok(())
    }

    fn handshake_kind(&self, endpoint: &Self::Endpoint) -> HandshakeKind {
        endpoint.handshake_kind().unwrap()
    }
}

/// A benchmark stepper for the server-side of the connection
struct ServerSideStepper<'a> {
    io: StepperIo<'a>,
    config: Arc<ServerConfig>,
}

impl ServerSideStepper<'_> {
    fn make_config(params: &BenchmarkParams, resume: ResumptionKind) -> Arc<ServerConfig> {
        let cfg = ServerConfig::builder(params.provider.clone());

        let mut cfg = match params.auth_key {
            AuthKeySource::KeyType(key_type) => cfg
                .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
                .with_single_cert(key_type.identity(), key_type.key())
                .expect("bad certs/private key?"),

            AuthKeySource::FuzzingProvider => cfg
                .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
                .with_server_credential_resolver(rustls_fuzzing_provider::server_cert_resolver())
                .unwrap(),
        };

        if resume == ResumptionKind::SessionId {
            cfg.session_storage = ServerSessionMemoryCache::new(128);
        } else if resume == ResumptionKind::Tickets {
            cfg.ticketer = Some((params.ticketer)());
        } else {
            cfg.session_storage = Arc::new(NoServerSessionStorage {});
        }

        Arc::new(cfg)
    }
}

#[async_trait(?Send)]
impl BenchStepper for ServerSideStepper<'_> {
    type Endpoint = ServerConnection;

    async fn handshake(&mut self) -> anyhow::Result<Self::Endpoint> {
        let mut server = ServerConnection::new(self.config.clone()).unwrap();
        server.set_buffer_limit(None);

        while server.is_handshaking() {
            read_handshake_message(&mut server, self.io.reader, self.io.handshake_buf).await?;
            send_handshake_message(&mut server, self.io.writer, self.io.handshake_buf).await?;
        }

        Ok(server)
    }

    async fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()> {
        // The server syncs by sending a single byte
        self.io.writer.write_all(&[42]).await?;
        self.io.writer.flush().await?;
        Ok(())
    }

    async fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()> {
        write_all_plaintext_bounded(endpoint, self.io.writer, TRANSFER_PLAINTEXT_SIZE).await?;
        Ok(())
    }

    fn handshake_kind(&self, endpoint: &Self::Endpoint) -> HandshakeKind {
        endpoint.handshake_kind().unwrap()
    }
}

/// Runs the benchmark using the provided stepper
async fn run_bench<T: BenchStepper>(
    mut stepper: T,
    kind: BenchmarkKind,
    resumed_reps: usize,
) -> anyhow::Result<()> {
    match kind {
        BenchmarkKind::Handshake(ResumptionKind::No) => {
            // Just count instructions for one handshake.
            let _count = CountInstructions::start();
            black_box(stepper.handshake().await?);
        }
        BenchmarkKind::Handshake(_) => {
            // The first handshake performed is non-resumed, because the client didn't have a
            // session ID / ticket.  This is not measured.
            stepper.handshake().await?;

            let _count = CountInstructions::start();
            for _ in 0..resumed_reps {
                // Wait for the endpoints to sync (i.e. the server must have discarded the previous
                // connection and be ready for a new handshake, otherwise the client will start a
                // handshake before the server is ready and the bytes will be fed to the old
                // connection!)
                stepper
                    .sync_before_resumed_handshake()
                    .await?;
                let endpoint = stepper.handshake().await?;
                assert_eq!(stepper.handshake_kind(&endpoint), HandshakeKind::Resumed);
            }
        }
        BenchmarkKind::Transfer => {
            // Measurement includes the transfer, but not the handshake.
            let mut endpoint = stepper.handshake().await?;
            let _count = CountInstructions::start();
            stepper
                .transmit_data(&mut endpoint)
                .await?;
        }
    }

    Ok(())
}

/// The results of a comparison between two `run-all` executions
struct CompareResult {
    /// Results for benchmark scenarios we know are fairly deterministic.
    ///
    /// The string is a detailed diff between the instruction counts obtained from callgrind.
    diffs: Vec<(Diff, String)>,
    /// Benchmark scenarios present in the candidate but missing in the baseline
    missing_in_baseline: Vec<String>,
}

/// The results of a comparison between two `run-all` executions
struct MemoryCompareResult {
    diffs: Vec<MemoryDiff>,
    /// Benchmark scenarios present in the candidate but missing in the baseline
    missing_in_baseline: Vec<String>,
}

/// Contains information about instruction counts and their difference for a specific scenario
#[derive(Clone)]
struct Diff {
    scenario: String,
    baseline: u64,
    candidate: u64,
    diff: i64,
    diff_ratio: f64,
}

/// Contains information about memory usage and a difference for a specific scenario & comparator
#[derive(Clone)]
struct MemoryDiff {
    scenario: String,
    baseline: MemoryDetails,
    candidate: MemoryDetails,
    comparator: CompareMemoryOperand,
    diff: i64,
    diff_ratio: f64,
}

/// Reads the (benchmark, instruction count) pairs from previous CSV output
fn read_icount_results(path: &Path) -> anyhow::Result<HashMap<String, u64>> {
    let file = File::open(path).context(format!(
        "CSV file for comparison not found: {}",
        path.display()
    ))?;

    let mut measurements = HashMap::new();
    for line in BufReader::new(file).lines() {
        let line = line.context("Unable to read results from CSV file")?;
        let line = line.trim();
        let mut parts = line.split(',');
        measurements.insert(
            parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                .to_string(),
            parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                .parse()
                .context("Unable to parse instruction count from CSV")?,
        );
    }

    Ok(measurements)
}

/// Reads the (benchmark, instruction count) pairs from previous CSV output
fn read_memory_results(path: &Path) -> anyhow::Result<HashMap<String, MemoryDetails>> {
    let file = File::open(path).context(format!(
        "CSV file for comparison not found: {}",
        path.display()
    ))?;

    let mut measurements = HashMap::new();
    for line in BufReader::new(file).lines() {
        let line = line.context("Unable to read results from CSV file")?;
        let line = line.trim();
        let mut parts = line.split(',');
        measurements.insert(
            parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                .to_string(),
            MemoryDetails {
                heap_total_bytes: parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                    .parse()
                    .context("Unable to parse heap total bytes from CSV")?,
                heap_total_blocks: parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                    .parse()
                    .context("Unable to parse heap total blocks from CSV")?,
                heap_peak_bytes: parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                    .parse()
                    .context("Unable to parse heap peak bytes from CSV")?,
                heap_peak_blocks: parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("CSV is wrongly formatted"))?
                    .parse()
                    .context("Unable to parse heap peak blocks from CSV")?,
            },
        );
    }

    Ok(measurements)
}

/// Returns an internal representation of the comparison between the baseline and the candidate
/// measurements
fn compare_icount_results(
    baseline_dir: &Path,
    candidate_dir: &Path,
    baseline: &HashMap<String, u64>,
    candidate: &HashMap<String, u64>,
) -> anyhow::Result<CompareResult> {
    let mut diffs = Vec::new();
    let mut missing = Vec::new();

    for (scenario, &instr_count) in candidate {
        let Some(&baseline_instr_count) = baseline.get(scenario) else {
            missing.push(scenario.clone());
            continue;
        };

        let diff = instr_count as i64 - baseline_instr_count as i64;
        let diff_ratio = diff as f64 / baseline_instr_count as f64;
        let diff = Diff {
            scenario: scenario.clone(),
            baseline: baseline_instr_count,
            candidate: instr_count,
            diff,
            diff_ratio,
        };

        diffs.push(diff);
    }

    diffs.sort_by(|diff1, diff2| {
        diff2
            .diff_ratio
            .abs()
            .total_cmp(&diff1.diff_ratio.abs())
    });

    let mut diffs_with_callgrind_diff = Vec::new();
    for diff in diffs {
        let detailed_diff = valgrind::callgrind_diff(baseline_dir, candidate_dir, &diff.scenario)?;
        diffs_with_callgrind_diff.push((diff, detailed_diff));
    }

    Ok(CompareResult {
        diffs: diffs_with_callgrind_diff,
        missing_in_baseline: missing,
    })
}

/// Returns an internal representation of the comparison between the baseline and the candidate
/// measurements
fn compare_memory_results(
    baseline: &HashMap<String, MemoryDetails>,
    candidate: &HashMap<String, MemoryDetails>,
    comparator: CompareMemoryOperand,
) -> anyhow::Result<MemoryCompareResult> {
    let mut diffs = Vec::new();
    let mut missing = Vec::new();

    for (scenario, &candidate_memory) in candidate {
        let Some(&baseline_memory) = baseline.get(scenario) else {
            missing.push(scenario.clone());
            continue;
        };

        let candidate_count = comparator.choose(candidate_memory);
        let baseline_count = comparator.choose(baseline_memory);

        let diff = candidate_count as i64 - baseline_count as i64;
        let diff_ratio = diff as f64 / baseline_count as f64;
        let diff = MemoryDiff {
            scenario: scenario.clone(),
            baseline: baseline_memory,
            candidate: candidate_memory,
            comparator,
            diff,
            diff_ratio,
        };

        diffs.push(diff);
    }

    diffs.sort_by(|diff1, diff2| {
        diff2
            .diff_ratio
            .abs()
            .total_cmp(&diff1.diff_ratio.abs())
    });

    Ok(MemoryCompareResult {
        diffs,
        missing_in_baseline: missing,
    })
}

/// Prints a report of the comparison to stdout, using GitHub-flavored markdown
fn print_icount_report(result: &CompareResult) {
    println!("# Benchmark results");

    if !result.missing_in_baseline.is_empty() {
        println!("### ⚠️ Warning: missing benchmarks");
        println!();
        println!(
            "The following benchmark scenarios are present in the candidate but not in the baseline:"
        );
        println!();
        for scenario in &result.missing_in_baseline {
            println!("* {scenario}");
        }
    }

    println!("## Instruction count differences");
    if result.diffs.is_empty() {
        println!("_There are no instruction count differences_");
    } else {
        table(
            result
                .diffs
                .iter()
                .map(|(diff, _)| diff),
            true,
        );
        println!("<details>");
        println!("<summary>Details per scenario</summary>\n");
        for (diff, detailed_diff) in &result.diffs {
            println!("#### {}", diff.scenario);
            println!("```");
            println!("{detailed_diff}");
            println!("```");
        }
        println!("</details>\n")
    }
}

fn print_memory_report(result: &MemoryCompareResult) {
    println!("# Memory measurement results");

    if !result.missing_in_baseline.is_empty() {
        println!("### ⚠️ Warning: missing benchmarks");
        println!();
        println!(
            "The following benchmark scenarios are present in the candidate but not in the baseline:"
        );
        println!();
        for scenario in &result.missing_in_baseline {
            println!("* {scenario}");
        }
    }

    println!("## Memory measurement differences");
    if result.diffs.is_empty() {
        println!("_There are no memory measurement differences_");
    } else {
        memory_table(&result.diffs, true);
    }
}

/// Renders the diffs as a markdown table
fn table<'a>(diffs: impl Iterator<Item = &'a Diff>, emoji_feedback: bool) {
    println!("| Scenario | Baseline | Candidate | Diff |");
    println!("| --- | ---: | ---: | ---: |");
    for diff in diffs {
        let emoji = match emoji_feedback {
            true if diff.diff > 0 => "⚠️ ",
            true if diff.diff < 0 => "✅ ",
            _ => "",
        };

        println!(
            "| {} | {} | {} | {}{} ({:.2}%) |",
            diff.scenario,
            diff.baseline,
            diff.candidate,
            emoji,
            diff.diff,
            diff.diff_ratio * 100.0
        )
    }
}

/// Renders the diffs as a markdown table
fn memory_table(diffs: &[MemoryDiff], emoji_feedback: bool) {
    println!("| Scenario | Baseline | Candidate | Diff |");
    println!("| --- | ---: | ---: | ---: |");
    for diff in diffs {
        let emoji = match emoji_feedback {
            true if diff.diff_ratio > 0.01 => "⚠️ ",
            true if diff.diff_ratio < -0.01 => "✅ ",
            _ => "",
        };

        println!(
            "| {} | Total {}B / {}# <br/> Peak {}B / {}# | Total {}B / {}# <br/> Peak {}B / {}# | {:?} {}{} ({:.2}%) |",
            diff.scenario,
            diff.baseline.heap_total_bytes,
            diff.baseline.heap_total_blocks,
            diff.baseline.heap_peak_bytes,
            diff.baseline.heap_peak_blocks,
            diff.candidate.heap_total_bytes,
            diff.candidate.heap_total_blocks,
            diff.candidate.heap_peak_bytes,
            diff.candidate.heap_peak_blocks,
            diff.comparator,
            emoji,
            diff.diff,
            diff.diff_ratio * 100.0
        )
    }
}
