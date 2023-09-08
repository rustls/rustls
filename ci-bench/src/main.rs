use std::collections::HashMap;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use fxhash::FxHashMap;
use itertools::Itertools;
use rayon::iter::Either;
use rayon::prelude::*;
use rustls::client::Resumption;
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    Ticketer,
};

use crate::benchmark::{
    get_reported_instr_count, validate_benchmarks, Benchmark, BenchmarkKind, BenchmarkParams,
    ResumptionKind,
};
use crate::cachegrind::CachegrindRunner;
use crate::util::transport::{
    read_handshake_message, read_plaintext_to_end_bounded, send_handshake_message,
    write_all_plaintext_bounded,
};
use crate::util::KeyType;

mod benchmark;
mod cachegrind;
mod util;

/// The size in bytes of the plaintext sent in the transfer benchmark
const TRANSFER_PLAINTEXT_SIZE: usize = 1024 * 1024;

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

/// The threshold at which instruction count changes are considered relevant
const CHANGE_THRESHOLD: f64 = 0.002; // 0.2%

/// The name of the file where the instruction counts are stored after a `run-all` run
const ICOUNTS_FILENAME: &str = "icounts.csv";

#[derive(Parser)]
#[command(about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run all benchmarks and prints the measured CPU instruction counts in CSV format
    RunAll {
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
    /// Run a single benchmark at the provided index (used by the bench runner to start each benchmark in its own process)
    RunSingle { index: u32, side: Side },
    /// Compare the results from two previous benchmark runs and print a user-friendly markdown overview
    Compare {
        /// Path to the directory with the results of a previous `run-all` execution
        baseline_dir: PathBuf,
        /// Path to the directory with the results of a previous `run-all` execution
        candidate_dir: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
pub enum Side {
    Server,
    Client,
}

impl Side {
    /// Returns the string representation of the side
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
        }
    }
}

fn main() -> anyhow::Result<()> {
    let benchmarks = all_benchmarks()?;

    let cli = Cli::parse();
    match cli.command {
        Command::RunAll { output_dir } => {
            let executable = std::env::args().next().unwrap();
            let output_dir = output_dir.unwrap_or("target/ci-bench".into());
            let results = run_all(executable, output_dir.clone(), &benchmarks)?;

            // Output results in CSV (note: not using a library here to avoid extra dependencies)
            let mut csv_file = File::create(output_dir.join(ICOUNTS_FILENAME))
                .context("cannot create output csv file")?;
            for (name, instr_count) in results {
                writeln!(csv_file, "{name},{instr_count}")?;
            }
        }
        Command::RunSingle { index, side } => {
            // `u32::MAX` is used as a signal to do nothing and return. By "running" an empty
            // benchmark we can measure the startup overhead.
            if index == u32::MAX {
                return Ok(());
            }

            let bench = benchmarks
                .get(index as usize)
                .ok_or(anyhow::anyhow!("Benchmark not found: {index}"))?;

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

            let handshake_buf = &mut [0u8; 262144];
            let resumption_kind = black_box(bench.kind.resumption_kind());
            let params = black_box(bench.params);
            let io = StepperIO {
                reader: &mut stdin,
                writer: &mut stdout,
                handshake_buf,
            };
            let result = match side {
                Side::Server => run_bench(
                    ServerSideStepper {
                        io,
                        config: ServerSideStepper::make_config(&params, resumption_kind),
                    },
                    bench.kind,
                ),
                Side::Client => run_bench(
                    ClientSideStepper {
                        io,
                        resumption_kind,
                        config: ClientSideStepper::make_config(&params, resumption_kind),
                    },
                    bench.kind,
                ),
            };

            result
                .with_context(|| format!("{} crashed for {} side", bench.name(), side.as_str()))?;

            // Prevent stdin / stdout from being closed
            mem::forget(stdin);
            mem::forget(stdout);
        }
        Command::Compare {
            baseline_dir,
            candidate_dir,
        } => {
            let baseline = read_results(&baseline_dir.join(ICOUNTS_FILENAME))?;
            let candidate = read_results(&candidate_dir.join(ICOUNTS_FILENAME))?;
            let result = compare_results(&baseline_dir, &candidate_dir, &baseline, &candidate)?;
            print_report(&result);

            if !result.noteworthy.is_empty() {
                // Signal to the parent process that there are noteworthy instruction count
                // differences (exit code 1 is already used when main returns an error)
                eprintln!("Noteworthy instruction count differences found. Check the job summary for details.");
                std::process::exit(2);
            }
        }
    }

    Ok(())
}

/// Returns all benchmarks
fn all_benchmarks() -> anyhow::Result<Vec<Benchmark>> {
    let mut benchmarks = Vec::new();
    for &param in ALL_BENCHMARK_PARAMS {
        add_benchmark_group(&mut benchmarks, param);
    }

    validate_benchmarks(&benchmarks)?;
    Ok(benchmarks)
}

/// The benchmark params to use for each group of benchmarks
static ALL_BENCHMARK_PARAMS: &[BenchmarkParams] = &[
    BenchmarkParams::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        &rustls::version::TLS12,
        "1.2_rsa_aes",
    ),
    BenchmarkParams::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
        "1.3_rsa_aes",
    ),
    BenchmarkParams::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
        "1.3_ecdsa_aes",
    ),
    BenchmarkParams::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS13,
        "1.3_rsa_chacha",
    ),
    BenchmarkParams::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS13,
        "1.3_ecdsa_chacha",
    ),
];

/// Adds a group of benchmarks for the specified parameters
///
/// The benchmarks in the group are:
///
/// - Handshake without resumption
/// - Handshake with session id resumption
/// - Handshake with ticket resumption
/// - Transfer a 1MB data stream from the server to the client
fn add_benchmark_group(benchmarks: &mut Vec<Benchmark>, params: BenchmarkParams) {
    let params_label = params.label;

    // Create handshake benchmarks for all resumption kinds
    for &resumption_param in ResumptionKind::ALL {
        let handshake_bench = Benchmark::new(
            format!("handshake_{}_{params_label}", resumption_param.label()),
            BenchmarkKind::Handshake(resumption_param),
            params,
        );

        let handshake_bench = if resumption_param != ResumptionKind::No {
            // Since resumed handshakes include a first non-resumed handshake, we need to subtract
            // the non-resumed handshake's instructions
            handshake_bench
                .exclude_setup_instructions(format!("handshake_no_resume_{params_label}"))
        } else {
            handshake_bench
        };

        benchmarks.push(handshake_bench);
    }

    // Benchmark data transfer
    benchmarks.push(
        Benchmark::new(
            format!("transfer_no_resume_{params_label}"),
            BenchmarkKind::Transfer,
            params,
        )
        .exclude_setup_instructions(format!("handshake_no_resume_{params_label}")),
    );
}

/// Run all the provided benches under cachegrind to retrieve their instruction count
pub fn run_all(
    executable: String,
    output_dir: PathBuf,
    benches: &[Benchmark],
) -> anyhow::Result<Vec<(String, u64)>> {
    // Run the benchmarks in parallel
    let cachegrind = CachegrindRunner::new(executable, output_dir)?;
    let results: Vec<_> = benches
        .par_iter()
        .enumerate()
        .map(|(i, bench)| (bench, cachegrind.run_bench(i as u32, bench)))
        .collect();

    // Report possible errors
    let (errors, results): (Vec<_>, FxHashMap<_, _>) =
        results
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

    // Gather results keeping the original order of the benchmarks
    let mut measurements = Vec::new();
    for bench in benches {
        let instr_counts = get_reported_instr_count(bench, &results);
        measurements.push((bench.name_with_side(Side::Server), instr_counts.server));
        measurements.push((bench.name_with_side(Side::Client), instr_counts.client));
    }

    Ok(measurements)
}

/// Drives the different steps in a benchmark.
///
/// See [`run_bench`] for specific details on how it is used.
trait BenchStepper {
    type Endpoint;

    fn handshake(&mut self) -> anyhow::Result<Self::Endpoint>;
    fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()>;
    fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()>;
}

/// Stepper fields necessary for IO
struct StepperIO<'a> {
    reader: &'a mut dyn Read,
    writer: &'a mut dyn Write,
    handshake_buf: &'a mut [u8],
}

/// A benchmark stepper for the client-side of the connection
struct ClientSideStepper<'a> {
    io: StepperIO<'a>,
    resumption_kind: ResumptionKind,
    config: Arc<ClientConfig>,
}

impl ClientSideStepper<'_> {
    fn make_config(params: &BenchmarkParams, resume: ResumptionKind) -> Arc<ClientConfig> {
        assert_eq!(params.ciphersuite.version(), params.version);
        let mut root_store = RootCertStore::empty();
        let mut rootbuf =
            io::BufReader::new(fs::File::open(params.key_type.path_for("ca.cert")).unwrap());
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut rootbuf).map(|result| result.unwrap()),
        );

        let mut cfg = ClientConfig::builder()
            .with_cipher_suites(&[params.ciphersuite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if resume != ResumptionKind::No {
            cfg.resumption = Resumption::in_memory_sessions(128);
        } else {
            cfg.resumption = Resumption::disabled();
        }

        Arc::new(cfg)
    }
}

impl BenchStepper for ClientSideStepper<'_> {
    type Endpoint = ClientConnection;

    fn handshake(&mut self) -> anyhow::Result<Self::Endpoint> {
        let server_name = "localhost".try_into().unwrap();
        let mut client = ClientConnection::new(self.config.clone(), server_name).unwrap();
        client.set_buffer_limit(None);

        loop {
            send_handshake_message(&mut client, self.io.writer, self.io.handshake_buf)?;
            if !client.is_handshaking() && !client.wants_write() {
                break;
            }
            read_handshake_message(&mut client, self.io.reader, self.io.handshake_buf)?;
        }

        // Session ids and tickets are no longer part of the handshake in TLS 1.3, so we need to
        // explicitly receive them from the server
        if self.resumption_kind != ResumptionKind::No
            && client.protocol_version().unwrap() == ProtocolVersion::TLSv1_3
        {
            read_handshake_message(&mut client, self.io.reader, self.io.handshake_buf)?;
        }

        Ok(client)
    }

    fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()> {
        // The client syncs by receiving a single byte (we assert that it matches the `42` byte sent
        // by the server, just to be sure)
        let buf = &mut [0];
        self.io.reader.read_exact(buf)?;
        assert_eq!(buf[0], 42);
        Ok(())
    }

    fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()> {
        let total_plaintext_read = read_plaintext_to_end_bounded(endpoint, self.io.reader)?;
        assert_eq!(total_plaintext_read, TRANSFER_PLAINTEXT_SIZE);
        Ok(())
    }
}

/// A benchmark stepper for the server-side of the connection
struct ServerSideStepper<'a> {
    io: StepperIO<'a>,
    config: Arc<ServerConfig>,
}

impl ServerSideStepper<'_> {
    fn make_config(params: &BenchmarkParams, resume: ResumptionKind) -> Arc<ServerConfig> {
        assert_eq!(params.ciphersuite.version(), params.version);

        let mut cfg = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
            .with_single_cert(params.key_type.get_chain(), params.key_type.get_key())
            .expect("bad certs/private key?");

        if resume == ResumptionKind::SessionID {
            cfg.session_storage = ServerSessionMemoryCache::new(128);
        } else if resume == ResumptionKind::Tickets {
            cfg.ticketer = Ticketer::new().unwrap();
        } else {
            cfg.session_storage = Arc::new(NoServerSessionStorage {});
        }

        Arc::new(cfg)
    }
}

impl BenchStepper for ServerSideStepper<'_> {
    type Endpoint = ServerConnection;

    fn handshake(&mut self) -> anyhow::Result<Self::Endpoint> {
        let mut server = ServerConnection::new(self.config.clone()).unwrap();
        server.set_buffer_limit(None);

        while server.is_handshaking() {
            read_handshake_message(&mut server, self.io.reader, self.io.handshake_buf)?;
            send_handshake_message(&mut server, self.io.writer, self.io.handshake_buf)?;
        }

        Ok(server)
    }

    fn sync_before_resumed_handshake(&mut self) -> anyhow::Result<()> {
        // The server syncs by sending a single byte
        self.io.writer.write_all(&[42])?;
        self.io.writer.flush()?;
        Ok(())
    }

    fn transmit_data(&mut self, endpoint: &mut Self::Endpoint) -> anyhow::Result<()> {
        write_all_plaintext_bounded(endpoint, self.io.writer, TRANSFER_PLAINTEXT_SIZE)?;
        Ok(())
    }
}

/// Runs the benchmark using the provided stepper
fn run_bench<T: BenchStepper>(mut stepper: T, kind: BenchmarkKind) -> anyhow::Result<()> {
    let mut endpoint = stepper.handshake()?;

    match kind {
        BenchmarkKind::Handshake(ResumptionKind::No) => {
            // Nothing else to do here, since the handshake already happened
            black_box(endpoint);
        }
        BenchmarkKind::Handshake(_) => {
            // The handshake performed above was non-resumed, because the client didn't have a
            // session ID / ticket; from now on we can perform resumed handshakes. We do it multiple
            // times, for reasons explained in the comments to `RESUMED_HANDSHAKE_RUNS`.
            for _ in 0..RESUMED_HANDSHAKE_RUNS {
                // Wait for the endpoints to sync (i.e. the server must have discarded the previous
                // connection and be ready for a new handshake, otherwise the client will start a
                // handshake before the server is ready and the bytes will be fed to the old
                // connection!)
                stepper.sync_before_resumed_handshake()?;
                stepper.handshake()?;
            }
        }
        BenchmarkKind::Transfer => {
            stepper.transmit_data(&mut endpoint)?;
        }
    }

    Ok(())
}

/// The results of a comparison between two `run-all` executions
struct CompareResult {
    /// Results that probably indicate a real change in performance and should be highlighted.
    ///
    /// The string is a detailed diff between the instruction counts obtained from cachegrind.
    noteworthy: Vec<(Diff, String)>,
    /// Results within the noise threshold
    negligible: Vec<Diff>,
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

/// Reads the (benchmark, instruction count) pairs from previous CSV output
fn read_results(path: &Path) -> anyhow::Result<HashMap<String, u64>> {
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
                .ok_or(anyhow::anyhow!("CSV is wrongly formatted"))?
                .to_string(),
            parts
                .next()
                .ok_or(anyhow::anyhow!("CSV is wrongly formatted"))?
                .parse()
                .context("Unable to parse instruction count from CSV")?,
        );
    }

    Ok(measurements)
}

/// Returns an internal representation of the comparison between the baseline and the candidate
/// measurements
fn compare_results(
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
        diffs.push(Diff {
            scenario: scenario.clone(),
            baseline: baseline_instr_count,
            candidate: instr_count,
            diff,
            diff_ratio,
        });
    }

    diffs.sort_by(|diff1, diff2| {
        diff2
            .diff_ratio
            .abs()
            .total_cmp(&diff1.diff_ratio.abs())
    });

    let (noteworthy, negligible) = split_on_threshold(&diffs);

    let mut noteworthy_with_details = Vec::new();
    for diff in noteworthy {
        let detailed_diff = cachegrind::diff(baseline_dir, candidate_dir, &diff.scenario)?;
        noteworthy_with_details.push((diff, detailed_diff));
    }

    Ok(CompareResult {
        noteworthy: noteworthy_with_details,
        negligible,
        missing_in_baseline: missing,
    })
}

/// Prints a report of the comparison to stdout, using GitHub-flavored markdown
fn print_report(result: &CompareResult) {
    println!("# Benchmark results");

    if !result.missing_in_baseline.is_empty() {
        println!("### ⚠️ Warning: missing benchmarks");
        println!();
        println!("The following benchmark scenarios are present in the candidate but not in the baseline:");
        println!();
        for scenario in &result.missing_in_baseline {
            println!("* {scenario}");
        }
    }

    println!("## Noteworthy instruction count differences");
    if result.noteworthy.is_empty() {
        println!(
            "_There are no noteworthy instruction count differences (i.e. above {}%)_",
            CHANGE_THRESHOLD * 100.0
        );
    } else {
        table(
            result
                .noteworthy
                .iter()
                .map(|(diff, _)| diff),
            true,
        );
        println!("<details>");
        println!("<summary>Details per scenario</summary>\n");
        for (diff, detailed_diff) in &result.noteworthy {
            println!("#### {}", diff.scenario);
            println!("```");
            println!("{detailed_diff}");
            println!("```");
        }
        println!("</details>\n")
    }

    println!("## Other instruction count differences");
    if result.negligible.is_empty() {
        println!("_There are no other instruction count differences_");
    } else {
        println!("<details>");
        println!("<summary>Click to expand</summary>\n");
        table(result.negligible.iter(), false);
        println!("</details>\n")
    }
}

/// Splits the diffs into two `Vec`s, the first one containing the diffs that exceed the threshold,
/// the second one containing the rest.
///
/// Assumes that the diff slice is sorted by `diff_ratio` in descending order.
fn split_on_threshold(diffs: &[Diff]) -> (Vec<Diff>, Vec<Diff>) {
    match diffs
        .iter()
        .position(|diff| diff.diff_ratio.abs() < CHANGE_THRESHOLD)
    {
        None => (diffs.to_vec(), Vec::new()),
        Some(first_below_threshold) => (
            diffs[..first_below_threshold].to_vec(),
            diffs[first_below_threshold..].to_vec(),
        ),
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
