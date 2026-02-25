use core::ops::Sub;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;

use crate::Side;
use crate::benchmark::Benchmark;

/// A callgrind-based benchmark runner
pub(crate) struct CallgrindRunner {
    /// The path to the ci-bench executable
    ///
    /// This is necessary because the callgrind runner works by spawning child processes
    executable: String,
    /// The directory where the callgrind output will be stored
    output_dir: PathBuf,
}

impl CallgrindRunner {
    /// Returns a new callgrind-based benchmark runner
    pub(crate) fn new(executable: String, output_dir: PathBuf) -> anyhow::Result<Self> {
        ensure_valgrind_tool_available("--tool=callgrind")?;

        let callgrind_output_dir = output_dir.join(CALLGRIND_OUTPUT_SUBDIR);
        std::fs::create_dir_all(&callgrind_output_dir)
            .context("Failed to create callgrind output directory")?;

        Ok(Self {
            executable,
            output_dir: callgrind_output_dir,
        })
    }

    /// Runs the benchmark at the specified index and returns the instruction counts for each side
    pub(crate) fn run_bench(
        &self,
        benchmark_index: u32,
        bench: &Benchmark,
    ) -> anyhow::Result<InstructionCounts> {
        // The server and client are started as child processes, and communicate with each other
        // through stdio.

        let mut server = Self::run_bench_side(
            &self.executable,
            benchmark_index,
            Side::Server,
            &bench.name_with_side(Side::Server),
            Stdio::piped(),
            Stdio::piped(),
            &self.output_dir,
        )
        .context("server side bench crashed")?;

        let client = Self::run_bench_side(
            &self.executable,
            benchmark_index,
            Side::Client,
            &bench.name_with_side(Side::Client),
            Stdio::from(server.process.stdout.take().unwrap()),
            Stdio::from(server.process.stdin.take().unwrap()),
            &self.output_dir,
        )
        .context("client side bench crashed")?;

        Ok(InstructionCounts {
            server: server.wait_and_get_instr_count()?,
            client: client.wait_and_get_instr_count()?,
        })
    }

    /// See docs for [`Self::run_bench`]
    fn run_bench_side(
        executable: &str,
        benchmark_index: u32,
        side: Side,
        name: &str,
        stdin: Stdio,
        stdout: Stdio,
        output_dir: &Path,
    ) -> anyhow::Result<BenchSubprocess> {
        let output_file = output_dir.join(name);
        let log_file = output_dir.join(format!("{name}.log"));

        // Run under setarch to disable ASLR, to reduce noise
        let mut cmd = Command::new("setarch");
        let child = cmd
            .arg("-R")
            .arg("valgrind")
            .arg("--tool=callgrind")
            // Do not count instructions from the start, instead this is controlled by `CountInstructions`
            .arg("--collect-atstart=no")
            // Disable the cache simulation, since we are only interested in instruction counts
            .arg("--cache-sim=no")
            // Save callgrind's logs, which would otherwise be printed to stderr (we want to
            // keep stderr free of noise, to see any errors from the child process)
            .arg(format!("--log-file={}", log_file.display()))
            // The file where the instruction counts will be stored
            .arg(format!("--callgrind-out-file={}", output_file.display()))
            .arg(executable)
            .arg("run-pipe")
            .arg(benchmark_index.to_string())
            .arg(side.as_str())
            .arg("instruction")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to run benchmark in callgrind")?;

        Ok(BenchSubprocess {
            process: child,
            output: ValgrindOutput::Callgrind { output_file },
        })
    }
}

/// A DHAT-based benchmark runner that measures runtime memory use.
pub(crate) struct DhatRunner {
    /// The path to the ci-bench executable
    ///
    /// This is necessary because the runner works by spawning child processes
    executable: String,
    /// The directory where the output will be stored
    output_dir: PathBuf,
}

impl DhatRunner {
    /// Returns a new callgrind-based benchmark runner
    pub(crate) fn new(executable: String, output_dir: PathBuf) -> anyhow::Result<Self> {
        ensure_valgrind_tool_available("--tool=dhat")?;

        let output_dir = output_dir.join("dhat");
        std::fs::create_dir_all(&output_dir).context("Failed to create DHAT output directory")?;

        Ok(Self {
            executable,
            output_dir,
        })
    }

    /// Runs the benchmark at the specified index and returns the memory usage for each side
    pub(crate) fn run_bench(
        &self,
        benchmark_index: u32,
        bench: &Benchmark,
    ) -> anyhow::Result<MemoryProfile> {
        // The server and client are started as child processes, and communicate with each other
        // through stdio.

        let mut server = Self::run_bench_side(
            &self.executable,
            benchmark_index,
            Side::Server,
            &bench.name_with_side(Side::Server),
            Stdio::piped(),
            Stdio::piped(),
            &self.output_dir,
        )
        .context("server side bench crashed")?;

        let client = Self::run_bench_side(
            &self.executable,
            benchmark_index,
            Side::Client,
            &bench.name_with_side(Side::Client),
            Stdio::from(server.process.stdout.take().unwrap()),
            Stdio::from(server.process.stdin.take().unwrap()),
            &self.output_dir,
        )
        .context("client side bench crashed")?;

        Ok(MemoryProfile {
            server: server.wait_and_get_memory_details()?,
            client: client.wait_and_get_memory_details()?,
        })
    }

    /// See docs for [`Self::run_bench`]
    fn run_bench_side(
        executable: &str,
        benchmark_index: u32,
        side: Side,
        name: &str,
        stdin: Stdio,
        stdout: Stdio,
        output_dir: &Path,
    ) -> anyhow::Result<BenchSubprocess> {
        let output_file = output_dir.join(name);
        let log_file = output_dir.join(format!("{name}.log"));

        // Run under setarch to disable ASLR, to reduce noise
        let mut cmd = Command::new("setarch");
        let child = cmd
            .arg("-R")
            .arg("valgrind")
            .arg("--tool=dhat")
            // We extract output from DHAT's logs, which contain a summary.
            .arg(format!("--log-file={}", log_file.display()))
            // Also save the detailed JSON
            .arg(format!("--dhat-out-file={}", output_file.display()))
            .arg(executable)
            .arg("run-pipe")
            .arg(benchmark_index.to_string())
            .arg(side.as_str())
            .arg("memory")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to run benchmark in DHAT")?;

        Ok(BenchSubprocess {
            process: child,
            output: ValgrindOutput::Dhat { log_file },
        })
    }
}

/// The subdirectory in which the callgrind output should be stored
const CALLGRIND_OUTPUT_SUBDIR: &str = "callgrind";

/// Returns an error if valgrind is not available
fn ensure_valgrind_tool_available(tool: &str) -> anyhow::Result<()> {
    let result = Command::new("valgrind")
        .arg(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match result {
        Err(e) => anyhow::bail!(
            "Unexpected error while launching valgrind {tool}. Error: {}",
            e
        ),
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!(
                    "Failed to launch valgrind {tool}. Error: {}. Please ensure that valgrind is installed and on the $PATH.",
                    status
                )
            }
        }
    }
}

/// A running subprocess for one of the sides of the benchmark (client or server)
struct BenchSubprocess {
    /// The benchmark's child process, running under valgrind
    process: Child,
    /// Valgrind's output file for this benchmark
    output: ValgrindOutput,
}

enum ValgrindOutput {
    Callgrind { output_file: PathBuf },
    Dhat { log_file: PathBuf },
}

impl BenchSubprocess {
    /// Waits for the process to finish and returns the measured instruction count
    fn wait_and_get_instr_count(mut self) -> anyhow::Result<u64> {
        let status = self
            .process
            .wait()
            .context("Failed to run benchmark in callgrind")?;
        if !status.success() {
            anyhow::bail!(
                "Failed to run benchmark in callgrind. Exit code: {:?}",
                status.code()
            );
        }

        let ValgrindOutput::Callgrind { output_file } = self.output else {
            panic!("wait_and_get_instr_count() is for Callgrind users");
        };

        parse_callgrind_output(&output_file)
    }

    /// Waits for the process to finish and returns the measured peak heap usage
    fn wait_and_get_memory_details(mut self) -> anyhow::Result<MemoryDetails> {
        let status = self
            .process
            .wait()
            .context("Failed to run benchmark in DHAT")?;
        if !status.success() {
            anyhow::bail!(
                "Failed to run benchmark in DHAT. Exit code: {:?}",
                status.code()
            );
        }

        let ValgrindOutput::Dhat { log_file } = self.output else {
            panic!("wait_and_get_memory_details() is for DHAT users");
        };

        MemoryDetails::from_file(&log_file)
    }
}

/// Returns the instruction count, extracted from the callgrind output file at the provided path
fn parse_callgrind_output(file: &Path) -> anyhow::Result<u64> {
    let file_in = File::open(file).context("Unable to open callgrind output file")?;

    for line in BufReader::new(file_in).lines() {
        let line = line.context("Error reading callgrind output file")?;
        if let Some(line) = line.strip_prefix("summary: ") {
            let instr_count = line
                .trim()
                .parse()
                .context("Unable to parse instruction counts from callgrind output file")?;

            return Ok(instr_count);
        }
    }

    anyhow::bail!("`summary` section not found in callgrind output file")
}

/// The instruction counts, for each side, after running a benchmark
#[derive(Copy, Clone)]
pub(crate) struct InstructionCounts {
    pub client: u64,
    pub server: u64,
}

impl Sub for InstructionCounts {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            client: self.client - rhs.client,
            server: self.server - rhs.server,
        }
    }
}

/// Peak heap usage in bytes, for each side
#[derive(Copy, Clone)]
pub(crate) struct MemoryProfile {
    pub client: MemoryDetails,
    pub server: MemoryDetails,
}

#[derive(Copy, Clone, Default)]
pub(crate) struct MemoryDetails {
    pub heap_total_bytes: u64,
    pub heap_total_blocks: u64,
    pub heap_peak_bytes: u64,
    pub heap_peak_blocks: u64,
}

impl MemoryDetails {
    /// Returns the heap usage, extracted from the DHAT log file at the provided path
    fn from_file(file: &Path) -> anyhow::Result<Self> {
        let file_in = File::open(file).context("Unable to open DHAT log file")?;
        let mut out = Self::default();

        /*
         * Sample:
         *
         * ==1018358== Total:     690,380 bytes in 4,158 blocks
         * ==1018358== At t-gmax: 70,539 bytes in 220 blocks
         * ==1018358== At t-end:  8,648 bytes in 2 blocks
         * ==1018358== Reads:     861,492 bytes
         * ==1018358== Writes:    782,958 bytes
         */

        for line in BufReader::new(file_in).lines() {
            let line = line.context("Error reading DHAT log file")?;

            match line
                .split_whitespace()
                .collect::<Vec<&str>>()
                .as_slice()
            {
                [_, "Total:", bytes, "bytes", "in", blocks, "blocks"] => {
                    out.heap_total_bytes = parse_u64(bytes);
                    out.heap_total_blocks = parse_u64(blocks);
                }
                [_, "At", "t-gmax:", bytes, "bytes", "in", blocks, "blocks"] => {
                    out.heap_peak_bytes = parse_u64(bytes);
                    out.heap_peak_blocks = parse_u64(blocks);
                }
                _ => {}
            }
        }

        fn parse_u64(s: &str) -> u64 {
            s.replace(",", "").parse().unwrap()
        }

        Ok(out)
    }
}

/// Returns the detailed instruction diff between the baseline and the candidate
pub(crate) fn callgrind_diff(
    baseline: &Path,
    candidate: &Path,
    scenario: &str,
) -> anyhow::Result<String> {
    // callgrind_annotate formats the callgrind output file, suitable for comparison with
    // callgrind_differ
    let callgrind_annotate_base = Command::new("callgrind_annotate")
        .arg(
            baseline
                .join(CALLGRIND_OUTPUT_SUBDIR)
                .join(scenario),
        )
        // do not annotate source, to keep output compact
        .arg("--auto=no")
        .output()
        .context("error waiting for callgrind_annotate to finish")?;

    let callgrind_annotate_candidate = Command::new("callgrind_annotate")
        .arg(
            candidate
                .join(CALLGRIND_OUTPUT_SUBDIR)
                .join(scenario),
        )
        // do not annotate source, to keep output compact
        .arg("--auto=no")
        .output()
        .context("error waiting for callgrind_annotate to finish")?;

    if !callgrind_annotate_base.status.success() {
        anyhow::bail!(
            "callgrind_annotate for base finished with an error (code = {:?})",
            callgrind_annotate_base.status.code()
        )
    }

    if !callgrind_annotate_candidate
        .status
        .success()
    {
        anyhow::bail!(
            "callgrind_annotate for candidate finished with an error (code = {:?})",
            callgrind_annotate_candidate
                .status
                .code()
        )
    }

    let string_base = String::from_utf8(callgrind_annotate_base.stdout)
        .context("callgrind_annotate produced invalid UTF8")?;
    let string_candidate = String::from_utf8(callgrind_annotate_candidate.stdout)
        .context("callgrind_annotate produced invalid UTF8")?;

    // TODO: reinstate actual diffing, using `callgrind_differ` crate
    Ok(format!(
        "Base output:\n{string_base}\n\
         =====\n\n\
         Candidate output:\n{string_candidate}\n"
    ))
}

/// A RAII-like object for enabling callgrind instruction counting.
///
/// Warning: must not be nested.
///
/// Instructions outside the scope of these objects are not counted.
pub(crate) struct CountInstructions;

impl CountInstructions {
    pub(crate) fn start() -> Self {
        #[cfg(target_os = "linux")]
        crabgrind::callgrind::toggle_collect();
        Self
    }
}

impl Drop for CountInstructions {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        crabgrind::callgrind::toggle_collect();
    }
}
