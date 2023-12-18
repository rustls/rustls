use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::ops::Sub;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;

use crate::benchmark::Benchmark;
use crate::Side;

/// The subdirectory in which the cachegrind output should be stored
const CACHEGRIND_OUTPUT_SUBDIR: &str = "cachegrind";

/// A cachegrind-based benchmark runner
pub struct CachegrindRunner {
    /// The path to the ci-bench executable
    ///
    /// This is necessary because the cachegrind runner works by spawning child processes
    executable: String,
    /// The directory where the cachegrind output will be stored
    output_dir: PathBuf,
    /// The amount of instructions that are executed upon startup of the child process, before
    /// actually running one of the benchmarks
    ///
    /// This count is subtracted from benchmark results, to reduce noise
    overhead_instructions: u64,
}

impl CachegrindRunner {
    /// Returns a new cachegrind-based benchmark runner
    pub fn new(executable: String, output_dir: PathBuf) -> anyhow::Result<Self> {
        Self::ensure_cachegrind_available()?;

        let cachegrind_output_dir = output_dir.join(CACHEGRIND_OUTPUT_SUBDIR);
        std::fs::create_dir_all(&cachegrind_output_dir)
            .context("Failed to create cachegrind output directory")?;

        // We don't care about the side here, so let's use `Server` just to choose something
        let overhead_instructions = Self::run_bench_side(
            &executable,
            u32::MAX,
            Side::Server,
            "calibration",
            Stdio::piped(),
            Stdio::piped(),
            &cachegrind_output_dir,
        )?
        .wait_and_get_instr_count()
        .context("Unable to count overhead instructions")?;

        Ok(CachegrindRunner {
            executable,
            output_dir: cachegrind_output_dir,
            overhead_instructions,
        })
    }

    /// Runs the benchmark at the specified index and returns the instruction counts for each side
    pub fn run_bench(
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

        let counts = InstructionCounts {
            server: server.wait_and_get_instr_count()?,
            client: client.wait_and_get_instr_count()?,
        };

        let overhead_counts = InstructionCounts {
            server: self.overhead_instructions,
            client: self.overhead_instructions,
        };

        Ok(counts - overhead_counts)
    }

    /// Returns an error if cachegrind is not available
    fn ensure_cachegrind_available() -> anyhow::Result<()> {
        let result = Command::new("valgrind")
            .arg("--tool=cachegrind")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match result {
            Err(e) => anyhow::bail!("Unexpected error while launching cachegrind. Error: {}", e),
            Ok(status) => {
                if status.success() {
                    Ok(())
                } else {
                    anyhow::bail!("Failed to launch cachegrind. Error: {}. Please ensure that valgrind is installed and on the $PATH.", status)
                }
            }
        }
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
        let cachegrind_output_file = output_dir.join(name);
        let cachegrind_log_file = output_dir.join(format!("{name}.log"));

        // Run under setarch to disable ASLR, to reduce noise
        let mut cmd = Command::new("setarch");
        let child = cmd
            .arg("-R")
            .arg("valgrind")
            .arg("--tool=cachegrind")
            // Disable the cache simulation, since we are only interested in instruction counts
            .arg("--cache-sim=no")
            // Save cachegrind's logs, which would otherwise be printed to stderr (we want to
            // keep stderr free of noise, to see any errors from the child process)
            .arg(format!("--log-file={}", cachegrind_log_file.display()))
            // The file where the instruction counts will be stored
            .arg(format!(
                "--cachegrind-out-file={}",
                cachegrind_output_file.display()
            ))
            .arg(executable)
            .arg("run-single")
            .arg(benchmark_index.to_string())
            .arg(side.as_str())
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to run benchmark in cachegrind")?;

        Ok(BenchSubprocess {
            process: child,
            cachegrind_output_file,
        })
    }
}

/// A running subprocess for one of the sides of the benchmark (client or server)
struct BenchSubprocess {
    /// The benchmark's child process, running under cachegrind
    process: Child,
    /// Cachegrind's output file for this benchmark
    cachegrind_output_file: PathBuf,
}

impl BenchSubprocess {
    /// Waits for the process to finish and returns the measured instruction count
    fn wait_and_get_instr_count(mut self) -> anyhow::Result<u64> {
        let status = self
            .process
            .wait()
            .context("Failed to run benchmark in cachegrind")?;
        if !status.success() {
            anyhow::bail!(
                "Failed to run benchmark in cachegrind. Exit code: {:?}",
                status.code()
            );
        }

        let instruction_count = parse_cachegrind_output(&self.cachegrind_output_file)?;
        Ok(instruction_count)
    }
}

/// Returns the instruction count, extracted from the cachegrind output file at the provided path
fn parse_cachegrind_output(file: &Path) -> anyhow::Result<u64> {
    let file_in = File::open(file).context("Unable to open cachegrind output file")?;

    for line in BufReader::new(file_in).lines() {
        let line = line.context("Error reading cachegrind output file")?;
        if let Some(line) = line.strip_prefix("summary: ") {
            let instr_count = line
                .trim()
                .parse()
                .context("Unable to parse instruction counts from cachegrind output file")?;

            return Ok(instr_count);
        }
    }

    anyhow::bail!("`summary` section not found in cachegrind output file")
}

/// The instruction counts, for each side, after running a benchmark
#[derive(Copy, Clone)]
pub struct InstructionCounts {
    pub client: u64,
    pub server: u64,
}

impl Sub for InstructionCounts {
    type Output = InstructionCounts;

    fn sub(self, rhs: Self) -> Self::Output {
        InstructionCounts {
            client: self.client - rhs.client,
            server: self.server - rhs.server,
        }
    }
}

/// Returns the detailed instruction diff between the baseline and the candidate
pub fn diff(baseline: &Path, candidate: &Path, scenario: &str) -> anyhow::Result<String> {
    // The latest version of valgrind has deprecated cg_diff, which has been superseded by
    // cg_annotate. Many systems are running older versions, though, so we are sticking with cg_diff
    // for the time being.

    let tmp_path = Path::new("ci-bench-tmp");
    let tmp = File::create(tmp_path).context("cannot create temp file for cg_diff")?;

    // cg_diff generates a diff between two cachegrind output files in a custom format that is not
    // user-friendly
    let cg_diff = Command::new("cg_diff")
        // remove per-compilation uniqueness in symbols, eg
        // _ZN9hashbrown3raw21RawTable$LT$T$C$A$GT$14reserve_rehash17hc60392f3f3eac4b2E.llvm.9716880419886440089 ->
        // _ZN9hashbrown3raw21RawTable$LT$T$C$A$GT$14reserve_rehashE
        .arg("--mod-funcname=s/17h[0-9a-f]+E\\.llvm\\.\\d+/E/")
        .arg(
            baseline
                .join(CACHEGRIND_OUTPUT_SUBDIR)
                .join(scenario),
        )
        .arg(
            candidate
                .join(CACHEGRIND_OUTPUT_SUBDIR)
                .join(scenario),
        )
        .stdout(Stdio::from(tmp))
        .spawn()
        .context("cannot spawn cg_diff subprocess")?
        .wait()
        .context("error waiting for cg_diff to finish")?;

    if !cg_diff.success() {
        anyhow::bail!(
            "cg_diff finished with an error (code = {:?})",
            cg_diff.code()
        )
    }

    // cg_annotate transforms the output of cg_diff into something a user can understand
    let cg_annotate = Command::new("cg_annotate")
        .arg(tmp_path)
        .arg("--auto=no")
        .output()
        .context("error waiting for cg_annotate to finish")?;

    if !cg_annotate.status.success() {
        anyhow::bail!(
            "cg_annotate finished with an error (code = {:?})",
            cg_annotate.status.code()
        )
    }

    let diff =
        String::from_utf8(cg_annotate.stdout).context("cg_annotate produced invalid UTF8")?;

    fs::remove_file(tmp_path).ok();

    Ok(diff)
}
