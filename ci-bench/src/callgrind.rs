use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Sub;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;

use crate::benchmark::Benchmark;
use crate::Side;

/// The subdirectory in which the callgrind output should be stored
const CALLGRIND_OUTPUT_SUBDIR: &str = "callgrind";

/// A callgrind-based benchmark runner
pub struct CallgrindRunner {
    /// The path to the ci-bench executable
    ///
    /// This is necessary because the callgrind runner works by spawning child processes
    executable: String,
    /// The directory where the callgrind output will be stored
    output_dir: PathBuf,
}

impl CallgrindRunner {
    /// Returns a new callgrind-based benchmark runner
    pub fn new(executable: String, output_dir: PathBuf) -> anyhow::Result<Self> {
        Self::ensure_callgrind_available()?;

        let callgrind_output_dir = output_dir.join(CALLGRIND_OUTPUT_SUBDIR);
        std::fs::create_dir_all(&callgrind_output_dir)
            .context("Failed to create callgrind output directory")?;

        Ok(CallgrindRunner {
            executable,
            output_dir: callgrind_output_dir,
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

        Ok(InstructionCounts {
            server: server.wait_and_get_instr_count()?,
            client: client.wait_and_get_instr_count()?,
        })
    }

    /// Returns an error if callgrind is not available
    fn ensure_callgrind_available() -> anyhow::Result<()> {
        let result = Command::new("valgrind")
            .arg("--tool=callgrind")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match result {
            Err(e) => anyhow::bail!("Unexpected error while launching callgrind. Error: {}", e),
            Ok(status) => {
                if status.success() {
                    Ok(())
                } else {
                    anyhow::bail!("Failed to launch callgrind. Error: {}. Please ensure that valgrind is installed and on the $PATH.", status)
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
        let callgrind_output_file = output_dir.join(name);
        let callgrind_log_file = output_dir.join(format!("{name}.log"));

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
            .arg(format!("--log-file={}", callgrind_log_file.display()))
            // The file where the instruction counts will be stored
            .arg(format!(
                "--callgrind-out-file={}",
                callgrind_output_file.display()
            ))
            .arg(executable)
            .arg("run-single")
            .arg(benchmark_index.to_string())
            .arg(side.as_str())
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to run benchmark in callgrind")?;

        Ok(BenchSubprocess {
            process: child,
            callgrind_output_file,
        })
    }
}

/// A running subprocess for one of the sides of the benchmark (client or server)
struct BenchSubprocess {
    /// The benchmark's child process, running under callgrind
    process: Child,
    /// Callgrind's output file for this benchmark
    callgrind_output_file: PathBuf,
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

        let instruction_count = parse_callgrind_output(&self.callgrind_output_file)?;
        Ok(instruction_count)
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
        CountInstructions
    }
}

impl Drop for CountInstructions {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        crabgrind::callgrind::toggle_collect();
    }
}
