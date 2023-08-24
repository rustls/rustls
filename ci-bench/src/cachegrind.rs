use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Sub;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;

use crate::benchmark::Benchmark;
use crate::Side;

/// A cachegrind-based benchmark runner
pub struct CachegrindRunner {
    /// The path to the ci-bench executable
    ///
    /// This is necessary because the cachegrind runner works by spawning child processes
    executable: String,
    /// The amount of instructions that are executed upon startup of the child process, before
    /// actually running one of the benchmarks
    ///
    /// This count is subtracted from benchmark results, to reduce noise
    overhead_instructions: u64,
}

impl CachegrindRunner {
    /// Returns a new cachegrind-based benchmark runner
    pub fn new(executable: String) -> anyhow::Result<Self> {
        Self::ensure_cachegrind_available()?;

        // We don't care about the side here, so let's use `Server` just to choose something
        let overhead_instructions = Self::run_bench_side(
            &executable,
            u32::MAX,
            Side::Server,
            "calibration",
            Stdio::piped(),
            Stdio::piped(),
        )?
        .wait_and_get_instr_count()
        .context("Unable to count overhead instructions")?;

        Ok(CachegrindRunner {
            executable,
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
        )
        .context("server side bench crashed")?;

        let client = Self::run_bench_side(
            &self.executable,
            benchmark_index,
            Side::Client,
            &bench.name_with_side(Side::Client),
            Stdio::from(server.process.stdout.take().unwrap()),
            Stdio::from(server.process.stdin.take().unwrap()),
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
    ) -> anyhow::Result<BenchSubprocess> {
        let output_file = PathBuf::from(format!("target/cachegrind/cachegrind.out.{}", name));
        std::fs::create_dir_all(output_file.parent().unwrap())
            .context("Failed to create cachegrind output directory")?;

        // Run under setarch to disable ASLR, to reduce noise
        let mut cmd = Command::new("setarch");
        let child = cmd
            .arg("-R")
            .arg("valgrind")
            .arg("--tool=cachegrind")
            // Disable the cache simulation, since we are only interested in instruction counts
            .arg("--cache-sim=no")
            // Discard cachegrind's logs, which would otherwise be printed to stderr (we want to
            // keep stderr free of noise, to see any errors from the child process)
            .arg("--log-file=/dev/null")
            // The file where the instruction counts will be stored
            .arg(format!("--cachegrind-out-file={}", output_file.display()))
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
            output_file,
        })
    }
}

/// A running subprocess for one of the sides of the benchmark (client or server)
struct BenchSubprocess {
    /// The benchmark's child process, running under cachegrind
    process: Child,
    /// Cachegrind's output file for this benchmark
    output_file: PathBuf,
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

        let instruction_count = parse_cachegrind_output(&self.output_file)?;
        std::fs::remove_file(&self.output_file).ok();

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
