use std::sync::Arc;

use fxhash::{FxHashMap, FxHashSet};
use itertools::Itertools;

use crate::cachegrind::InstructionCounts;
use crate::util::KeyType;
use crate::Side;

/// Validates a benchmark collection, returning an error if the provided benchmarks are invalid
///
/// Benchmarks can be invalid because of the following reasons:
///
/// - Re-using an already defined benchmark name.
/// - Referencing a non-existing benchmark in [`ReportingMode::AllInstructionsExceptSetup`].
pub fn validate_benchmarks(benchmarks: &[Benchmark]) -> anyhow::Result<()> {
    // Detect duplicate definitions
    let duplicate_names: Vec<_> = benchmarks
        .iter()
        .map(|b| b.name.as_str())
        .duplicates()
        .collect();
    if !duplicate_names.is_empty() {
        anyhow::bail!(
            "The following benchmarks are defined multiple times: {}",
            duplicate_names.join(", ")
        );
    }

    // Detect dangling benchmark references
    let all_names: FxHashSet<_> = benchmarks
        .iter()
        .map(|b| b.name.as_str())
        .collect();
    let referenced_names: FxHashSet<_> = benchmarks
        .iter()
        .flat_map(|b| match &b.reporting_mode {
            ReportingMode::AllInstructions => None,
            ReportingMode::AllInstructionsExceptSetup(name) => Some(name.as_str()),
        })
        .collect();

    let undefined_names: Vec<_> = referenced_names
        .difference(&all_names)
        .cloned()
        .collect();
    if !undefined_names.is_empty() {
        anyhow::bail!("The following benchmark names are referenced, but have no corresponding benchmarks: {}",
            undefined_names.join(", "));
    }

    Ok(())
}

/// Specifies how the results of a particular benchmark should be reported
pub enum ReportingMode {
    /// All instructions are reported
    AllInstructions,
    /// All instructions are reported, after subtracting the instructions of the setup code
    ///
    /// The instruction count of the setup code is obtained by running a benchmark containing only
    /// that code. The string parameter corresponds to the name of that benchmark.
    AllInstructionsExceptSetup(String),
}

/// Get the reported instruction counts for the provided benchmark
pub fn get_reported_instr_count(
    bench: &Benchmark,
    results: &FxHashMap<&str, InstructionCounts>,
) -> InstructionCounts {
    match bench.reporting_mode() {
        ReportingMode::AllInstructions => results[&bench.name()],
        ReportingMode::AllInstructionsExceptSetup(setup_name) => {
            let bench_results = results[&bench.name()];
            let setup_results = results[setup_name.as_str()];
            bench_results - setup_results
        }
    }
}

/// Specifies which functionality is being benchmarked
#[derive(Copy, Clone)]
pub enum BenchmarkKind {
    /// Perform the handshake and exit
    Handshake(ResumptionKind),
    /// Perform the handshake and transfer 1MB of data
    Transfer,
}

impl BenchmarkKind {
    /// Returns the [`ResumptionKind`] used in the handshake part of the benchmark
    pub fn resumption_kind(self) -> ResumptionKind {
        match self {
            BenchmarkKind::Handshake(kind) => kind,
            BenchmarkKind::Transfer => ResumptionKind::No,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
/// The kind of resumption used during the handshake
pub enum ResumptionKind {
    /// No resumption
    No,
    /// Session ID
    SessionId,
    /// Session tickets
    Tickets,
}

impl ResumptionKind {
    pub const ALL: &'static [ResumptionKind] = &[Self::No, Self::SessionId, Self::Tickets];

    /// Returns a user-facing label that identifies the resumption kind
    pub fn label(&self) -> &'static str {
        match *self {
            Self::No => "no_resume",
            Self::SessionId => "session_id",
            Self::Tickets => "tickets",
        }
    }
}

/// Parameters associated to a benchmark
#[derive(Clone, Debug)]
pub struct BenchmarkParams {
    /// Which `CryptoProvider` to test
    pub provider: rustls::crypto::CryptoProvider,
    /// How to make a suitable [`rustls::server::ProducesTickets`].
    pub ticketer: &'static fn() -> Arc<dyn rustls::server::ProducesTickets>,
    /// The type of key used to sign the TLS certificate
    pub key_type: KeyType,
    /// Cipher suite
    pub ciphersuite: rustls::SupportedCipherSuite,
    /// TLS version
    pub version: &'static rustls::SupportedProtocolVersion,
    /// A user-facing label that identifies these params
    pub label: String,
}

impl BenchmarkParams {
    /// Create a new set of benchmark params
    pub const fn new(
        provider: rustls::crypto::CryptoProvider,
        ticketer: &'static fn() -> Arc<dyn rustls::server::ProducesTickets>,
        key_type: KeyType,
        ciphersuite: rustls::SupportedCipherSuite,
        version: &'static rustls::SupportedProtocolVersion,
        label: String,
    ) -> Self {
        Self {
            provider,
            ticketer,
            key_type,
            ciphersuite,
            version,
            label,
        }
    }
}

/// A benchmark specification
pub struct Benchmark {
    /// The name of the benchmark, as shown in the benchmark results
    name: String,
    /// The benchmark kind
    pub kind: BenchmarkKind,
    /// The benchmark's parameters
    pub params: BenchmarkParams,
    /// The way instruction counts should be reported for this benchmark
    pub reporting_mode: ReportingMode,
}

impl Benchmark {
    /// Create a new benchmark
    pub fn new(name: String, kind: BenchmarkKind, params: BenchmarkParams) -> Self {
        Self {
            name,
            kind,
            params,
            reporting_mode: ReportingMode::AllInstructions,
        }
    }

    /// Configure this benchmark to subtract the instruction count of the referenced benchmark when
    /// reporting results
    pub fn exclude_setup_instructions(mut self, name: String) -> Self {
        self.reporting_mode = ReportingMode::AllInstructionsExceptSetup(name);
        self
    }

    /// Returns the benchmark's unique name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the benchmark's unique name with the side appended to it
    pub fn name_with_side(&self, side: Side) -> String {
        format!("{}_{}", self.name, side.as_str())
    }

    /// Returns the benchmark's reporting mode
    pub fn reporting_mode(&self) -> &ReportingMode {
        &self.reporting_mode
    }
}
