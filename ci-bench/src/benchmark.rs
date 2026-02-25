use core::borrow::Borrow;
use core::cmp;
use std::sync::Arc;

use rustc_hash::FxHashMap;
use rustls::crypto::{CryptoProvider, TicketProducer};
use rustls_test::KeyType;

use crate::Side;
use crate::valgrind::InstructionCounts;

/// Get the reported instruction counts for the provided benchmark
pub(crate) fn get_reported_instr_count(
    bench: &Benchmark,
    results: &FxHashMap<&str, InstructionCounts>,
) -> InstructionCounts {
    results[&bench.name()]
}

/// Specifies which functionality is being benchmarked
#[derive(Copy, Clone)]
pub(crate) enum BenchmarkKind {
    /// Perform the handshake and exit
    Handshake(ResumptionKind),
    /// Perform the handshake and transfer 1MB of data
    Transfer,
}

impl BenchmarkKind {
    /// Returns the [`ResumptionKind`] used in the handshake part of the benchmark
    pub(crate) fn resumption_kind(self) -> ResumptionKind {
        match self {
            Self::Handshake(kind) => kind,
            Self::Transfer => ResumptionKind::No,
        }
    }
}

/// The kind of resumption used during the handshake
#[derive(PartialEq, Clone, Copy)]
pub(crate) enum ResumptionKind {
    /// No resumption
    No,
    /// Session ID
    SessionId,
    /// Session tickets
    Tickets,
}

impl ResumptionKind {
    pub(crate) const ALL: &'static [Self] = &[Self::No, Self::SessionId, Self::Tickets];

    /// Returns a user-facing label that identifies the resumption kind
    pub(crate) fn label(&self) -> &'static str {
        match *self {
            Self::No => "no_resume",
            Self::SessionId => "session_id",
            Self::Tickets => "tickets",
        }
    }
}

/// Parameters associated to a benchmark
#[derive(Clone, Debug)]
pub(crate) struct BenchmarkParams {
    /// Which `CryptoProvider` to test.
    ///
    /// The choice of cipher suite is baked into this.
    pub provider: Arc<CryptoProvider>,
    /// How to make a suitable [`rustls::crypto::TicketProducer`].
    pub ticketer: &'static fn() -> Arc<dyn TicketProducer>,
    /// Where to get keys for server auth
    pub auth_key: AuthKeySource,
    /// A user-facing label that identifies these params
    pub label: String,
    /// Call this once this BenchmarkParams is sure to be used
    pub warm_up: Option<fn()>,
}

impl BenchmarkParams {
    /// Create a new set of benchmark params
    pub(crate) const fn new(
        provider: Arc<CryptoProvider>,
        ticketer: &'static fn() -> Arc<dyn TicketProducer>,
        auth_key: AuthKeySource,
        label: String,
        warm_up: Option<fn()>,
    ) -> Self {
        Self {
            provider,
            ticketer,
            auth_key,
            label,
            warm_up,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AuthKeySource {
    KeyType(KeyType),
    FuzzingProvider,
}

/// A benchmark specification
pub(crate) struct Benchmark {
    /// The name of the benchmark, as shown in the benchmark results
    name: String,
    /// The benchmark kind
    pub kind: BenchmarkKind,
    /// The benchmark's parameters
    pub params: BenchmarkParams,
}

impl Benchmark {
    /// Create a new benchmark
    pub(crate) fn new(name: String, kind: BenchmarkKind, params: BenchmarkParams) -> Self {
        Self { name, kind, params }
    }

    /// Returns the benchmark's unique name
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns the benchmark's unique name with the side appended to it
    pub(crate) fn name_with_side(&self, side: Side) -> String {
        format!("{}_{}", self.name, side.as_str())
    }
}

impl Borrow<str> for Benchmark {
    fn borrow(&self) -> &str {
        &self.name
    }
}

impl PartialEq for Benchmark {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Benchmark {}

impl PartialOrd for Benchmark {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Benchmark {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name.cmp(&other.name)
    }
}
