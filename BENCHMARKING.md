# Benchmarking

This repository includes benchmarks for multiple use cases. They are described below, along with
information on how to run them.

## Throughput and memory usage benchmarks

These benchmarks measure the throughput and memory footprint you get from rustls. They have been
used in the past to compare performance against OpenSSL:

- See [the most up-to-date reports](https://rustls.dev/perf/).
- See the [historical results from December 2023](https://github.com/aochagavia/rustls-bench-results).
- See the [historical results from July 2019](https://jbp.io/2019/07/01/rustls-vs-openssl-performance.html).

You can also use them to evaluate rustls' performance on different hardware (e.g. a bare-metal server
with support for AVX-512 instructions vs. a cloud VM with a consumer-grade CPU).

The measured aspects are:

1. Bulk data transfer throughput in MiB/s;
2. Handshake throughput (full, session id, tickets) in handshakes per second;
3. Memory usage per connection.

If you are interested in comparing against OpenSSL, check out the [twin OpenSSL
benchmarks](https://github.com/ctz/openssl-bench), which produce similar measurements.

#### Building

The benchmarks are implemented in `rustls-bench/src/main.rs`.
Use `cargo build --release -p rustls-bench --features aws-lc-rs` to obtain the corresponding
binary (you can toggle conditionally compiled code with the `--no-default-features` and `--features`
flags) or simply run below, which will build and run the benchmark.

#### Running

There is a makefile in [admin/bench-measure.mk](admin/bench-measure.mk) providing useful commands to
facilitate benchmarking:

- `make measure`: runs bulk transfer and handshake throughput benchmarks using a predefined list of
  cipher suites.
- `make memory`: measures memory usage for different amounts of connections.

You can inspect the makefile to get an idea of the command line arguments accepted by `bench`. With
the right arguments, you can run benchmarks for other cipher suites (through `cargo run --release`
or by directly launching the compiled binary).

#### Reducing noise

We usually extend the duration of the benchmarks in an attempt to neutralize the effect of cold CPU
and page caches, giving us more accurate results. This is done through the `BENCH_MULTIPLIER`
environment variable, which tells the benchmark runner to multiply the amount of work done. For
instance, `BENCH_MULTIPLIER=8` will ensure we do 8 times the work.

Additional ways to reduce noise are:

- Disabling ASLR (through `setarch -R`).
- Disabling CPU dynamic frequency scaling (usually on the BIOS/UEFI level).
- Disabling CPU hyper-threading (usually on the BIOS/UEFI level).
- Setting the Linux CPU governor to performance for all cores.
- Running the benchmarks multiple times (e.g. 30) and taking the median for each scenario (the
  [December 2023 results](https://github.com/aochagavia/rustls-bench-results) include Python code
  doing this).

## CI benchmarks

These benchmarks are meant to provide _automated_ and _accurate_ feedback on a PR's performance
impact compared to the main branch. By automating them we ensure they are regularly used, by keeping
them accurate we ensure they are actionable (i.e. too much noise would train reviewers to ignore the
information).

The benchmarks themselves are located under [ci-bench](ci-bench), together with a detailed readme
(including instructions on how to run them locally). The automated runner lives in its own
[repository](https://github.com/rustls/rustls-bench-app) and is deployed to a bare-metal machine to
ensure low-noise results.

## Nightly benchmarks

There are some `#[bench]` benchmarks spread throughout the codebase. We do not use them
systematically, but they help understand the performance of smaller pieces of code (one or two
functions), which would be difficult to see when the unit-of-benchmark is an entire handshake.

These benchmarks require a nightly compiler. If you are using `rustup`, you can run them with
`RUSTFLAGS=--cfg=bench cargo +nightly bench`
