# CI Bench

This crate is meant for CI benchmarking. It measures CPU instructions using `cachegrind`, outputs
the results in CSV format and allows comparing results from multiple runs.

## Usage

You can get detailed usage information through `cargo run --release -- --help`. Below are the most
important bits.

### Running all benchmarks

_Note: this step requires having `valgrind` in your path._

Use `cargo run --release -- run-all > out.csv` to generate a CSV with the instruction counts for
the different scenarios we support. The result should look like the following:

```csv
handshake_no_resume_1.2_rsa_aes_server,11327015
handshake_no_resume_1.2_rsa_aes_client,4314952
handshake_session_id_1.2_rsa_aes_server,11342136
handshake_session_id_1.2_rsa_aes_client,4327564
handshake_tickets_1.2_rsa_aes_server,11347746
handshake_tickets_1.2_rsa_aes_client,4331424
transfer_no_resume_1.2_rsa_aes_server,8775780
transfer_no_resume_1.2_rsa_aes_client,8818847
handshake_no_resume_1.3_rsa_aes_server,11517007
handshake_no_resume_1.3_rsa_aes_client,4212770
...
... rest omitted for brevity
...
```

### Comparing results

Use `cargo run --release -- compare out1.csv out2.csv`. It will output a report using
GitHub-flavored markdown (used by the CI itself to give feedback about PRs). We currently
consider differences of 0.2% to be significant, but might tweak it in the future after we gain
experience with the benchmarking setup.

### Supported scenarios

We benchmark the following scenarios:

- Handshake without resumption (`handshake_no_resume`)
- Handshake with ticket resumption (`handshake_tickets`)
- Handshake with session id resumption (`handshake_session_id`)
- Encrypt, transfer and decrypt 1MB of data sent by the server
  (`transfer_no_resume`)

The scenarios are benchmarked with different TLS versions, certificate key types and cipher suites.
CPU counts are measured independently for the server side and for the client side. Hence, we end up
with names like `transfer_no_resume_1.3_rsa_aes_client`.

## Internals

We have made an effort to heavily document the source code of the benchmarks. In addition to that,
here are some high-level considerations that can help you hack on the crate.

### Architecture

An important goal of this benchmarking setup is that it should run with minimum noise on
standard GitHub Actions runners. We achieve that by measuring CPU instructions using `cachegrind`,
which runs fine on the cloud (contrary to hardware instruction counters). This is the same
approach used by the [iai](https://crates.io/crates/iai) benchmarking crate, but we needed more
flexibility and have therefore rolled our own setup.

Using `cachegrind` has some architectural consequences because it operates at the process level
(i.e. it can count CPU instructions for a whole process, but not for a single function). The
most important consequences are:

- Since we want to measure server and client instruction counts separately, the benchmark runner
  spawns two child processes for each benchmark (one for the client, one for the server) and pipes
  their stdio to each other for communication (i.e. stdio acts as the transport layer).
- There is a no-op "benchmark" that measures the overhead of starting up the child process, so
  we can subtract it from the instruction count of the real benchmarks and reduce noise.
- Since we want to measure individual portions of code (e.g. data transfer after the handshake),
  there is a mechanism to subtract the instructions that are part of a benchmark's setup.
  Specifically, a benchmark can be configured to have another benchmark's instruction count
  subtracted from it. We are currently using this to subtract the handshake instructions from the
  data transfer benchmark.

### Debugging

If you need to debug the crate, here are a few tricks that might help:

- For printf debugging, you should use `eprintln!`, because child processes use stdio as the
  transport for the TLS connection (i.e. if you print something to stdout, you won't even see it
  _and_ the other side of the connection will choke on it).
- When using a proper debugger, remember that each side of the connection runs as a child process.
  If necessary, you can tweak the code to ensure both sides of the connection run on the parent
  process (e.g. by starting each side on its own thread and having them communicate through TCP).
  This should require little effort, because the TLS transport layer is encapsulated and generic
  over `Read` and `Write`.

### Why measure CPU instructions

This technique has been successfully used in tracking the Rust compiler's performance, and is
known to work well when comparing two versions of the same code. It has incredibly low noise,
and therefore makes for a very good metric for automatic PR checking (i.e. the automatic check
will reliably identify significant performance changes).

It is not possible to deduce the exact change in runtime based on the instruction count
difference (e.g. a 5% increase in instructions does not necessarily result in a 5% increase in
runtime). However, if there is a significant change in instruction count, you can be fairly
confident there is a significant change in runtime too. This is very useful information to have
when reviewing a PR.

For more information, including the alternatives we considered, check out [this comment]
(https://github.com/rustls/rustls/issues/1385#issuecomment-1668023152) in the issue tracker.
