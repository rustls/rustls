# CI Bench

This crate is meant for CI benchmarking. It has two modes of operation:

1. Measure CPU instructions using `callgrind`.
2. Measure wall-time (runs each benchmark multiple times, leaving it to the caller to do statistical
   analysis).

## Usage

You can get detailed usage information through `cargo run --release -- --help`. Below are the most
important bits.

### Running all benchmarks in instruction count mode

_Note: this step requires having `valgrind` in your path._

Use `cargo run --release -- run-all --output-dir foo` to generate the results inside the `foo`
directory. Within that directory, you will find an `icounts.csv` file with the instruction counts
for the different scenarios we support. It should look like the following:

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

In the `callgrind` subdirectory you will find output files emitted by the `callgrind` tool, which
are useful to report detailed instruction count differences when comparing two benchmark runs. This
subdirectory also contains log information from callgrind itself (in `.log` files), which can be
used to diagnose unexpected callgrind crashes.

### Running all benchmarks in wall-time mode

Use `cargo run --release -- walltime --iterations-per-scenario 3` to print the CSV results to stdout
(we use 3 iterations here for demonstration purposes, but recommend 100 iterations to deal with
noise). The output should look like the following (one column per iteration):

```csv
handshake_no_resume_ring_1.2_rsa_aes,6035261,1714158,977368
handshake_session_id_ring_1.2_rsa_aes,1537632,2445849,1766888
handshake_tickets_ring_1.2_rsa_aes,1553743,2418286,1636431
transfer_no_resume_ring_1.2_rsa_aes,10192862,10374258,8988854
handshake_no_resume_ring_1.3_rsa_aes,1010150,1400602,936029
...
... rest omitted for brevity
...
```

### Comparing results from an instruction count benchmark run

Use `cargo run --release -- compare foo bar`. It will output a report using GitHub-flavored markdown
for local use. Note that not all reported differences are significant. When you need to know if a
result is significant you should rely on the CI benchmark report, which automatically categorizes
results into significant / negligible based on historic data.

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

### Environment configuration

An important goal of this benchmarking setup is that it should run with minimal noise. Measuring CPU
instructions using `callgrind` yields excellent results, regardless of your environment. The
wall-time benchmarks, however, require a more elaborate benchmarking environment: running them on a
laptop is too noisy, but running them on a carefully configured bare-metal server yields accurate
measurements (up to 1% resolution, according to our tests).

### Instruction count mode

Instruction counting is done with `callgrind`, and is precise in the sense that only operations
we want to measure are included.  We tell `callgrind` to start with collection disabled,
with `--collect-atstart=no`.  Then we use
[client requests](https://valgrind.org/docs/manual/cl-manual.html#cl-manual.clientrequests) via
the [crabgrind crate](https://docs.rs/crabgrind/latest/crabgrind/) to enable and disable collection
(see `callgrind::CountInstructions`).

Since we want to measure server and client instruction counts separately, the benchmark runner
spawns two child processes for each benchmark (one for the client, one for the server) and pipes
their stdio to each other for communication (i.e. stdio acts as the transport layer).

If you need to debug benchmarks in instruction count mode, here are a few tricks that might help:

- For printf debugging, you should use `eprintln!`, because child processes use stdio as the
  transport for the TLS connection (i.e. if you print something to stdout, you won't even see it
  _and_ the other side of the connection will choke on it).
- When using a proper debugger, remember that each side of the connection runs as a child process.

### Wall-time mode

To increase determinism, it is important that wall-time mode benchmarks run in a single process and
thread. All IO is done in-memory and there is no complex setup like in the case of the instruction
counting mode. Because of this, the easiest way to debug the crate is by running the benchmarks in
wall-time mode.

### Code reuse between benchmarking modes

Originally, we only supported the instruction count mode, implemented using blocking IO. Even though
the code was generic over the `Reader` and `Writer`, it could not be reused for the wall-time mode
because it was blocking (e.g. if the client side of the connection is waiting for a read, the thread
is blocked and the server never gets a chance to write).

The solution was to:

1. Rewrite the IO code to use async / await.
2. Keep using blocking operations under the hood in instruction-count mode, disguised as `Future`s
   that complete after a single `poll`. This way we avoid using an async runtime, which could
   introduce non-determinism.
3. Use non-blocking operations under the hood in wall-time mode, which simulate IO through shared
   in-memory buffers. The server and client `Future`s are polled in turns, so again we we avoid
   pulling in an async runtime and keep things as deterministic as possible.

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

### Why measure wall-time

While instruction counts are a useful proxy to detect changes in runtime performance, they do not
account for important factors such as cache misses and branch mispredictions. As an example,
consider two equivalent functions that calculate an aggregate value based on a `Vec<u64>`: if they
use roughly the same code, yet a different memory access pattern, that could result in a similar
instruction count, yet significantly different runtime.

The bigger the change in code, the higher the chance that memory layout and access patterns are
significantly affected. For that reason, having wall-time measurements is important as a complement
to instruction counts.
