# Fuzz Testing

Rustls supports fuzz testing using [cargo-fuzz]. Fuzz tests are automatically
run during continuous integration using [oss-fuzz]. You may also run fuzz tests
locally. See the [cargo-fuzz setup] instructions for requirements.

```bash
# List available fuzzing targets.
$ cargo fuzz list
client
deframer
fragment
message
persist
servert

# Run the message fuzz target for a fixed period of time (expressed in seconds).
$ cargo fuzz run message -- -max_total_time=120

# Clean up generated corpus files
git clean --interactive -- ./corpus
```

[cargo-fuzz]: https://rust-fuzz.github.io/book/cargo-fuzz.html
[oss-fuzz]: https://google.github.io/oss-fuzz/
[cargo-fuzz setup]: https://rust-fuzz.github.io/book/cargo-fuzz/setup.html
